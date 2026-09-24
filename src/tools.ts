import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import {
  MAX_DISASM_COUNT,
  MAX_DUMP_LENGTH,
  R2Error,
  r2Version,
  radare2Capabilities,
  radare2Engine,
} from "./engines/radare2.js";
import { closeRegisteredDebugEngines } from "./engines/registry.js";
import { ENGINE_IDS } from "./engines/types.js";
import { registerDebugTools } from "./debug_tools.js";
import { registerDynamicTools } from "./dynamic_tools.js";
import { registerGuideTools } from "./guide_tools.js";
import { clearCheckpoints } from "./snapshots.js";
import { SessionNotFoundError, registry, type DebugSession } from "./registry.js";

const SERVER_NAME = "conduit";
const PROTOCOL = "2026-07-28";

type ToolContent = { type: "text"; text: string };

function jsonResult(value: unknown, isError = false): { content: ToolContent[]; isError?: boolean } {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    ...(isError ? { isError: true } : {}),
  };
}

const sessionIdSchema = z.uuid().describe("Application session id. Not an MCP protocol session.");

/** Hex string ("0x..."), decimal string, flag name, or a plain number. */
const addressSchema = z
  .union([z.string(), z.number()])
  .describe('Target address as hex ("0x400200"), decimal, or flag name ("entry0").');

type StaticGate = { session: DebugSession; error?: undefined } | { session?: undefined; error: ReturnType<typeof jsonResult> };

/**
 * Static-tool precondition: the session must exist and belong to radare2.
 * Anything else is answered with a clear capability error, never a stub.
 */
function requireStaticSession(session_id: string, tool: string): StaticGate {
  const session = registry.get(session_id);
  if (session === undefined) {
    return { error: jsonResult({ error: "session_not_found", tool, session_id }, true) };
  }
  if (session.engine !== "radare2") {
    return {
      error: jsonResult(
        {
          error: "capability_unsupported",
          tool,
          session_id,
          engine: session.engine,
          required: { engine: "radare2", kind: "static" },
          detail: `tool '${tool}' needs a radare2 (static) session; session '${session_id}' belongs to '${session.engine}'`,
        },
        true,
      ),
    };
  }
  return { session };
}

function r2Failure(error: unknown, tool: string, session_id: string): ReturnType<typeof jsonResult> {
  if (error instanceof R2Error) {
    return jsonResult(
      { error: error.code, tool, session_id, detail: error.message, ...(error.data ?? {}) },
      true,
    );
  }
  // Unexpected failures (bugs, runtime faults) keep the tool contract: they
  // are answered as engine_error payloads, never MCP protocol errors.
  return jsonResult(
    {
      error: "engine_error",
      tool,
      session_id,
      detail: error instanceof Error ? error.message : String(error),
    },
    true,
  );
}

function capabilityFailure(
  tool: string,
  session_id: string,
  requested: unknown,
  supported: unknown,
  detail: string,
): ReturnType<typeof jsonResult> {
  return jsonResult({ error: "capability_unsupported", tool, session_id, requested, supported, detail }, true);
}

/**
 * Tool registrations. Session and event tools talk only to the in-process registry.
 * Static tools drive the radare2 engine; debug tools dispatch through the engine registry.
 */
export function registerTools(server: McpServer): void {
  server.registerTool(
    "health",
    {
      description: "Report bridge liveness. Does not touch a debugger engine.",
      inputSchema: z.object({}),
    },
    async () =>
      jsonResult({
        status: "ok",
        name: SERVER_NAME,
        protocol: PROTOCOL,
        sessions: registry.size,
      }),
  );

  server.registerTool(
    "session_open",
    {
      description:
        "Open an application session for an engine. Returns session_id for later tool arguments.",
      inputSchema: z.object({
        engine: z.enum(ENGINE_IDS),
      }),
    },
    async ({ engine }) => {
      const session = registry.open(engine);
      return jsonResult({
        session_id: session.id,
        engine: session.engine,
        createdAt: session.createdAt,
      });
    },
  );

  server.registerTool(
    "session_close",
    {
      description: "Drop an application session and its event buffer.",
      inputSchema: z.object({ session_id: sessionIdSchema }),
    },
    async ({ session_id }) => {
      const removed = registry.close(session_id);
      if (!removed) {
        return jsonResult({ error: "session_not_found", session_id }, true);
      }
      // Best-effort teardown of whatever the session held; the session is
      // gone either way. The static engine and every registered debug
      // engine are closed unconditionally so a session_close without a
      // prior close_target/debug_close cannot leak a child process.
      await radare2Engine.close(session_id).catch(() => undefined);
      await closeRegisteredDebugEngines(session_id).catch(() => undefined);
      clearCheckpoints(session_id);
      return jsonResult({ closed: true, session_id });
    },
  );

  server.registerTool(
    "session_list",
    {
      description: "List application sessions held in this process.",
      inputSchema: z.object({}),
    },
    async () =>
      jsonResult({
        sessions: registry.list().map((session) => ({
          session_id: session.id,
          engine: session.engine,
          createdAt: session.createdAt,
        })),
      }),
  );

  server.registerTool(
    "events_pull",
    {
      description:
        "Pull events stored for one application session since a sequence number. This does not subscribe to push notifications.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        after: z.number().int().nonnegative().optional().describe("Return events with seq greater than this."),
        limit: z.number().int().min(1).max(256).optional(),
      }),
    },
    async ({ session_id, after, limit }) => {
      try {
        const session = registry.require(session_id);
        return jsonResult({
          session_id,
          retainedFrom: session.events.retainedFrom(),
          events: session.events.pull(after ?? 0, limit ?? 100),
        });
      } catch (error) {
        if (error instanceof SessionNotFoundError) {
          return jsonResult({ error: "session_not_found", session_id }, true);
        }
        return jsonResult(
          {
            error: "engine_error",
            tool: "events_pull",
            session_id,
            detail: error instanceof Error ? error.message : String(error),
          },
          true,
        );
      }
    },
  );

  server.registerTool(
    "static_info",
    {
      description:
        "Report radare2 static-engine capabilities, r2 availability, and the open target (if any).",
      inputSchema: z.object({ session_id: sessionIdSchema }),
    },
    async ({ session_id }) => {
      const gate = requireStaticSession(session_id, "static_info");
      if (gate.error !== undefined) {
        return gate.error;
      }
      let r2: unknown;
      try {
        const found = await r2Version();
        r2 = { available: true, binary: found.binary, version: found.version };
      } catch (error) {
        r2 = {
          available: false,
          detail: error instanceof R2Error ? error.message : String(error),
        };
      }
      let target: unknown = null;
      if (radare2Engine.isOpen(session_id)) {
        try {
          const info = await radare2Engine.targetInfo(session_id);
          target = { open: true, ...info };
        } catch (error) {
          target = {
            open: true,
            path: radare2Engine.openPath(session_id) ?? null,
            error: error instanceof R2Error ? error.code : "engine_error",
            detail: error instanceof Error ? error.message : String(error),
          };
        }
      }
      return jsonResult({
        session_id,
        engine: "radare2",
        capabilities: radare2Capabilities,
        r2,
        target,
      });
    },
  );

  server.registerTool(
    "open_target",
    {
      description:
        "Open a binary target for static analysis in a radare2 session. Only mode 'static' is supported; anything else is a capability error. Requires r2 on PATH.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        path: z.string().min(1).describe("Filesystem path of the binary to analyze."),
        mode: z.string().default("static").describe('Analysis mode. Only "static" is supported.'),
      }),
    },
    async ({ session_id, path, mode }) => {
      const gate = requireStaticSession(session_id, "open_target");
      if (gate.error !== undefined) {
        return gate.error;
      }
      if (mode !== "static") {
        return capabilityFailure(
          "open_target",
          session_id,
          { mode },
          { mode: ["static"] },
          `open_target supports mode "static" only; got ${JSON.stringify(mode)}`,
        );
      }
      try {
        await radare2Engine.open(session_id, path);
        const openedPath = radare2Engine.openPath(session_id) ?? path;
        gate.session.events.push("target.opened", { path: openedPath, mode });
        return jsonResult({ opened: true, session_id, engine: "radare2", mode, path: openedPath });
      } catch (error) {
        return r2Failure(error, "open_target", session_id);
      }
    },
  );

  server.registerTool(
    "close_target",
    {
      description: "Release the binary target (and its radare2 process) held by a session.",
      inputSchema: z.object({ session_id: sessionIdSchema }),
    },
    async ({ session_id }) => {
      const gate = requireStaticSession(session_id, "close_target");
      if (gate.error !== undefined) {
        return gate.error;
      }
      const wasOpen = radare2Engine.isOpen(session_id);
      try {
        await radare2Engine.close(session_id);
      } catch (error) {
        return r2Failure(error, "close_target", session_id);
      }
      if (wasOpen) {
        gate.session.events.push("target.closed", {});
      }
      return jsonResult({ closed: wasOpen, session_id });
    },
  );

  server.registerTool(
    "disassemble",
    {
      description:
        "Disassemble instructions at an address (linear, `count` ops) or a whole function. Defaults to the entry function.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        address: addressSchema.optional(),
        function: z.string().min(1).optional().describe('Function name or address, e.g. "entry0".'),
        count: z.number().int().min(1).max(MAX_DISASM_COUNT).optional().describe("Ops for address mode (default 32)."),
      }),
    },
    async ({ session_id, address, function: fn, count }) => {
      const gate = requireStaticSession(session_id, "disassemble");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const result = await radare2Engine.disassemble(session_id, { address, function: fn, count });
        return jsonResult({ session_id, ...result });
      } catch (error) {
        return r2Failure(error, "disassemble", session_id);
      }
    },
  );

  server.registerTool(
    "get_cfg",
    {
      description:
        "Control-flow graph of a function as JSON and/or Graphviz DOT. Defaults to the entry function.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        address: addressSchema.optional(),
        function: z.string().min(1).optional().describe('Function name or address, e.g. "entry0".'),
        format: z.enum(["json", "dot", "both"]).default("both"),
      }),
    },
    async ({ session_id, address, function: fn, format }) => {
      const gate = requireStaticSession(session_id, "get_cfg");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const result = await radare2Engine.getCfg(session_id, { address, function: fn, format });
        return jsonResult({ session_id, ...result });
      } catch (error) {
        return r2Failure(error, "get_cfg", session_id);
      }
    },
  );

  server.registerTool(
    "xrefs",
    {
      description: "Cross-references to and/or from an address (code and data).",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        address: addressSchema,
        direction: z.enum(["to", "from", "both"]).default("both"),
      }),
    },
    async ({ session_id, address, direction }) => {
      const gate = requireStaticSession(session_id, "xrefs");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const result = await radare2Engine.xrefs(session_id, { address, direction });
        return jsonResult({ session_id, ...result });
      } catch (error) {
        return r2Failure(error, "xrefs", session_id);
      }
    },
  );

  server.registerTool(
    "strings",
    {
      description: "Strings found in the binary (address, section, length, text).",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        min_length: z.number().int().min(0).optional().describe("Keep strings with length >= this (default 0)."),
        limit: z.number().int().min(1).max(5000).optional().describe("Max strings returned (default 200)."),
        offset: z.number().int().min(0).optional().describe("Skip this many matches (default 0)."),
        section: z.string().min(1).optional().describe('Only strings from this section, e.g. ".rodata".'),
      }),
    },
    async ({ session_id, min_length, limit, offset, section }) => {
      const gate = requireStaticSession(session_id, "strings");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const result = await radare2Engine.strings(session_id, {
          minLength: min_length,
          limit,
          offset,
          section,
        });
        return jsonResult({ session_id, ...result });
      } catch (error) {
        return r2Failure(error, "strings", session_id);
      }
    },
  );

  server.registerTool(
    "dump",
    {
      description: "Read raw bytes at an address as hexdump text or a JSON byte array.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        address: addressSchema,
        length: z.number().int().min(1).max(MAX_DUMP_LENGTH).optional().describe("Bytes to read (default 128)."),
        format: z.enum(["hex", "json"]).default("hex"),
      }),
    },
    async ({ session_id, address, length, format }) => {
      const gate = requireStaticSession(session_id, "dump");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const result = await radare2Engine.dump(session_id, { address, length, format });
        return jsonResult({ session_id, ...result });
      } catch (error) {
        return r2Failure(error, "dump", session_id);
      }
    },
  );

  registerDebugTools(server);
  registerDynamicTools(server);
  registerGuideTools(server);
}
