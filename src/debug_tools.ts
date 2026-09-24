import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import { CdbError } from "./engines/cdb.js";
import { FridaError } from "./engines/frida.js";
import { getDebugEngine, type LiveDebugEngine } from "./engines/registry.js";
import { engineKind, isDebugEngineId } from "./engines/types.js";
import { X64dbgError } from "./engines/x64dbg.js";
import { registry, type DebugSession } from "./registry.js";
import { clearCheckpoints } from "./snapshots.js";

type ToolContent = { type: "text"; text: string };

function jsonResult(value: unknown, isError = false): { content: ToolContent[]; isError?: boolean } {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    ...(isError ? { isError: true } : {}),
  };
}

const sessionIdSchema = z.uuid().describe("Application session id. Not an MCP protocol session.");

/** Hex string ("0x..."), decimal string, x64dbg symbol/expression, or a plain number. */
const addressSchema = z
  .union([z.string(), z.number()])
  .describe('Breakpoint address as hex ("0x140001000"), decimal, or x64dbg expression ("entry", "cip").');

type DebugGate =
  | { session: DebugSession; engine: LiveDebugEngine; error?: undefined }
  | { session?: undefined; engine?: undefined; error: ReturnType<typeof jsonResult> };

/**
 * Debug-tool precondition: the session must exist and belong to a debug
 * engine that has a registered instance. Static sessions and debug ids
 * without an adapter are capability errors, never stubs.
 */
function requireDebugSession(session_id: string, tool: string): DebugGate {
  const session = registry.get(session_id);
  if (session === undefined) {
    return { error: jsonResult({ error: "session_not_found", tool, session_id }, true) };
  }
  if (!isDebugEngineId(session.engine)) {
    return {
      error: jsonResult(
        {
          error: "capability_unsupported",
          tool,
          session_id,
          engine: session.engine,
          required: { kind: "debug" },
          detail:
            `tool '${tool}' needs a debug session (kind "debug"); ` +
            `session '${session_id}' belongs to '${session.engine}' (${engineKind(session.engine)})`,
        },
        true,
      ),
    };
  }
  return { session, engine: getDebugEngine(session.engine) };
}

function x64Failure(error: unknown, tool: string, session_id: string): ReturnType<typeof jsonResult> {
  if (error instanceof X64dbgError || error instanceof CdbError || error instanceof FridaError) {
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

/**
 * Forward async bridge pushes (stateChange frames from the debugger) into
 * the session ring buffer, where `events_pull` serves them with its
 * `after` cursor. The lookup is lazy so pushes after `session_close`
 * are dropped instead of throwing.
 */
function subscribeBridgePushes(session_id: string, engine: LiveDebugEngine): void {
  engine.onPush(session_id, (type, payload) => {
    const session = registry.get(session_id);
    if (session === undefined) {
      return;
    }
    session.events.push(type === "stateChange" ? "debug.state_changed" : "debug.event", payload ?? null);
  });
}

function continueEvent(reason: string): string {
  if (reason === "breakpoint") {
    return "debug.breakpoint_hit";
  }
  if (reason === "exited") {
    return "debug.exited";
  }
  return "debug.paused";
}

/**
 * Live-debug tools. Each call dispatches to the session's registered
 * debug engine; async debugger activity lands in the session event buffer
 * (`events_pull`).
 */
export function registerDebugTools(server: McpServer): void {
  server.registerTool(
    "debug_open",
    {
      description:
        "Open a PE target for live debugging on this session's debug engine. Auto-detects x86/x64 and leaves the debuggee paused. x64dbg breaks on entry; cdb stops at the initial loader breakpoint and reports the PE entry.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        path: z.string().min(1).describe("Filesystem path of the PE binary to debug."),
        break_on_entry: z.boolean().default(true).describe("Stop at the entry point after loading."),
        auto_analyze: z.boolean().default(false).describe("Run x64dbg auto-analysis after loading (slower)."),
        command_line_args: z.string().optional().describe("Command line arguments for the debuggee."),
      }),
    },
    async ({ session_id, path, break_on_entry, auto_analyze, command_line_args }) => {
      const gate = requireDebugSession(session_id, "debug_open");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const info = await gate.engine.open(session_id, path, {
          breakOnEntry: break_on_entry,
          autoAnalyze: auto_analyze,
          ...(command_line_args ? { commandLineArgs: command_line_args } : {}),
        });
        subscribeBridgePushes(session_id, gate.engine);
        const openedPath = gate.engine.openPath(session_id) ?? path;
        gate.session.events.push("target.opened", { path: openedPath, mode: "debug" });
        gate.session.events.push("debug.loaded", {
          pid: info.pid,
          architecture: info.architecture,
          entry_point: info.entryPoint,
          module_base: info.moduleBase,
          module_entry: info.moduleEntry,
        });
        return jsonResult({
          opened: true,
          session_id,
          engine: gate.engine.id,
          mode: "debug",
          attached: false,
          path: openedPath,
          pid: info.pid,
          architecture: info.architecture,
          entry_point: info.entryPoint,
          module_base: info.moduleBase,
          module_entry: info.moduleEntry,
        });
      } catch (error) {
        return x64Failure(error, "debug_open", session_id);
      }
    },
  );

  server.registerTool(
    "debug_attach",
    {
      description:
        "Attach by pid, or, on a frida session, connect to a listening Frida Gadget (gadget host:port) or a running mobile package on USB (usb + package). The target keeps running after debug_close.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        pid: z.number().int().min(1).optional().describe("Live process id. Required unless gadget or usb is set."),
        gadget: z
          .string()
          .min(1)
          .optional()
          .describe("Frida Gadget listen address host:port. For targets that cannot be attached by pid."),
        package: z
          .string()
          .min(1)
          .optional()
          .describe("Process or mobile package name. Defaults to Gadget. Required with usb."),
        usb: z.boolean().optional().describe("Use the USB Frida device (phone or tablet) instead of a host:port Gadget."),
        break_on_entry: z.boolean().default(true).describe("Pause the debuggee right after attaching."),
        auto_analyze: z.boolean().default(false).describe("Run x64dbg auto-analysis after attaching (slower)."),
      }),
    },
    async ({ session_id, pid, gadget, package: packageName, usb, break_on_entry, auto_analyze }) => {
      const gate = requireDebugSession(session_id, "debug_attach");
      if (gate.error !== undefined) {
        return gate.error;
      }
      const remote = gadget !== undefined || usb === true || packageName !== undefined;
      if (remote && gate.engine.id !== "frida") {
        return jsonResult(
          {
            error: "capability_unsupported",
            tool: "debug_attach",
            session_id,
            engine: gate.engine.id,
            detail: "gadget listen address and usb package attach are implemented for frida only",
          },
          true,
        );
      }
      if (remote && pid !== undefined) {
        return jsonResult(
          {
            error: "invalid_argument",
            tool: "debug_attach",
            session_id,
            detail: "pass pid or gadget/usb, not both",
          },
          true,
        );
      }
      if (!remote && pid === undefined) {
        return jsonResult(
          {
            error: "invalid_argument",
            tool: "debug_attach",
            session_id,
            detail: "pid is required unless gadget or usb is set",
          },
          true,
        );
      }
      try {
        const engine = gate.engine;
        const info = await (async () => {
          if (remote) {
            if (engine.id !== "frida") {
              throw new Error("unreachable frida remote attach");
            }
            return engine.attachRemote(session_id, {
              ...(gadget !== undefined ? { gadget } : {}),
              ...(usb === true ? { usb: true } : {}),
              ...(packageName !== undefined ? { packageName } : {}),
            });
          }
          return engine.attach(session_id, pid ?? 0, {
            breakOnEntry: break_on_entry,
            autoAnalyze: auto_analyze,
          });
        })();
        subscribeBridgePushes(session_id, gate.engine);
        const attachedPath = gate.engine.openPath(session_id) ?? `<attached-pid-${info.pid}>`;
        gate.session.events.push("target.opened", { path: attachedPath, mode: "debug", attached: true });
        gate.session.events.push("debug.attached", {
          pid: info.pid,
          architecture: info.architecture,
          entry_point: info.entryPoint,
          module_base: info.moduleBase,
          module_entry: info.moduleEntry,
        });
        return jsonResult({
          attached: true,
          session_id,
          engine: gate.engine.id,
          mode: "debug",
          path: attachedPath,
          pid: info.pid,
          architecture: info.architecture,
          entry_point: info.entryPoint,
          module_base: info.moduleBase,
          module_entry: info.moduleEntry,
        });
      } catch (error) {
        return x64Failure(error, "debug_attach", session_id);
      }
    },
  );

  server.registerTool(
    "debug_close",
    {
      description:
        "Tear down the hidden x64dbg process held by a session. Launched targets are stopped; attached targets are detached and left running.",
      inputSchema: z.object({ session_id: sessionIdSchema }),
    },
    async ({ session_id }) => {
      const gate = requireDebugSession(session_id, "debug_close");
      if (gate.error !== undefined) {
        return gate.error;
      }
      const wasOpen = gate.engine.isOpen(session_id);
      try {
        await gate.engine.close(session_id);
      } catch (error) {
        return x64Failure(error, "debug_close", session_id);
      }
      if (wasOpen) {
        gate.session.events.push("target.closed", {});
      }
      clearCheckpoints(session_id);
      return jsonResult({ closed: wasOpen, session_id });
    },
  );

  server.registerTool(
    "debug_state",
    {
      description: "Report live debug state (running/paused/terminated + pause reason) and the open target, if any.",
      inputSchema: z.object({ session_id: sessionIdSchema }),
    },
    async ({ session_id }) => {
      const gate = requireDebugSession(session_id, "debug_state");
      if (gate.error !== undefined) {
        return gate.error;
      }
      if (!gate.engine.isOpen(session_id)) {
        return jsonResult({ session_id, engine: gate.engine.id, open: false, target: null });
      }
      try {
        const state = await gate.engine.state(session_id);
        return jsonResult({
          session_id,
          engine: gate.engine.id,
          capabilities: gate.engine.capabilities,
          open: state.open,
          target: state.target,
          arch: state.arch,
          pid: state.pid,
          attached: state.attached,
          entry_point: state.entryPoint,
          module_base: state.moduleBase,
          module_entry: state.moduleEntry,
          opened_at: state.openedAt,
          state: state.state,
          pause_reason: state.pauseReason,
          termination_reason: state.terminationReason,
        });
      } catch (error) {
        return x64Failure(error, "debug_state", session_id);
      }
    },
  );

  server.registerTool(
    "debug_breakpoint",
    {
      description: "Set, remove, or list breakpoints. Address may be hex, a number, or an x64dbg expression.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        action: z.enum(["set", "remove", "list"]).default("set"),
        address: addressSchema.optional().describe("Required for set/remove; ignored for list."),
        type: z
          .enum([
            "software",
            "hardware_execute",
            "hardware_read",
            "hardware_write",
            "hardware_access",
            "memory_read",
            "memory_write",
            "memory_access",
          ])
          .default("software"),
        condition: z.string().optional().describe("Break condition expression (set only)."),
        name: z.string().optional().describe("Breakpoint name (set only)."),
        log_text: z.string().optional().describe("Log text on hit (set only)."),
      }),
    },
    async ({ session_id, action, address, type, condition, name, log_text }) => {
      const gate = requireDebugSession(session_id, "debug_breakpoint");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        if (action === "list") {
          const list = await gate.engine.listBreakpoints(session_id);
          return jsonResult({ session_id, ...list });
        }
        if (address === undefined) {
          return jsonResult(
            { error: "invalid_argument", tool: "debug_breakpoint", session_id, detail: `"address" is required for action "${action}"` },
            true,
          );
        }
        if (action === "remove") {
          const removed = await gate.engine.removeBreakpoint(session_id, address);
          gate.session.events.push("debug.breakpoint_removed", { address: String(address) });
          return jsonResult({ session_id, action, address: String(address), ...removed });
        }
        const set = await gate.engine.setBreakpoint(session_id, {
          address,
          type,
          ...(condition !== undefined ? { condition } : {}),
          ...(name !== undefined ? { name } : {}),
          ...(log_text !== undefined ? { logText: log_text } : {}),
        });
        gate.session.events.push("debug.breakpoint_set", { address: set.address, type });
        return jsonResult({ session_id, action, type, ...set });
      } catch (error) {
        return x64Failure(error, "debug_breakpoint", session_id);
      }
    },
  );

  server.registerTool(
    "debug_continue",
    {
      description:
        "Resume the debuggee until the next breakpoint, single-step, or exit. The stop posts an event (debug.breakpoint_hit / debug.exited / debug.paused) retrievable via events_pull.",
      inputSchema: z.object({ session_id: sessionIdSchema }),
    },
    async ({ session_id }) => {
      const gate = requireDebugSession(session_id, "debug_continue");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const result = await gate.engine.continue_(session_id);
        gate.session.events.push(continueEvent(result.reason), {
          reason: result.reason,
          address: result.address,
        });
        return jsonResult({ session_id, ...result });
      } catch (error) {
        return x64Failure(error, "debug_continue", session_id);
      }
    },
  );

  server.registerTool(
    "debug_step",
    {
      description: "Single-step the debuggee (into or over calls) and report the new location.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        kind: z.enum(["into", "over"]).default("into"),
        count: z.number().int().min(1).max(1000).optional().describe("Steps to take (default 1)."),
      }),
    },
    async ({ session_id, kind, count }) => {
      const gate = requireDebugSession(session_id, "debug_step");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const result = await gate.engine.step(session_id, kind, count ?? 1);
        gate.session.events.push("debug.stepped", { kind, address: result.address });
        return jsonResult({ session_id, kind, ...result });
      } catch (error) {
        return x64Failure(error, "debug_step", session_id);
      }
    },
  );

  server.registerTool(
    "debug_pause",
    {
      description: "Asynchronously break a running debuggee. Idempotent when already paused.",
      inputSchema: z.object({ session_id: sessionIdSchema }),
    },
    async ({ session_id }) => {
      const gate = requireDebugSession(session_id, "debug_pause");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const result = await gate.engine.pause(session_id);
        gate.session.events.push("debug.paused", { reason: result.reason, address: result.address });
        return jsonResult({ session_id, ...result });
      } catch (error) {
        return x64Failure(error, "debug_pause", session_id);
      }
    },
  );

  server.registerTool(
    "debug_registers",
    {
      description: "Read debuggee registers (general + flags; segment/debug optionally).",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        include_segment: z.boolean().optional().describe("Include segment registers."),
        include_debug: z.boolean().optional().describe("Include debug registers."),
      }),
    },
    async ({ session_id, include_segment, include_debug }) => {
      const gate = requireDebugSession(session_id, "debug_registers");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const result = await gate.engine.registers(session_id, {
          ...(include_segment ? { includeSegment: true } : {}),
          ...(include_debug ? { includeDebug: true } : {}),
        });
        return jsonResult({ session_id, ...result });
      } catch (error) {
        return x64Failure(error, "debug_registers", session_id);
      }
    },
  );

  server.registerTool(
    "debug_callstack",
    {
      description: "Read the current thread's call stack (address, module, function per frame).",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        max_frames: z.number().int().min(1).max(500).optional().describe("Max frames returned (default 50)."),
      }),
    },
    async ({ session_id, max_frames }) => {
      const gate = requireDebugSession(session_id, "debug_callstack");
      if (gate.error !== undefined) {
        return gate.error;
      }
      try {
        const result = await gate.engine.callStack(session_id, max_frames ?? 50);
        return jsonResult({ session_id, ...result });
      } catch (error) {
        return x64Failure(error, "debug_callstack", session_id);
      }
    },
  );
}
