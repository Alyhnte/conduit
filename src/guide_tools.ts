import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import { disassemble as disassembleDebug, instructionPointer } from "./dynamic_tools.js";
import { explainRegion, type ExplainInsn } from "./explain.js";
import { radare2Engine } from "./engines/radare2.js";
import { getDebugEngine, type LiveDebugEngine } from "./engines/registry.js";
import { engineKind, isDebugEngineId } from "./engines/types.js";
import { checkPrerequisites } from "./prereq.js";
import { registry } from "./registry.js";

type ToolContent = { type: "text"; text: string };
type ToolResult = { content: ToolContent[]; isError?: boolean };

function jsonResult(value: unknown, isError = false): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    ...(isError ? { isError: true } : {}),
  };
}

const sessionIdSchema = z.uuid().describe("Application session id. Not an MCP protocol session.");
const confirmSchema = z
  .boolean()
  .optional()
  .describe("Required only when explain itself disassembles a live debug session. Pasted instructions skip this.");

const insnSchema = z.object({
  address: z.string().optional(),
  opcode: z.string().optional(),
  mnemonic: z.string().optional(),
  operands: z.string().optional(),
  type: z.string().optional(),
  jump: z.string().optional(),
  fail: z.string().optional(),
  comment: z.string().optional(),
});

function confirmation(tool: string, session_id: string, engine: string, detail: Record<string, unknown>): ToolResult {
  return jsonResult(
    {
      error: "confirmation_required",
      tool,
      session_id,
      engine,
      action: "explain",
      message: "Onay gerekli. Bu çağrı hata ayıklayıcıya ulaşmadı. Aynı çağrıyı confirm:true ile tekrarlayın.",
      detail,
    },
    true,
  );
}

async function instructionsFromSession(
  sessionId: string,
  confirm: boolean | undefined,
  address: string | undefined,
  count: number,
): Promise<{ source: string; instructions: ExplainInsn[] } | ToolResult> {
  const session = registry.get(sessionId);
  if (session === undefined) {
    return jsonResult({ error: "session_not_found", tool: "explain", session_id: sessionId }, true);
  }
  if (!isDebugEngineId(session.engine)) {
    if (session.engine !== "radare2") {
      return jsonResult(
        {
          error: "capability_unsupported",
          tool: "explain",
          session_id: sessionId,
          engine: session.engine,
          detail: `explain needs radare2 or a debug session; this session is ${session.engine} (${engineKind(session.engine)})`,
        },
        true,
      );
    }
    const result = await radare2Engine.disassemble(sessionId, {
      ...(address !== undefined ? { address } : {}),
      count,
    });
    return {
      source: "radare2",
      instructions: result.ops.map((op) => ({
        address: op.address,
        opcode: op.opcode,
        type: op.type,
        ...(op.jump !== undefined ? { jump: op.jump } : {}),
        ...(op.fail !== undefined ? { fail: op.fail } : {}),
      })),
    };
  }
  if (confirm !== true) {
    return confirmation("explain", sessionId, session.engine, { address: address ?? "cip", count });
  }
  const engine: LiveDebugEngine = getDebugEngine(session.engine);
  const at = address ?? (await instructionPointer(engine, sessionId));
  const rows = await disassembleDebug(engine, sessionId, at, count);
  return {
    source: engine.id,
    instructions: rows.map((row) => ({
      address: row.address,
      mnemonic: row.mnemonic,
      operands: row.operands,
      opcode: `${row.mnemonic} ${row.operands}`.trim(),
    })),
  };
}

/**
 * Turkish assembly reading, and a prerequisite report with download hints.
 * explain does not touch a debugger when the caller passes instructions.
 */
export function registerGuideTools(server: McpServer): void {
  server.registerTool(
    "explain",
    {
      description:
        "Short Turkish explanation of an assembly window: what the region does, where it jumps, and which calls notify the user or the system. " +
        "Pass instructions already disassembled, or a session_id. A live debug session is read only when confirm is true. " +
        "Call this when the user asks what the assembly means.",
      inputSchema: z.object({
        session_id: sessionIdSchema.optional(),
        confirm: confirmSchema,
        address: z.union([z.string(), z.number()]).optional().describe("Address to disassemble when instructions are omitted."),
        count: z.number().int().min(1).max(32).optional().describe("How many instructions to read (default 16)."),
        instructions: z.array(insnSchema).max(64).optional().describe("Already fetched ops. When set, the debugger is not called."),
      }),
    },
    async ({ session_id, confirm, address, count, instructions }) => {
      try {
        const limit = count ?? 16;
        let source = "verilen_komutlar";
        let rows: ExplainInsn[] = instructions ?? [];
        if (rows.length === 0) {
          if (session_id === undefined) {
            return jsonResult(
              { error: "invalid_argument", tool: "explain", detail: "instructions or session_id is required" },
              true,
            );
          }
          const fetched = await instructionsFromSession(
            session_id,
            confirm,
            address === undefined ? undefined : String(address),
            limit,
          );
          if ("content" in fetched) {
            return fetched;
          }
          source = fetched.source;
          rows = fetched.instructions;
        }
        if (rows.length === 0) {
          return jsonResult({ error: "engine_error", tool: "explain", detail: "disassembly returned no instructions" }, true);
        }
        const usable = rows.filter((row) => (row.opcode ?? row.mnemonic ?? "").trim() !== "");
        if (usable.length === 0) {
          return jsonResult(
            { error: "invalid_argument", tool: "explain", detail: "each instruction needs opcode or mnemonic" },
            true,
          );
        }
        return jsonResult({ kaynak: source, ...explainRegion(usable) });
      } catch (error) {
        const code =
          error instanceof Error && "code" in error && typeof error.code === "string" ? error.code : "engine_error";
        return jsonResult(
          {
            error: code,
            tool: "explain",
            ...(session_id !== undefined ? { session_id } : {}),
            detail: error instanceof Error ? error.message : String(error),
          },
          true,
        );
      }
    },
  );

  server.registerTool(
    "prerequisites",
    {
      description:
        "Check the programs Conduit uses (radare2, x64dbg, cdb, Python, Frida, Graphviz, ScyllaHide). " +
        "Missing ones include a download URL and where to put the files. The bridge does not download them. " +
        "Call this when a tool is missing or before choosing an engine.",
      inputSchema: z.object({}),
    },
    async () => jsonResult(await checkPrerequisites()),
  );
}
