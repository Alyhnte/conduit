import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";

import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import { suggestDownload } from "./catalog.js";
import { CdbError } from "./engines/cdb.js";
import { FridaError } from "./engines/frida.js";
import { getDebugEngine, type LiveDebugEngine } from "./engines/registry.js";
import { engineKind, isDebugEngineId } from "./engines/types.js";
import { debuggerArchDir, resolveDebuggerExe, resolveX64dbgDir, X64dbgError, x64dbgContinueTimeoutMs, type X64Arch } from "./engines/x64dbg.js";
import { registry, type DebugSession } from "./registry.js";
import { addCheckpoint, CHECKPOINT_LIMITS, getCheckpoint, listCheckpoints, type CheckpointThread } from "./snapshots.js";

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
  .describe("Must be true or the tool returns confirmation_required and does not touch the debuggee.");
const addressSchema = z
  .union([z.string(), z.number()])
  .describe('Address as hex ("0x140001000"), decimal, or an engine expression ("cip").');

class ToolInputError extends Error {
  readonly code = "invalid_argument" as const;
  constructor(message: string) {
    super(message);
    this.name = "ToolInputError";
  }
}

const RESTORE_REGS = new Set([
  "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
  "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
]);

interface MemoryView {
  address: string;
  size: number;
  hex: string;
  ascii: string;
}

interface Insn {
  address: string;
  bytes: string;
  mnemonic: string;
  operands: string;
}

interface ThreadRow {
  id: number;
  current: boolean;
  state: string | null;
  entry: string | null;
}

interface StopView {
  address: string;
  reason: string;
  reached: boolean;
}

type Begun =
  | { ok: true; session: DebugSession; engine: LiveDebugEngine }
  | { ok: false; result: ToolResult };

function failure(error: unknown, tool: string, session_id: string): ToolResult {
  if (error instanceof X64dbgError || error instanceof CdbError || error instanceof FridaError || error instanceof ToolInputError) {
    return jsonResult(
      { error: error.code, tool, session_id, detail: error.message, ...("data" in error ? (error.data ?? {}) : {}) },
      true,
    );
  }
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

function begin(
  tool: string,
  session_id: string,
  confirm: boolean | undefined,
  action: string,
  detail: Record<string, unknown>,
): Begun {
  const session = registry.get(session_id);
  if (session === undefined) {
    return { ok: false, result: jsonResult({ error: "session_not_found", tool, session_id }, true) };
  }
  if (!isDebugEngineId(session.engine)) {
    return {
      ok: false,
      result: jsonResult(
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
  if (confirm !== true) {
    return {
      ok: false,
      result: jsonResult(
        {
          error: "confirmation_required",
          tool,
          session_id,
          engine: session.engine,
          action,
          message: "Onay gerekli. Bu çağrı hata ayıklayıcıya ulaşmadı. Aynı çağrıyı confirm:true ile tekrarlayın.",
          detail,
        },
        true,
      ),
    };
  }
  return { ok: true, session, engine: getDebugEngine(session.engine) };
}

function unsupported(tool: string, session_id: string, engine: string, requested: string, detail: string): ToolResult {
  return jsonResult({ error: "capability_unsupported", tool, session_id, engine, requested, detail }, true);
}

function parseAddress(value: string | number, label: string): string {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
      throw new ToolInputError(`"${label}" must be a non-negative integer`);
    }
    return `0x${value.toString(16)}`;
  }
  const trimmed = value.trim();
  if (trimmed === "" || trimmed.length > 256 || !/^[0-9A-Za-z_$.+\-*/()]+$/.test(trimmed)) {
    throw new ToolInputError(`"${label}" must be hex, decimal, or an engine expression`);
  }
  return trimmed;
}

function canonicalHex(address: string): string | undefined {
  const trimmed = address.trim();
  if (/^0x[0-9a-fA-F]+$/i.test(trimmed)) {
    return `0x${BigInt(trimmed).toString(16)}`;
  }
  if (/^\d+$/.test(trimmed)) {
    return `0x${BigInt(trimmed).toString(16)}`;
  }
  return undefined;
}

function addHex(address: string, offset: number): string {
  return `0x${(BigInt(address) + BigInt(offset)).toString(16)}`;
}

function sameAddr(left: string, right: string): boolean {
  try {
    return BigInt(left) === BigInt(right);
  } catch {
    return left.toLowerCase() === right.toLowerCase();
  }
}

function hexToAscii(hex: string): string {
  let ascii = "";
  for (let i = 0; i < hex.length; i += 2) {
    const value = Number.parseInt(hex.slice(i, i + 2), 16);
    ascii += value >= 32 && value < 127 ? String.fromCharCode(value) : ".";
  }
  return ascii;
}

function hexTokens(pattern: string): string[] {
  const trimmed = pattern.trim();
  if (/^[0-9a-fA-F]{2}$/.test(trimmed) || /^[0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2})+$/.test(trimmed)) {
    return trimmed.toLowerCase().split(/\s+/);
  }
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0 && trimmed.length <= 256) {
    return trimmed.toLowerCase().match(/../g) ?? [];
  }
  throw new ToolInputError("pattern must be hex bytes");
}

function asciiTokens(pattern: string): string[] {
  if (pattern.length === 0 || pattern.length > 128 || /[^\x20-\x7e]/.test(pattern) || pattern.includes('"')) {
    throw new ToolInputError("ascii pattern must be printable and contain no quotes");
  }
  const tokens: string[] = [];
  for (const ch of pattern) {
    tokens.push(ch.charCodeAt(0).toString(16).padStart(2, "0"));
  }
  return tokens;
}

function parseInstruction(text: string): string {
  const trimmed = text.trim();
  if (trimmed.length === 0 || trimmed.length > 200 || /[\r\n;"'`|&]/.test(trimmed)) {
    throw new ToolInputError("instruction must be a single assembler line");
  }
  return trimmed;
}

function requireThreadId(threadId: number | undefined): number {
  if (threadId === undefined || !Number.isInteger(threadId) || threadId < 0) {
    throw new ToolInputError("thread_id must be a non-negative integer from debug_thread list");
  }
  return threadId;
}

function parseDb(body: string): string {
  let hex = "";
  for (const line of body.split(/\r?\n/)) {
    const match = /^[0-9a-fA-F`]{8,17}\s+(.*)$/.exec(line.trim());
    const rest = match?.[1];
    if (rest === undefined) {
      continue;
    }
    const hexPart = rest.split(/\s{2,}/)[0] ?? rest;
    for (const token of hexPart.replace(/-/g, " ").split(/\s+/)) {
      if (/^[0-9a-fA-F]{2}$/.test(token)) {
        hex += token.toLowerCase();
      }
    }
  }
  return hex;
}

function parseDisasm(body: string): Insn[] {
  const out: Insn[] = [];
  for (const line of body.split(/\r?\n/)) {
    const match = /^([0-9a-fA-F`]{8,17})\s+([0-9a-fA-F]{2,})\s+(\S+)(?:\s+(.*))?$/.exec(line.trim());
    if (match?.[1] === undefined || match[2] === undefined || match[3] === undefined) {
      continue;
    }
    out.push({
      address: `0x${BigInt(`0x${match[1].replace(/`/g, "")}`).toString(16)}`,
      bytes: match[2].toLowerCase(),
      mnemonic: match[3],
      operands: (match[4] ?? "").trim(),
    });
  }
  return out;
}

function parseSearch(body: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of body.split(/\r?\n/)) {
    const match = /^([0-9a-fA-F`]{8,17})\b/.exec(line.trim());
    const raw = match?.[1];
    if (raw === undefined) {
      continue;
    }
    const address = `0x${BigInt(`0x${raw.replace(/`/g, "")}`).toString(16)}`;
    if (!seen.has(address)) {
      seen.add(address);
      out.push(address);
    }
  }
  return out;
}

function parseCdbThreads(body: string): ThreadRow[] {
  const out: ThreadRow[] = [];
  for (const line of body.split(/\r?\n/)) {
    const match =
      /^([.#* ]*)(\d+)\s+Id:\s+[0-9a-fA-F]+\.[0-9a-fA-F]+\s+Suspend:\s+\d+\s+Teb:\s+\S+\s+(\S+)/.exec(line.trim());
    if (match?.[2] === undefined || match[3] === undefined) {
      continue;
    }
    out.push({
      id: Number(match[2]),
      current: (match[1] ?? "").includes(".") || (match[1] ?? "").includes("#") || (match[1] ?? "").includes("*"),
      state: match[3],
      entry: null,
    });
  }
  return out;
}

function parseRegs(body: string): Record<string, string> {
  const general: Record<string, string> = {};
  for (const match of body.matchAll(/\b([A-Za-z][A-Za-z0-9]{1,3})=([0-9a-fA-F]+)/g)) {
    const name = match[1]?.toLowerCase();
    const raw = match[2];
    if (name === undefined || raw === undefined || name === "iopl") {
      continue;
    }
    general[name] = `0x${BigInt(`0x${raw}`).toString(16)}`;
  }
  return general;
}

function restoreNames(registers: Record<string, string>): string[] {
  const names = Object.keys(registers).filter((name) => RESTORE_REGS.has(name) && name !== "rip" && name !== "eip");
  if (registers.rip !== undefined) {
    names.push("rip");
  }
  if (registers.eip !== undefined) {
    names.push("eip");
  }
  return names;
}

function asRecord(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    throw new Error(`${what} returned a non-object`);
  }
  return value as Record<string, unknown>;
}

async function numericAddress(engine: LiveDebugEngine, sessionId: string, address: string): Promise<string> {
  const direct = canonicalHex(address);
  if (direct !== undefined) {
    return direct;
  }
  switch (engine.id) {
    case "cdb": {
      const body = await engine.debuggerCommand(sessionId, `? ${address}`);
      const match = /=\s*([0-9a-fA-F`]{4,})/.exec(body);
      const raw = match?.[1];
      if (raw === undefined) {
        throw new CdbError("engine_error", "cdb did not evaluate the address", { excerpt: body.slice(0, 400) });
      }
      return `0x${BigInt(`0x${raw.replace(/`/g, "")}`).toString(16)}`;
    }
    case "x64dbg":
      return address;
    case "frida":
      throw new ToolInputError("frida addresses must be numeric hex or decimal");
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
}

async function readMemory(engine: LiveDebugEngine, sessionId: string, address: string, size: number): Promise<MemoryView> {
  switch (engine.id) {
    case "x64dbg": {
      const raw = asRecord(
        await engine.bridgeCall(sessionId, "memory.read", { address, size }),
        "memory.read",
      );
      const hex = typeof raw.hex === "string" ? raw.hex.replace(/\s+/g, "").toLowerCase() : "";
      if (hex.length === 0 || hex.length % 2 !== 0) {
        throw new X64dbgError("engine_error", "x64dbg memory read returned no bytes");
      }
      return {
        address: typeof raw.address === "string" ? raw.address : address,
        size: typeof raw.size === "number" ? raw.size : hex.length / 2,
        hex,
        ascii: typeof raw.ascii === "string" ? raw.ascii : hexToAscii(hex),
      };
    }
    case "cdb": {
      const start = await numericAddress(engine, sessionId, address);
      let hex = "";
      let offset = 0;
      while (offset < size) {
        const n = Math.min(0x80, size - offset);
        const at = addHex(start, offset);
        const body = await engine.debuggerCommand(sessionId, `db ${at} L${n.toString(16)}`);
        const chunk = parseDb(body);
        if (chunk.length < n * 2) {
          throw new CdbError("engine_error", "cdb memory read was shorter than requested", {
            excerpt: body.slice(0, 400),
            address: at,
            size: n,
          });
        }
        hex += chunk.slice(0, n * 2);
        offset += n;
      }
      return { address: start, size, hex, ascii: hexToAscii(hex) };
    }
    case "frida": {
      const start = await numericAddress(engine, sessionId, address);
      const raw = asRecord(await engine.callAgent(sessionId, "readMemory", [start, size]), "readMemory");
      const hex = typeof raw.hex === "string" ? raw.hex.toLowerCase() : "";
      if (hex.length === 0) {
        throw new FridaError("engine_error", "frida memory read returned no bytes");
      }
      return {
        address: typeof raw.address === "string" ? raw.address : start,
        size: typeof raw.size === "number" ? raw.size : hex.length / 2,
        hex,
        ascii: typeof raw.ascii === "string" ? raw.ascii : hexToAscii(hex),
      };
    }
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
}

async function writeMemory(engine: LiveDebugEngine, sessionId: string, address: string, hex: string): Promise<number> {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  switch (engine.id) {
    case "x64dbg": {
      const raw = asRecord(
        await engine.bridgeCall(sessionId, "memory.write", { address, hexBytes: clean }),
        "memory.write",
      );
      return typeof raw.bytesWritten === "number" ? raw.bytesWritten : clean.length / 2;
    }
    case "cdb": {
      const start = await numericAddress(engine, sessionId, address);
      let offset = 0;
      while (offset < clean.length) {
        const slice = clean.slice(offset, offset + 32);
        const bytes = slice.match(/../g) ?? [];
        const at = addHex(start, offset / 2);
        await engine.debuggerCommand(sessionId, `eb ${at} ${bytes.join(" ")}`);
        offset += slice.length;
      }
      return clean.length / 2;
    }
    case "frida": {
      const start = await numericAddress(engine, sessionId, address);
      const raw = asRecord(await engine.callAgent(sessionId, "writeMemory", [start, clean]), "writeMemory");
      return typeof raw.bytesWritten === "number" ? raw.bytesWritten : clean.length / 2;
    }
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
}

async function defaultRange(engine: LiveDebugEngine, sessionId: string): Promise<{ start: string; length: number }> {
  switch (engine.id) {
    case "frida": {
      const raw = asRecord(await engine.callAgent(sessionId, "moduleRange", []), "moduleRange");
      const base = typeof raw.base === "string" ? raw.base : "0x0";
      const size = typeof raw.size === "number" ? raw.size : 0x1000;
      return { start: base, length: Math.min(size, 0x100000) };
    }
    case "cdb":
    case "x64dbg": {
      const state = await engine.state(sessionId);
      if (state.moduleBase === null) {
        throw new ToolInputError("pass start_address; the engine has no module base yet");
      }
      return { start: state.moduleBase, length: 0x1000 };
    }
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
}

async function searchMemory(
  engine: LiveDebugEngine,
  sessionId: string,
  pattern: string,
  searchType: "hex" | "ascii",
  start: string | undefined,
  length: number | undefined,
  maxResults: number,
): Promise<{ matches: { address: string }[]; total_found: number; truncated: boolean }> {
  const tokens = searchType === "ascii" ? asciiTokens(pattern) : hexTokens(pattern);
  const ranged = start === undefined ? await defaultRange(engine, sessionId) : { start, length: length ?? 0x1000 };
  switch (engine.id) {
    case "x64dbg": {
      const end = canonicalHex(ranged.start);
      const params: Record<string, unknown> = {
        pattern: searchType === "ascii" ? pattern : tokens.join(" "),
        searchType: searchType === "ascii" ? "ascii" : "hex",
        maxResults,
      };
      if (end !== undefined) {
        params.startAddress = end;
        params.endAddress = addHex(end, ranged.length);
      } else {
        params.startAddress = ranged.start;
        params.endAddress = `${ranged.start}+0x${ranged.length.toString(16)}`;
      }
      const raw = asRecord(await engine.bridgeCall(sessionId, "memory.search", params), "memory.search");
      const rows = Array.isArray(raw.matches) ? raw.matches : [];
      const matches = rows.map((row) => {
        const rec = asRecord(row, "match");
        return { address: typeof rec.address === "string" ? rec.address : "0x0" };
      });
      const total = typeof raw.totalFound === "number" ? raw.totalFound : matches.length;
      return { matches, total_found: total, truncated: raw.truncated === true };
    }
    case "cdb": {
      const at = await numericAddress(engine, sessionId, ranged.start);
      const command =
        searchType === "ascii"
          ? `s -a ${at} L${ranged.length.toString(16)} "${pattern}"`
          : `s -b ${at} L${ranged.length.toString(16)} ${tokens.join(" ")}`;
      const found = parseSearch(await engine.debuggerCommand(sessionId, command));
      return {
        matches: found.slice(0, maxResults).map((address) => ({ address })),
        total_found: found.length,
        truncated: found.length > maxResults,
      };
    }
    case "frida": {
      const at = await numericAddress(engine, sessionId, ranged.start);
      const raw = asRecord(
        await engine.callAgent(sessionId, "searchMemory", [at, ranged.length, tokens.join(" "), maxResults]),
        "searchMemory",
      );
      const rows = Array.isArray(raw.matches) ? raw.matches : [];
      const matches = rows.map((row) => {
        const rec = asRecord(row, "match");
        return { address: typeof rec.address === "string" ? rec.address : "0x0" };
      });
      const total = typeof raw.totalFound === "number" ? raw.totalFound : matches.length;
      return { matches, total_found: total, truncated: raw.truncated === true };
    }
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
}

export async function instructionPointer(engine: LiveDebugEngine, sessionId: string): Promise<string> {
  switch (engine.id) {
    case "frida": {
      const ip = await engine.callAgent<string>(sessionId, "instructionPointer", []);
      if (typeof ip !== "string" || ip.length === 0) {
        throw new FridaError("engine_error", "frida did not return an instruction pointer");
      }
      return ip;
    }
    case "cdb":
    case "x64dbg": {
      const regs = await engine.registers(sessionId);
      const ip = regs.general.rip ?? regs.general.eip;
      if (ip === undefined) {
        throw new ToolInputError("pass address; the engine did not report rip or eip");
      }
      return ip;
    }
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
}

export async function disassemble(engine: LiveDebugEngine, sessionId: string, address: string, count: number): Promise<Insn[]> {
  switch (engine.id) {
    case "x64dbg": {
      const raw = asRecord(
        await engine.bridgeCall(sessionId, "analysis.disassemble", { address, count }),
        "analysis.disassemble",
      );
      const rows = Array.isArray(raw.instructions) ? raw.instructions : [];
      return rows.map((row) => {
        const rec = asRecord(row, "instruction");
        return {
          address: typeof rec.address === "string" ? rec.address : "0x0",
          bytes: typeof rec.bytes === "string" ? rec.bytes.toLowerCase() : "",
          mnemonic: typeof rec.mnemonic === "string" ? rec.mnemonic : "",
          operands: typeof rec.operands === "string" ? rec.operands : "",
        };
      });
    }
    case "cdb": {
      const at = await numericAddress(engine, sessionId, address);
      const body = await engine.debuggerCommand(sessionId, `u ${at} L${count.toString(16)}`);
      const rows = parseDisasm(body);
      if (rows.length === 0) {
        throw new CdbError("engine_error", "cdb disassembly was not recognized", { excerpt: body.slice(0, 400) });
      }
      return rows.slice(0, count);
    }
    case "frida": {
      const at = await numericAddress(engine, sessionId, address);
      const raw = asRecord(await engine.callAgent(sessionId, "disassemble", [at, count]), "disassemble");
      const rows = Array.isArray(raw.instructions) ? raw.instructions : [];
      if (rows.length === 0) {
        throw new FridaError("engine_error", "frida disassembly returned no instructions");
      }
      return rows.map((row) => {
        const rec = asRecord(row, "instruction");
        return {
          address: typeof rec.address === "string" ? rec.address : "0x0",
          bytes: typeof rec.bytes === "string" ? rec.bytes.toLowerCase() : "",
          mnemonic: typeof rec.mnemonic === "string" ? rec.mnemonic : "",
          operands: typeof rec.operands === "string" ? rec.operands : "",
        };
      });
    }
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
}

async function listThreads(engine: LiveDebugEngine, sessionId: string): Promise<{ active_thread_id: number | null; threads: ThreadRow[] }> {
  switch (engine.id) {
    case "x64dbg": {
      const raw = asRecord(await engine.bridgeCall(sessionId, "threads.list", {}), "threads.list");
      const rows = Array.isArray(raw.threads) ? raw.threads : [];
      const active = typeof raw.activeThreadId === "number" ? raw.activeThreadId : null;
      const threads = rows.map((row) => {
        const rec = asRecord(row, "thread");
        const id = typeof rec.id === "number" ? rec.id : 0;
        return {
          id,
          current: active === id,
          state: typeof rec.state === "string" && rec.state !== "" ? rec.state : null,
          entry: typeof rec.entry === "string" ? rec.entry : null,
        };
      });
      return { active_thread_id: active, threads };
    }
    case "cdb": {
      const body = await engine.debuggerCommand(sessionId, "~");
      const threads = parseCdbThreads(body);
      if (threads.length === 0) {
        throw new CdbError("engine_error", "cdb thread list was not recognized", { excerpt: body.slice(0, 500) });
      }
      const active = threads.find((row) => row.current)?.id ?? null;
      return { active_thread_id: active, threads };
    }
    case "frida": {
      const raw = asRecord(await engine.callAgent(sessionId, "listThreads", []), "listThreads");
      const rows = Array.isArray(raw.threads) ? raw.threads : [];
      const active = typeof raw.activeThreadId === "number" ? raw.activeThreadId : null;
      const threads = rows.map((row) => {
        const rec = asRecord(row, "thread");
        return {
          id: typeof rec.id === "number" ? rec.id : 0,
          current: rec.current === true,
          state: typeof rec.state === "string" ? rec.state : null,
          entry: typeof rec.entry === "string" ? rec.entry : null,
        };
      });
      return { active_thread_id: active, threads };
    }
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
}

async function runTo(engine: LiveDebugEngine, sessionId: string, address: string): Promise<StopView> {
  switch (engine.id) {
    case "x64dbg": {
      const raw = asRecord(
        await engine.bridgeCall(sessionId, "debug.runToAddress", { address }, x64dbgContinueTimeoutMs()),
        "debug.runToAddress",
      );
      return {
        address: typeof raw.stopAddress === "string" ? raw.stopAddress : "0x0",
        reason: typeof raw.reason === "string" ? raw.reason : "paused",
        reached: raw.reached === true,
      };
    }
    case "cdb": {
      const stop = await engine.runTo(sessionId, address);
      return { address: stop.address, reason: stop.reason, reached: sameAddr(stop.address, address) };
    }
    case "frida": {
      await engine.setBreakpoint(sessionId, { address, type: "hardware_execute" });
      const stop = await engine.continue_(sessionId);
      return { address: stop.address, reason: stop.reason, reached: sameAddr(stop.address, address) };
    }
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
}

function stopEvent(reason: string, reached: boolean): string {
  if (reason === "exited") {
    return "debug.exited";
  }
  return reached ? "debug.breakpoint_hit" : "debug.continued";
}

async function capture(engine: LiveDebugEngine, sessionId: string, memorySize: number) {
  const listed = await listThreads(engine, sessionId);
  const address = await instructionPointer(engine, sessionId);
  const memory = await readMemory(engine, sessionId, address, memorySize);
  let registers: Record<string, string> = {};
  switch (engine.id) {
    case "cdb":
    case "x64dbg": {
      const regs = await engine.registers(sessionId);
      registers = regs.general;
      break;
    }
    case "frida": {
      if (listed.active_thread_id !== null) {
        const raw = asRecord(
          await engine.callAgent(sessionId, "threadContext", [listed.active_thread_id]),
          "threadContext",
        );
        const general = asRecord(raw.general ?? {}, "general");
        for (const [name, value] of Object.entries(general)) {
          if (typeof value === "string") {
            registers[name] = value;
          }
        }
      }
      break;
    }
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
  const threads: CheckpointThread[] = listed.threads.map((row) => ({
    id: row.id,
    current: row.current,
    state: row.state,
    entry: row.entry,
  }));
  return addCheckpoint({
    sessionId,
    engine: engine.id,
    address,
    threadId: listed.active_thread_id,
    registers,
    threads,
    memoryAddress: memory.address,
    memoryHex: memory.hex,
  });
}

async function restoreRegisters(engine: LiveDebugEngine, sessionId: string, registers: Record<string, string>): Promise<void> {
  const names = restoreNames(registers);
  switch (engine.id) {
    case "x64dbg": {
      for (const name of names) {
        const value = registers[name];
        if (value === undefined) {
          continue;
        }
        await engine.bridgeCall(sessionId, "registers.set", { register: name, value });
      }
      return;
    }
    case "cdb": {
      for (const name of names) {
        const value = registers[name];
        if (value === undefined) {
          continue;
        }
        await engine.debuggerCommand(sessionId, `r ${name}=${value}`);
      }
      return;
    }
    case "frida":
      throw new FridaError("capability_unsupported", "frida register restore is applied separately");
    default: {
      const neverEngine: never = engine;
      throw new ToolInputError(String(neverEngine));
    }
  }
}

interface PluginRow {
  arch: X64Arch;
  debugger_dir: string;
  plugins_dir: string;
  gui_dll: string;
  gui_dll_present: boolean;
  hide_plugins: string[];
  dump_plugins: string[];
}

async function scyllaRows(): Promise<PluginRow[]> {
  const root = await resolveX64dbgDir();
  const rows: PluginRow[] = [];
  const arches: X64Arch[] = ["x64", "x86"];
  for (const arch of arches) {
    let exe: string;
    try {
      exe = await resolveDebuggerExe(root, arch);
    } catch {
      continue;
    }
    const dir = debuggerArchDir(exe);
    const pluginsDir = join(dir, "plugins");
    let names: string[] = [];
    try {
      names = await readdir(pluginsDir);
    } catch {
      names = [];
    }
    const gui = join(dir, "Scylla.dll");
    let guiPresent = false;
    try {
      await stat(gui);
      guiPresent = true;
    } catch {
      guiPresent = false;
    }
    rows.push({
      arch,
      debugger_dir: dir,
      plugins_dir: pluginsDir,
      gui_dll: gui,
      gui_dll_present: guiPresent,
      hide_plugins: names.filter((name) => /scyllahide/i.test(name) && /\.dp(32|64)$/i.test(name)),
      dump_plugins: names.filter((name) => /scylla/i.test(name) && !/hide/i.test(name) && /\.dp(32|64)$/i.test(name)),
    });
  }
  if (rows.length === 0) {
    throw new X64dbgError("engine_unavailable", `x64dbg debugger executables were not found under ${root}`);
  }
  return rows;
}

/**
 * Live memory, code, thread, plugin, and checkpoint tools.
 * Every call requires confirm:true. A call without it does not touch the debuggee.
 */
export function registerDynamicTools(server: McpServer): void {
  server.registerTool(
    "debug_memory",
    {
      description:
        "Live process memory: read, search, or dump. Requires confirm:true. Without it the call returns confirmation_required and does not touch the debuggee.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        confirm: confirmSchema,
        action: z.enum(["read", "search", "dump"]),
        address: addressSchema.optional().describe("Read/dump address."),
        size: z.number().int().min(1).max(65536).optional().describe("Byte count for read (default 64) or dump (default 256)."),
        pattern: z.string().max(256).optional().describe("Search pattern. Hex bytes, or ascii when search_type is ascii."),
        search_type: z.enum(["hex", "ascii"]).optional(),
        start_address: addressSchema.optional(),
        length: z.number().int().min(1).max(1048576).optional().describe("Search length in bytes (default 4096, or the main module)."),
        max_results: z.number().int().min(1).max(100).optional(),
      }),
    },
    async ({ session_id, confirm, action, address, size, pattern, search_type, start_address, length, max_results }) => {
      try {
        if ((action === "read" || action === "dump") && address === undefined) {
          throw new ToolInputError("address is required for read and dump");
        }
        if (action === "search" && (pattern === undefined || pattern.trim() === "")) {
          throw new ToolInputError("pattern is required for search");
        }
        const begun = begin("debug_memory", session_id, confirm, action, {
          address: address ?? null,
          size: size ?? null,
          pattern: pattern ?? null,
          search_type: search_type ?? "hex",
          start_address: start_address ?? null,
          length: length ?? null,
        });
        if (!begun.ok) {
          return begun.result;
        }
        const { engine } = begun;
        if (action === "read" || action === "dump") {
          const at = parseAddress(address ?? "0", "address");
          const count = size ?? (action === "dump" ? 256 : 64);
          const memory = await readMemory(engine, session_id, at, count);
          return jsonResult({ session_id, engine: engine.id, action, live: true, ...memory });
        }
        if (action === "search") {
          const found = await searchMemory(
            engine,
            session_id,
            pattern ?? "",
            search_type ?? "hex",
            start_address === undefined ? undefined : parseAddress(start_address, "start_address"),
            length,
            max_results ?? 20,
          );
          return jsonResult({ session_id, engine: engine.id, action, live: true, ...found });
        }
        const neverAction: never = action;
        throw new ToolInputError(String(neverAction));
      } catch (error) {
        return failure(error, "debug_memory", session_id);
      }
    },
  );

  server.registerTool(
    "debug_code",
    {
      description:
        "Live code: disassemble at an address (default: the stopped instruction pointer), assemble one instruction, or run until an address. Requires confirm:true.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        confirm: confirmSchema,
        action: z.enum(["disassemble", "assemble", "run_to"]),
        address: addressSchema.optional(),
        count: z.number().int().min(1).max(64).optional().describe("Instruction count for disassemble (default 12)."),
        instruction: z.string().max(200).optional().describe("Single instruction for assemble."),
      }),
    },
    async ({ session_id, confirm, action, address, count, instruction }) => {
      try {
        if (action === "assemble") {
          if (instruction === undefined) {
            throw new ToolInputError("instruction is required for assemble");
          }
          parseInstruction(instruction);
        }
        if ((action === "assemble" || action === "run_to") && address === undefined) {
          throw new ToolInputError("address is required for assemble and run_to");
        }
        const begun = begin("debug_code", session_id, confirm, action, {
          address: address ?? "cip",
          count: count ?? null,
          instruction: instruction ?? null,
        });
        if (!begun.ok) {
          return begun.result;
        }
        const { session, engine } = begun;
        if (action === "disassemble") {
          const at = address === undefined ? await instructionPointer(engine, session_id) : parseAddress(address, "address");
          const instructions = await disassemble(engine, session_id, at, count ?? 12);
          return jsonResult({ session_id, engine: engine.id, action, live: true, address: at, instructions });
        }
        if (action === "assemble") {
          if (engine.id !== "x64dbg") {
            const detail =
              engine.id === "cdb"
                ? "cdb exposes assemble only as an interactive prompt, which this pipe cannot drive"
                : "frida has no assembler API";
            return unsupported("debug_code", session_id, engine.id, "assemble", detail);
          }
          const at = parseAddress(address ?? "0", "address");
          const text = parseInstruction(instruction ?? "");
          const raw = asRecord(
            await engine.bridgeCall(session_id, "code.assemble", { address: at, instruction: text }),
            "code.assemble",
          );
          return jsonResult({
            session_id,
            engine: engine.id,
            action,
            address: typeof raw.address === "string" ? raw.address : at,
            bytes: typeof raw.bytes === "string" ? raw.bytes : "",
            size: typeof raw.size === "number" ? raw.size : 0,
            bytes_written: typeof raw.bytesWritten === "number" ? raw.bytesWritten : 0,
          });
        }
        if (action === "run_to") {
          const at = parseAddress(address ?? "0", "address");
          const stop = await runTo(engine, session_id, at);
          session.events.push(stopEvent(stop.reason, stop.reached), {
            address: stop.address,
            reason: stop.reason,
            run_to: at,
          });
          return jsonResult({ session_id, engine: engine.id, action, run_to: at, ...stop });
        }
        const neverAction: never = action;
        throw new ToolInputError(String(neverAction));
      } catch (error) {
        return failure(error, "debug_code", session_id);
      }
    },
  );

  server.registerTool(
    "debug_thread",
    {
      description:
        "Live threads: list, select, freeze, thaw, or read one thread's context. The id is the value returned by list (cdb index, x64dbg/frida OS thread id). Requires confirm:true. Frida has no suspend or switch API.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        confirm: confirmSchema,
        action: z.enum(["list", "select", "freeze", "thaw", "context"]),
        thread_id: z.number().int().nonnegative().optional(),
      }),
    },
    async ({ session_id, confirm, action, thread_id }) => {
      try {
        if (action !== "list") {
          requireThreadId(thread_id);
        }
        const begun = begin("debug_thread", session_id, confirm, action, { thread_id: thread_id ?? null });
        if (!begun.ok) {
          return begun.result;
        }
        const { session, engine } = begun;
        if (action === "list") {
          const listed = await listThreads(engine, session_id);
          return jsonResult({ session_id, engine: engine.id, action, ...listed });
        }
        const tid = requireThreadId(thread_id);
        if (engine.id === "frida" && (action === "select" || action === "freeze" || action === "thaw")) {
          return unsupported(
            "debug_thread",
            session_id,
            "frida",
            action,
            "frida has no thread-suspend or thread-switch API (only Thread.sleep)",
          );
        }
        if (engine.id === "frida" && action === "context") {
          const raw = asRecord(await engine.callAgent(session_id, "threadContext", [tid]), "threadContext");
          return jsonResult({
            session_id,
            engine: engine.id,
            action,
            thread_id: tid,
            selected: false,
            general: raw.general ?? {},
          });
        }
        if (engine.id === "x64dbg") {
          if (action === "select" || action === "context") {
            const raw = asRecord(
              await engine.bridgeCall(session_id, "threads.switch", { threadId: tid }),
              "threads.switch",
            );
            const regs = await engine.registers(session_id);
            session.events.push("debug.thread", { action, thread_id: tid });
            return jsonResult({
              session_id,
              engine: engine.id,
              action,
              thread_id: tid,
              selected: true,
              address: typeof raw.address === "string" ? raw.address : null,
              general: action === "context" ? regs.general : undefined,
            });
          }
          if (action === "freeze" || action === "thaw") {
            await engine.bridgeCall(session_id, "threads.setFrozen", { threadId: tid, frozen: action === "freeze" });
            session.events.push("debug.thread", { action, thread_id: tid });
            const listed = await listThreads(engine, session_id);
            return jsonResult({ session_id, engine: engine.id, action, thread_id: tid, frozen: action === "freeze", ...listed });
          }
        }
        if (engine.id === "cdb") {
          if (action === "select") {
            await engine.debuggerCommand(session_id, `~${tid}s`);
            const body = await engine.debuggerCommand(session_id, "r");
            session.events.push("debug.thread", { action, thread_id: tid });
            return jsonResult({ session_id, engine: engine.id, action, thread_id: tid, selected: true, general: parseRegs(body) });
          }
          if (action === "context") {
            const body = await engine.debuggerCommand(session_id, `~${tid}r`);
            const general = parseRegs(body);
            if (Object.keys(general).length === 0) {
              throw new CdbError("engine_error", "cdb thread context was not recognized", { excerpt: body.slice(0, 400) });
            }
            return jsonResult({ session_id, engine: engine.id, action, thread_id: tid, selected: false, general });
          }
          if (action === "freeze" || action === "thaw") {
            await engine.debuggerCommand(session_id, action === "freeze" ? `~${tid}f` : `~${tid}u`);
            session.events.push("debug.thread", { action, thread_id: tid });
            const listed = await listThreads(engine, session_id);
            return jsonResult({ session_id, engine: engine.id, action, thread_id: tid, frozen: action === "freeze", ...listed });
          }
        }
        throw new ToolInputError(`unhandled thread action ${action} on ${engine.id}`);
      } catch (error) {
        return failure(error, "debug_thread", session_id);
      }
    },
  );

  server.registerTool(
    "debug_plugin",
    {
      description:
        "x64dbg Scylla and ScyllaHide. status reports files on disk. dump and hide do not open a window: a missing headless plugin returns engine_unavailable with the plugins path. Requires confirm:true. cdb and frida return capability_unsupported.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        confirm: confirmSchema,
        action: z.enum(["status", "dump", "hide"]),
      }),
    },
    async ({ session_id, confirm, action }) => {
      try {
        const begun = begin("debug_plugin", session_id, confirm, action, {});
        if (!begun.ok) {
          return begun.result;
        }
        const { engine } = begun;
        if (engine.id !== "x64dbg") {
          return unsupported(
            "debug_plugin",
            session_id,
            engine.id,
            action,
            "Scylla and ScyllaHide exist only on the x64dbg engine",
          );
        }
        const rows = await scyllaRows();
        if (action === "status") {
          return jsonResult({
            session_id,
            engine: engine.id,
            action,
            window_opened: false,
            installs: rows,
            limits:
              "Scylla.dll is the GUI component and is not launched. ScyllaHide applies when its .dp32/.dp64 is in plugins/ at debugger start.",
          });
        }
        if (action === "dump") {
          const plugins = rows.flatMap((row) => row.dump_plugins.map((name) => join(row.plugins_dir, name)));
          if (plugins.length === 0) {
            const gui = rows.filter((row) => row.gui_dll_present).map((row) => row.gui_dll);
            throw new X64dbgError(
              "engine_unavailable",
              `No headless Scylla plugin (.dp32/.dp64) is installed under ${rows.map((row) => row.plugins_dir).join(", ")}. ` +
                (gui.length > 0 ? `Scylla.dll is present (${gui.join(", ")}) and will not be launched.` : "Scylla.dll was not found either."),
              { plugins_dirs: rows.map((row) => row.plugins_dir), gui_dlls: gui },
            );
          }
          return jsonResult({
            session_id,
            engine: engine.id,
            action,
            window_opened: false,
            plugins,
            detail: "A headless Scylla plugin file is present. This bridge has no dump command for it and will not open the GUI.",
          });
        }
        if (action === "hide") {
          const plugins = rows.flatMap((row) => row.hide_plugins.map((name) => join(row.plugins_dir, name)));
          if (plugins.length === 0) {
            throw new X64dbgError(
              "engine_unavailable",
              `ScyllaHide plugin (.dp32/.dp64) is not in ${rows.map((row) => row.plugins_dir).join(", ")}. The bridge will not open a ScyllaHide window. ${suggestDownload("scyllahide")}`,
              { plugins_dirs: rows.map((row) => row.plugins_dir) },
            );
          }
          return jsonResult({
            session_id,
            engine: engine.id,
            action,
            window_opened: false,
            present: true,
            plugins,
            detail:
              "ScyllaHide is in the x64dbg autoload plugins directory. x64dbg loads it when the debugger starts. This call does not open a window and does not hot-load the plugin.",
          });
        }
        const neverAction: never = action;
        throw new ToolInputError(String(neverAction));
      } catch (error) {
        return failure(error, "debug_plugin", session_id);
      }
    },
  );

  server.registerTool(
    "debug_time",
    {
      description:
        "Checkpoint snapshot, the checkpoint timeline, and rewind of one checkpoint. A checkpoint is the active thread's registers, the thread list, and one memory window. Requires confirm:true.",
      inputSchema: z.object({
        session_id: sessionIdSchema,
        confirm: confirmSchema,
        action: z.enum(["snapshot", "timeline", "rewind"]),
        checkpoint_id: z.string().max(80).optional(),
        memory_size: z.number().int().min(1).max(4096).optional().describe("Bytes captured at the instruction pointer (default 64)."),
      }),
    },
    async ({ session_id, confirm, action, checkpoint_id, memory_size }) => {
      try {
        if (action === "rewind" && (checkpoint_id === undefined || !/^cp-[a-z0-9-]+$/i.test(checkpoint_id))) {
          throw new ToolInputError("checkpoint_id from debug_time snapshot is required for rewind");
        }
        const begun = begin("debug_time", session_id, confirm, action, {
          checkpoint_id: checkpoint_id ?? null,
          memory_size: memory_size ?? 64,
        });
        if (!begun.ok) {
          return begun.result;
        }
        const { session, engine } = begun;
        if (action === "timeline") {
          return jsonResult({
            session_id,
            engine: engine.id,
            action,
            limits: CHECKPOINT_LIMITS,
            checkpoints: listCheckpoints(session_id),
          });
        }
        if (action === "snapshot") {
          const checkpoint = await capture(engine, session_id, memory_size ?? 64);
          session.events.push("debug.checkpoint", { id: checkpoint.id, address: checkpoint.address });
          return jsonResult({ session_id, engine: engine.id, action, checkpoint });
        }
        if (action === "rewind") {
          const checkpoint = getCheckpoint(session_id, checkpoint_id ?? "");
          if (checkpoint === undefined) {
            throw new ToolInputError(`no checkpoint ${checkpoint_id ?? ""} in this session`);
          }
          if (checkpoint.threadId !== null && engine.id === "x64dbg") {
            await engine.bridgeCall(session_id, "threads.switch", { threadId: checkpoint.threadId });
          }
          if (checkpoint.threadId !== null && engine.id === "cdb") {
            await engine.debuggerCommand(session_id, `~${checkpoint.threadId}s`);
          }
          const bytesWritten = await writeMemory(engine, session_id, checkpoint.memoryAddress, checkpoint.memoryHex);
          let registersRestored = false;
          let registerDetail: string | null = null;
          if (engine.id === "frida") {
            if (checkpoint.threadId === null) {
              registerDetail = "checkpoint has no thread id";
            } else {
              try {
                await engine.callAgent(session_id, "applyRegisters", [checkpoint.threadId, checkpoint.registers]);
                registersRestored = true;
              } catch (error) {
                registerDetail = error instanceof Error ? error.message : String(error);
              }
            }
          } else {
            await restoreRegisters(engine, session_id, checkpoint.registers);
            registersRestored = true;
          }
          session.events.push("debug.rewound", { id: checkpoint.id, address: checkpoint.address });
          return jsonResult({
            session_id,
            engine: engine.id,
            action,
            checkpoint_id: checkpoint.id,
            memory_restored: true,
            bytes_written: bytesWritten,
            registers_restored: registersRestored,
            register_detail: registerDetail,
            address: checkpoint.address,
            limits: CHECKPOINT_LIMITS,
          });
        }
        const neverAction: never = action;
        throw new ToolInputError(String(neverAction));
      } catch (error) {
        return failure(error, "debug_time", session_id);
      }
    },
  );
}
