import { execFile, spawn, type ChildProcessByStdio } from "node:child_process";
import { stat } from "node:fs/promises";
import { delimiter as pathDelimiter, resolve as resolvePath } from "node:path";
import type { Readable, Writable } from "node:stream";

import { suggestDownload } from "../catalog.js";
import type { Capabilities, StaticEngine } from "./types.js";

/**
 * Headless static-analysis adapter. It speaks the r2pipe protocol
 * (`radare2 -q0 <target>`, one NUL byte terminates each command reply)
 * over a persistent child process per application session.
 *
 * No new dependency is introduced on purpose: the npm `r2pipe` package
 * does not force `TERM=dumb`, and without it radare2 6.x on Windows
 * blocks on a terminal cursor-position query instead of reading commands.
 */
export const radare2Capabilities: Capabilities = {
  kind: "static",
  disassembly: true,
  symbols: true,
  readMemory: true,
  writeMemory: false,
  breakpoints: false,
  registers: false,
  modules: false,
  threads: false,
};

export type R2ErrorCode =
  | "engine_unavailable"
  | "invalid_target"
  | "target_not_open"
  | "function_not_found"
  | "invalid_argument"
  | "engine_timeout"
  | "engine_error";

export class R2Error extends Error {
  readonly code: R2ErrorCode;
  readonly data?: Record<string, unknown>;

  constructor(code: R2ErrorCode, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "R2Error";
    this.code = code;
    this.data = data;
  }
}

export const DEFAULT_CMD_TIMEOUT_MS = 30_000;
export const DEFAULT_ANALYSIS_TIMEOUT_MS = 180_000;
export const MAX_DUMP_LENGTH = 65_536;
export const MAX_DISASM_COUNT = 1000;

function envTimeout(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

export function cmdTimeoutMs(): number {
  return envTimeout("DBG_BRIDGE_R2_CMD_TIMEOUT_MS", DEFAULT_CMD_TIMEOUT_MS);
}

export function analysisTimeoutMs(): number {
  return envTimeout("DBG_BRIDGE_R2_ANALYSIS_TIMEOUT_MS", DEFAULT_ANALYSIS_TIMEOUT_MS);
}

export interface R2Binary {
  /** Absolute path of the launcher. */
  path: string;
  /** True for .bat/.cmd launchers, which must run under cmd.exe. */
  viaCmd: boolean;
}

let binaryCache: R2Binary | null | undefined;

export function resetR2BinaryCache(): void {
  binaryCache = undefined;
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

/**
 * Resolve the radare2 launcher from PATH. Real executables win over
 * .bat/.cmd shims so the child can be spawned without a shell.
 * `DBG_BRIDGE_R2` overrides PATH lookup with an explicit path.
 */
export async function resolveR2Binary(): Promise<R2Binary> {
  if (binaryCache !== undefined) {
    if (binaryCache === null) {
      throw r2MissingError();
    }
    return binaryCache;
  }
  const override = process.env.DBG_BRIDGE_R2;
  if (override !== undefined && override !== "") {
    const resolved = resolvePath(override);
    if (await isFile(resolved)) {
      binaryCache = { path: resolved, viaCmd: /\.bat$/i.test(resolved) || /\.cmd$/i.test(resolved) };
      return binaryCache;
    }
    binaryCache = null;
    throw new R2Error("engine_unavailable", `DBG_BRIDGE_R2 points at a missing file: ${override}`);
  }
  const pathEnv = process.env.PATH ?? "";
  const dirs = pathEnv.split(pathDelimiter).filter((dir) => dir !== "");
  const isWindows = process.platform === "win32";
  const bases = ["radare2", "r2"];
  const exeNames: string[] = [];
  const scriptNames: string[] = [];
  for (const base of bases) {
    if (isWindows) {
      exeNames.push(`${base}.exe`);
      scriptNames.push(`${base}.bat`, `${base}.cmd`);
    } else {
      exeNames.push(base);
    }
  }
  for (const names of [exeNames, scriptNames]) {
    for (const dir of dirs) {
      for (const name of names) {
        const candidate = resolvePath(dir, name);
        if (await isFile(candidate)) {
          binaryCache = { path: candidate, viaCmd: names === scriptNames };
          return binaryCache;
        }
      }
    }
  }
  binaryCache = null;
  throw r2MissingError();
}

function r2MissingError(): R2Error {
  return new R2Error(
    "engine_unavailable",
    `radare2 not found on PATH (looked for \`radare2\` / \`r2\`). ${suggestDownload("radare2")}`,
  );
}

function quoteCmdArg(arg: string): string {
  if (!/[\s"]/.test(arg)) {
    return arg;
  }
  return `"${arg.replace(/"/g, '""')}"`;
}

interface PendingReply {
  resolve: (output: string) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

/** One persistent `r2 -q0` process. Commands are strictly serialized. */
class R2Pipe {
  private readonly pending: PendingReply[] = [];
  private rxBuf: Buffer = Buffer.alloc(0);
  private tail: Promise<void> = Promise.resolve();
  private dead = false;
  private stderrTail = "";
  private readonly exitPromise: Promise<void>;
  private exitCode: string;

  private constructor(
    private readonly child: ChildProcessByStdio<Writable, Readable, Readable>,
    readonly target: string,
  ) {
    this.exitCode = "running";
    this.exitPromise = new Promise<void>((resolve) => {
      child.on("exit", (code, signal) => {
        this.exitCode = code === null ? `signal ${signal ?? "unknown"}` : `code ${code}`;
        this.failAllPending(
          new R2Error("engine_error", `radare2 exited (${this.exitCode}): ${this.stderrTail}`, {
            target: this.target,
          }),
        );
        resolve();
      });
      child.on("error", (error: Error) => {
        this.failAllPending(
          new R2Error("engine_error", `radare2 process error: ${error.message}`, { target: this.target }),
        );
        resolve();
      });
    });
    child.stdout.on("data", (chunk: Buffer) => {
      this.rxBuf = Buffer.concat([this.rxBuf, chunk]);
      let nul: number;
      while ((nul = this.rxBuf.indexOf(0)) !== -1) {
        const output = this.rxBuf.subarray(0, nul).toString("utf8");
        this.rxBuf = this.rxBuf.subarray(nul + 1);
        const next = this.pending.shift();
        if (next !== undefined) {
          clearTimeout(next.timer);
          next.resolve(output);
        }
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      this.stderrTail = `${this.stderrTail}${chunk.toString("utf8")}`.slice(-2048);
    });
  }

  static async spawn(binary: R2Binary, target: string, timeoutMs: number): Promise<R2Pipe> {
    const r2Args = ["-q0", "-e", "scr.color=false", target];
    const child =
      binary.viaCmd
        ? spawn("cmd.exe", ["/d", "/s", "/c", [binary.path, ...r2Args].map(quoteCmdArg).join(" ")], {
            stdio: ["pipe", "pipe", "pipe"],
            env: { ...process.env, TERM: "dumb" },
            windowsHide: true,
          })
        : spawn(binary.path, r2Args, {
            stdio: ["pipe", "pipe", "pipe"],
            env: { ...process.env, TERM: "dumb" },
            windowsHide: true,
          });
    const pipe = new R2Pipe(child as ChildProcessByStdio<Writable, Readable, Readable>, target);
    try {
      await pipe.sync(timeoutMs);
    } catch (error) {
      await pipe.close();
      throw error;
    }
    return pipe;
  }

  /**
   * Self-synchronize with the reply stream. Some builds emit a startup
   * NUL before the first command; a unique probe output distinguishes
   * that marker from the real reply either way.
   */
  private sync(timeoutMs: number): Promise<void> {
    const magic = `0x52b2${(process.pid % 0xffff).toString(16).padStart(4, "0")}`;
    const run = this.tail.then(async () => {
      this.writeLine(`?v ${magic}`);
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const chunk = await this.readChunk(timeoutMs);
        if (chunk.replace(/\s/g, "") === magic) {
          return;
        }
      }
      throw new R2Error("engine_error", "radare2 pipe failed to synchronize (no reply marker)", {
        target: this.target,
      });
    });
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  cmd(command: string, timeoutMs: number): Promise<string> {
    const run = this.tail.then(() => this.execCommand(command, timeoutMs));
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private execCommand(command: string, timeoutMs: number): Promise<string> {
    if (this.dead) {
      return Promise.reject(new R2Error("engine_error", "radare2 pipe is closed", { target: this.target }));
    }
    this.writeLine(command);
    return this.readChunk(timeoutMs).catch((error: unknown) => {
      // A reply that never arrives leaves the stream position unknown;
      // the pipe cannot be trusted afterwards, so retire it.
      void this.kill();
      if (error instanceof R2Error) {
        throw error;
      }
      throw new R2Error("engine_error", `radare2 command failed: ${String(error)}`, { target: this.target });
    });
  }

  private writeLine(command: string): void {
    try {
      this.child.stdin.write(`${command}\n`);
    } catch {
      this.failAllPending(new R2Error("engine_error", "radare2 stdin is broken", { target: this.target }));
    }
  }

  private readChunk(timeoutMs: number): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.pending.findIndex((entry) => entry.timer === timer);
        if (index !== -1) {
          this.pending.splice(index, 1);
        }
        reject(
          new R2Error("engine_timeout", `radare2 command timed out after ${timeoutMs}ms`, {
            target: this.target,
          }),
        );
      }, timeoutMs);
      this.pending.push({ resolve, reject, timer });
    });
  }

  private failAllPending(error: R2Error): void {
    this.dead = true;
    while (this.pending.length > 0) {
      const next = this.pending.shift();
      if (next !== undefined) {
        clearTimeout(next.timer);
        next.reject(error);
      }
    }
  }

  private kill(): Promise<void> {
    this.dead = true;
    try {
      this.child.kill();
    } catch {
      // Already gone.
    }
    return this.exitPromise;
  }

  async close(): Promise<void> {
    if (this.dead) {
      return;
    }
    this.dead = true;
    try {
      this.child.stdin.write("q!\n");
    } catch {
      // Fall through to kill.
    }
    const graceful = new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 3000);
      void this.exitPromise.then(() => {
        clearTimeout(timer);
        resolve();
      });
    });
    await graceful;
    try {
      this.child.kill();
    } catch {
      // Already gone.
    }
    await this.exitPromise;
  }
}

export type AddressInput = string | number;

const HEX_RE = /^0[xX][0-9a-fA-F]+$/;
const DEC_RE = /^[0-9]+$/;
const FLAG_RE = /^[A-Za-z_.][A-Za-z0-9_.:$@-]*$/;

/**
 * Validate anything interpolated into an r2 command line. r2 splits
 * commands on `;`, so anything outside hex/decimal/flag shapes is rejected.
 */
export function normalizeLocation(value: AddressInput, name: string): string {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
      throw new R2Error("invalid_argument", `"${name}" must be a non-negative integer`);
    }
    return `0x${value.toString(16)}`;
  }
  const trimmed = value.trim();
  if (trimmed === "" || trimmed.length > 128) {
    throw new R2Error("invalid_argument", `"${name}" must be a non-empty address or flag (max 128 chars)`);
  }
  if (HEX_RE.test(trimmed) || DEC_RE.test(trimmed) || FLAG_RE.test(trimmed)) {
    return trimmed;
  }
  throw new R2Error(
    "invalid_argument",
    `"${name}" must be hex (0x...), decimal, or a flag name; got ${JSON.stringify(trimmed)}`,
  );
}

function toHex(value: unknown): string {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return `0x${value.toString(16)}`;
  }
  if (typeof value === "string") {
    return value;
  }
  return String(value);
}

function unixNewlines(text: string): string {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

function parseJsonValue(raw: string, command: string): unknown {
  const trimmed = raw.trim();
  if (trimmed === "") {
    throw new R2Error("engine_error", `radare2 returned no output for: ${command}`);
  }
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    throw new R2Error("engine_error", `radare2 returned non-JSON output for: ${command}`, {
      excerpt: trimmed.slice(0, 300),
    });
  }
}

function parseJsonArray(raw: string, command: string): unknown[] {
  const parsed = parseJsonValue(raw, command);
  if (!Array.isArray(parsed)) {
    throw new R2Error("engine_error", `radare2 returned unexpected JSON for: ${command}`, {
      excerpt: raw.trim().slice(0, 300),
    });
  }
  return parsed;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value === "object" && value !== null) {
    return value as Record<string, unknown>;
  }
  return {};
}

export interface DisasmOp {
  address: string;
  size: number;
  bytes: string;
  opcode: string;
  type: string;
  jump?: string;
  fail?: string;
}

export interface DisassemblyResult {
  location: string;
  count: number;
  ops: DisasmOp[];
  text: string;
}

export interface CfgFunction {
  name: string;
  address: string;
  size: number;
  blocks: number;
}

export interface CfgResult {
  location: string;
  function: CfgFunction | null;
  json?: unknown[];
  dot?: string;
}

export interface XrefEntry {
  from: string;
  to?: string;
  type: string;
  opcode?: string;
  function?: string;
}

export interface XrefsResult {
  address: string;
  to: XrefEntry[];
  from: XrefEntry[];
}

export interface R2String {
  vaddr: string;
  paddr: string;
  section: string;
  type: string;
  length: number;
  string: string;
}

export interface StringsResult {
  total: number;
  offset: number;
  strings: R2String[];
}

export interface DumpResult {
  address: string;
  length: number;
  format: "hex" | "json";
  text?: string;
  bytes?: number[];
}

export interface TargetBinaryInfo {
  arch?: string;
  bits?: number;
  os?: string;
  bintype?: string;
  format?: string;
}

export interface TargetInfo {
  path: string;
  openedAt: string;
  binary: TargetBinaryInfo;
}

interface OpenTarget {
  pipe: R2Pipe;
  path: string;
  openedAt: string;
}

function mapDisasmOp(raw: unknown): DisasmOp {
  const rec = asRecord(raw);
  const addr = rec.addr ?? rec.offset;
  const opcode = rec.opcode ?? rec.disasm ?? rec.opstr ?? "";
  const op: DisasmOp = {
    address: toHex(addr),
    size: typeof rec.size === "number" ? rec.size : 0,
    bytes: typeof rec.bytes === "string" ? rec.bytes : "",
    opcode: typeof opcode === "string" ? opcode : String(opcode),
    type: typeof rec.type === "string" ? rec.type : "",
  };
  if (rec.jump !== undefined) {
    op.jump = toHex(rec.jump);
  }
  if (rec.fail !== undefined) {
    op.fail = toHex(rec.fail);
  }
  return op;
}

function mapXref(raw: unknown, direction: "to" | "from"): XrefEntry {
  const rec = asRecord(raw);
  const entry: XrefEntry = {
    from: toHex(rec.from),
    type: typeof rec.type === "string" ? rec.type : "",
  };
  if (rec.to !== undefined) {
    entry.to = toHex(rec.to);
  }
  if (typeof rec.opcode === "string") {
    entry.opcode = rec.opcode;
  }
  const fcn = rec.fcn_name ?? rec.fcn_addr;
  if (typeof fcn === "string") {
    entry.function = fcn;
  } else if (typeof fcn === "number") {
    entry.function = toHex(fcn);
  }
  if (direction === "to" && entry.to === undefined && typeof rec.refname === "string") {
    entry.to = rec.refname;
  }
  return entry;
}

/** Headless static engine. One persistent `r2 -q0` process per session. */
export class Radare2Engine implements StaticEngine {
  readonly id = "radare2" as const;
  readonly capabilities = radare2Capabilities;
  private readonly targets = new Map<string, OpenTarget>();

  async open(sessionId: string, targetPath: string): Promise<void> {
    if (sessionId.trim() === "") {
      throw new R2Error("invalid_argument", "session id must not be empty");
    }
    const trimmed = targetPath.trim();
    if (trimmed === "" || trimmed.startsWith("-")) {
      throw new R2Error("invalid_target", `refusing to open target: ${JSON.stringify(targetPath)}`);
    }
    const absolute = resolvePath(trimmed);
    let info;
    try {
      info = await stat(absolute);
    } catch {
      throw new R2Error("invalid_target", `target not found: ${trimmed}`);
    }
    if (!info.isFile()) {
      throw new R2Error("invalid_target", `target is not a file: ${trimmed}`);
    }
    await this.close(sessionId);
    const binary = await resolveR2Binary();
    const pipe = await R2Pipe.spawn(binary, absolute, cmdTimeoutMs());
    const openedAt = new Date().toISOString();
    this.targets.set(sessionId, { pipe, path: absolute, openedAt });
    try {
      await pipe.cmd("aa", analysisTimeoutMs());
    } catch (error) {
      await this.close(sessionId);
      throw error;
    }
  }

  async close(sessionId: string): Promise<void> {
    const open = this.targets.get(sessionId);
    if (open === undefined) {
      return;
    }
    this.targets.delete(sessionId);
    await open.pipe.close();
  }

  isOpen(sessionId: string): boolean {
    return this.targets.has(sessionId);
  }

  openPath(sessionId: string): string | undefined {
    return this.targets.get(sessionId)?.path;
  }

  private requirePipe(sessionId: string): R2Pipe {
    const open = this.targets.get(sessionId);
    if (open === undefined) {
      throw new R2Error(
        "target_not_open",
        `no target open for session ${sessionId}; call open_target first`,
        { session_id: sessionId },
      );
    }
    return open.pipe;
  }

  async disassemble(
    sessionId: string,
    opts: { address?: AddressInput; function?: string; count?: number } = {},
  ): Promise<DisassemblyResult> {
    const pipe = this.requirePipe(sessionId);
    const count = opts.count ?? 32;
    if (!Number.isInteger(count) || count < 1 || count > MAX_DISASM_COUNT) {
      throw new R2Error("invalid_argument", `"count" must be an integer 1..${MAX_DISASM_COUNT}`);
    }
    if (opts.address !== undefined) {
      const location = normalizeLocation(opts.address, "address");
      const raw = await pipe.cmd(`pdj ${count} @ ${location}`, cmdTimeoutMs());
      const ops = parseJsonArray(raw, "pdj").map(mapDisasmOp);
      return { location, count: ops.length, ops, text: renderDisasmText(ops) };
    }
    const location = opts.function !== undefined ? normalizeLocation(opts.function, "function") : "entry0";
    const raw = await pipe.cmd(`pdfj @ ${location}`, cmdTimeoutMs());
    if (raw.trim() === "") {
      throw new R2Error("function_not_found", `no function at ${JSON.stringify(location)}`, { location });
    }
    const parsed = parseJsonValue(raw, "pdfj");
    const opList = Array.isArray(parsed) ? parsed : asRecord(parsed).ops;
    if (!Array.isArray(opList)) {
      throw new R2Error("function_not_found", `no function at ${JSON.stringify(location)}`, { location });
    }
    const ops = opList.map(mapDisasmOp);
    return { location, count: ops.length, ops, text: renderDisasmText(ops) };
  }

  async getCfg(
    sessionId: string,
    opts: { address?: AddressInput; function?: string; format?: "json" | "dot" | "both" } = {},
  ): Promise<CfgResult> {
    const pipe = this.requirePipe(sessionId);
    const format = opts.format ?? "both";
    const location =
      opts.address !== undefined
        ? normalizeLocation(opts.address, "address")
        : opts.function !== undefined
          ? normalizeLocation(opts.function, "function")
          : "entry0";
    let info = await this.functionInfo(pipe, location);
    if (info === null) {
      await pipe.cmd(`af @ ${location}`, cmdTimeoutMs());
      info = await this.functionInfo(pipe, location);
    }
    if (info === null) {
      throw new R2Error("function_not_found", `no function at ${JSON.stringify(location)}`, { location });
    }
    const result: CfgResult = { location, function: info };
    if (format === "json" || format === "both") {
      const raw = await pipe.cmd(`agfj @ ${location}`, cmdTimeoutMs());
      result.json = raw.trim() === "" ? [] : parseJsonArray(raw, "agfj");
    }
    if (format === "dot" || format === "both") {
      const raw = await pipe.cmd(`agfd @ ${location}`, cmdTimeoutMs());
      const dot = unixNewlines(raw).trim();
      if (!dot.startsWith("digraph")) {
        throw new R2Error("engine_error", `radare2 returned no CFG graph for ${JSON.stringify(location)}`, {
          location,
          excerpt: dot.slice(0, 300),
        });
      }
      result.dot = dot;
    }
    return result;
  }

  private async functionInfo(pipe: R2Pipe, location: string): Promise<CfgFunction | null> {
    const raw = await pipe.cmd(`afij @ ${location}`, cmdTimeoutMs());
    if (raw.trim() === "" || raw.trim() === "[]") {
      return null;
    }
    const parsed = parseJsonArray(raw, "afij");
    const rec = asRecord(parsed[0]);
    if (rec.addr === undefined) {
      return null;
    }
    return {
      name: typeof rec.name === "string" ? rec.name : location,
      address: toHex(rec.addr),
      size: typeof rec.size === "number" ? rec.size : 0,
      blocks: typeof rec.nbbs === "number" ? rec.nbbs : 0,
    };
  }

  async xrefs(
    sessionId: string,
    opts: { address: AddressInput; direction?: "to" | "from" | "both" },
  ): Promise<XrefsResult> {
    const pipe = this.requirePipe(sessionId);
    const address = normalizeLocation(opts.address, "address");
    const direction = opts.direction ?? "both";
    const result: XrefsResult = { address, to: [], from: [] };
    if (direction === "to" || direction === "both") {
      const raw = await pipe.cmd(`axtj @ ${address}`, cmdTimeoutMs());
      const list = raw.trim() === "" ? [] : parseJsonArray(raw, "axtj");
      result.to = list.map((entry) => mapXref(entry, "to"));
    }
    if (direction === "from" || direction === "both") {
      const raw = await pipe.cmd(`axfj @ ${address}`, cmdTimeoutMs());
      const list = raw.trim() === "" ? [] : parseJsonArray(raw, "axfj");
      result.from = list.map((entry) => mapXref(entry, "from"));
    }
    return result;
  }

  async strings(
    sessionId: string,
    opts: { minLength?: number; limit?: number; offset?: number; section?: string } = {},
  ): Promise<StringsResult> {
    const pipe = this.requirePipe(sessionId);
    const minLength = opts.minLength ?? 0;
    const limit = opts.limit ?? 200;
    const offset = opts.offset ?? 0;
    if (!Number.isInteger(minLength) || minLength < 0) {
      throw new R2Error("invalid_argument", `"min_length" must be a non-negative integer`);
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 5000) {
      throw new R2Error("invalid_argument", `"limit" must be an integer 1..5000`);
    }
    if (!Number.isInteger(offset) || offset < 0) {
      throw new R2Error("invalid_argument", `"offset" must be a non-negative integer`);
    }
    const raw = await pipe.cmd("izj", cmdTimeoutMs());
    const list = raw.trim() === "" ? [] : parseJsonArray(raw, "izj");
    const all: R2String[] = [];
    for (const item of list) {
      const rec = asRecord(item);
      const length = typeof rec.length === "number" ? rec.length : 0;
      const section = typeof rec.section === "string" ? rec.section : "";
      if (length < minLength) {
        continue;
      }
      if (opts.section !== undefined && section !== opts.section) {
        continue;
      }
      all.push({
        vaddr: toHex(rec.vaddr),
        paddr: toHex(rec.paddr),
        section,
        type: typeof rec.type === "string" ? rec.type : "",
        length,
        string: typeof rec.string === "string" ? rec.string : "",
      });
    }
    return { total: all.length, offset, strings: all.slice(offset, offset + limit) };
  }

  async dump(
    sessionId: string,
    opts: { address: AddressInput; length?: number; format?: "hex" | "json" },
  ): Promise<DumpResult> {
    const pipe = this.requirePipe(sessionId);
    const address = normalizeLocation(opts.address, "address");
    const length = opts.length ?? 128;
    if (!Number.isInteger(length) || length < 1 || length > MAX_DUMP_LENGTH) {
      throw new R2Error("invalid_argument", `"length" must be an integer 1..${MAX_DUMP_LENGTH}`);
    }
    const format = opts.format ?? "hex";
    if (format === "json") {
      const raw = await pipe.cmd(`pxj ${length} @ ${address}`, cmdTimeoutMs());
      const parsed = parseJsonArray(raw, "pxj");
      const bytes: number[] = [];
      for (const item of parsed) {
        if (typeof item === "number") {
          bytes.push(item);
        }
      }
      return { address, length: bytes.length, format, bytes };
    }
    const raw = await pipe.cmd(`px ${length} @ ${address}`, cmdTimeoutMs());
    return { address, length, format, text: unixNewlines(raw).trimEnd() };
  }

  async targetInfo(sessionId: string): Promise<TargetInfo> {
    const open = this.targets.get(sessionId);
    if (open === undefined) {
      throw new R2Error("target_not_open", `no target open for session ${sessionId}`, {
        session_id: sessionId,
      });
    }
    const binary: TargetBinaryInfo = {};
    try {
      const raw = await open.pipe.cmd("ij", cmdTimeoutMs());
      const parsed = asRecord(JSON.parse(raw.trim() === "" ? "{}" : raw) as unknown);
      const bin = asRecord(parsed.bin);
      const core = asRecord(parsed.core);
      if (typeof bin.arch === "string") {
        binary.arch = bin.arch;
      }
      if (typeof bin.bits === "number") {
        binary.bits = bin.bits;
      }
      if (typeof bin.os === "string") {
        binary.os = bin.os;
      }
      if (typeof bin.bintype === "string") {
        binary.bintype = bin.bintype;
      }
      if (typeof core.format === "string") {
        binary.format = core.format;
      }
    } catch {
      // Binary info is best-effort; path/openedAt still answer the question.
    }
    return { path: open.path, openedAt: open.openedAt, binary };
  }
}

function renderDisasmText(ops: DisasmOp[]): string {
  return ops.map((op) => `${op.address}  ${op.opcode}`).join("\n");
}

/** Process-wide engine shared by stdio and every stateless HTTP request. */
export const radare2Engine = new Radare2Engine();

/** One-shot `r2 -v` for health checks; never touches a session pipe. */
export async function r2Version(): Promise<{ binary: string; version: string }> {
  const binary = await resolveR2Binary();
  const args = binary.viaCmd ? ["/d", "/s", "/c", `${quoteCmdArg(binary.path)} -v`] : ["-v"];
  const file = binary.viaCmd ? "cmd.exe" : binary.path;
  const stdout: string = await new Promise((resolve, reject) => {
    execFile(file, args, { timeout: 15_000, windowsHide: true }, (error, out) => {
      if (error !== null) {
        reject(new R2Error("engine_error", `failed to query radare2 version: ${error.message}`));
        return;
      }
      resolve(out);
    });
  });
  const firstLine = unixNewlines(stdout).split("\n")[0]?.trim() ?? "";
  return { binary: binary.path, version: firstLine };
}
