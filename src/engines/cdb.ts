import { spawn, spawnSync, type ChildProcessByStdio } from "node:child_process";
import { open as fsOpen, stat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, join, resolve as resolvePath } from "node:path";
import type { Readable, Writable } from "node:stream";

import { suggestDownload } from "../catalog.js";
import type { Capabilities, DebugEngine } from "./types.js";
import type {
  AttachOptions,
  BreakpointType,
  BridgePushHandler,
  CallFrame,
  CallStack,
  ContinueResult,
  DebugState,
  DebugTargetInfo,
  OpenDebugOptions,
  RegisterSet,
  SetBreakpointOptions,
  StepResult,
  X64Arch,
} from "./x64dbg.js";

/**
 * Windowless cdb adapter. One hidden `cdb.exe` per application session,
 * talking a marker-framed stdin/stdout protocol.
 *
 * Debugging Tools for Windows (SDK feature OptionId.WindowsDesktopDebuggers,
 * kit 10.0.26100) install to:
 *   C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe
 *   C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe
 * `CDB_DIR` overrides that Debuggers root. Resolution then checks the
 * Windows Kits defaults and `cdb.exe` on PATH.
 *
 * Command-line switches were checked against this install's `cdb -?`
 * (version 10.0.26100.1). `-netsym:yes|no` is printed in that help but
 * the binary rejects it (`Invalid switch 'n'`), so symbol traffic is
 * stopped with `-sins` plus a local `-y` directory instead.
 * Session commands were checked on cdb 10.0.26100.1 against both arches:
 * `.echo`, `|`, `lm`, `? $exentry`, `bp`, `bl`, `bc`, `ba`, `g`, `t`, `p`,
 * `r`, `k`, `q`, `qd`. `.help ba` only points at the chm; `ba e|r|w 1 <addr>`
 * is the syntax this build accepts. A running target does not see Ctrl-F on
 * a pipe, so pause injects `DebugBreakProcess` instead.
 *
 * Open stays at the loader breakpoint and plants `bp $exentry`, so the first
 * `g` stops on the PE entry the way the x64dbg flow does. `entryPoint` is
 * that PE entry. Memory breakpoints and hardware-access have no cdb command
 * and answer `capability_unsupported`.
 */
export const cdbCapabilities: Capabilities = {
  kind: "debug",
  disassembly: true,
  symbols: false,
  readMemory: true,
  writeMemory: true,
  breakpoints: true,
  registers: true,
  modules: false,
  threads: true,
};

export type CdbErrorCode =
  | "engine_unavailable"
  | "invalid_target"
  | "target_not_open"
  | "invalid_argument"
  | "engine_timeout"
  | "engine_error"
  | "capability_unsupported";

export class CdbError extends Error {
  readonly code: CdbErrorCode;
  readonly data?: Record<string, unknown>;

  constructor(code: CdbErrorCode, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "CdbError";
    this.code = code;
    this.data = data;
  }
}

const DEFAULT_CMD_TIMEOUT_MS = 30_000;
const DEFAULT_START_TIMEOUT_MS = 60_000;
const DEFAULT_CONTINUE_TIMEOUT_MS = 60_000;
const SYNC_ATTEMPTS = 3;
const QUIT_GRACE_MS = 3_000;
const MAX_BUFFER_CHARS = 2_000_000;

const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_FILE_MACHINE_ARMNT = 0x01c4;
const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;

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

export function cdbCmdTimeoutMs(): number {
  return envTimeout("DBG_BRIDGE_CDB_CMD_TIMEOUT_MS", DEFAULT_CMD_TIMEOUT_MS);
}

export function cdbStartTimeoutMs(): number {
  return envTimeout("DBG_BRIDGE_CDB_START_TIMEOUT_MS", DEFAULT_START_TIMEOUT_MS);
}

export function cdbContinueTimeoutMs(): number {
  return envTimeout("DBG_BRIDGE_CDB_CONTINUE_TIMEOUT_MS", DEFAULT_CONTINUE_TIMEOUT_MS);
}

let exeCache: Partial<Record<X64Arch, string>> = {};

export function resetCdbResolutionCache(): void {
  exeCache = {};
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

/** Candidate `cdb.exe` paths for one architecture, given a root or an arch folder. */
export function cdbExeCandidates(dir: string, arch: X64Arch): string[] {
  const folder = arch === "x64" ? "x64" : "x86";
  const resolved = resolvePath(dir);
  return [
    join(resolved, folder, "cdb.exe"),
    join(resolved, "cdb.exe"),
    join(dirname(resolved), folder, "cdb.exe"),
  ];
}

/** Debuggers roots to probe, in priority order. `CDB_DIR` wins. */
export function cdbDirCandidates(): string[] {
  const out: string[] = [];
  const override = process.env.CDB_DIR;
  if (override !== undefined && override !== "") {
    out.push(resolvePath(override));
  }
  if (process.platform === "win32") {
    const programFilesX86 = process.env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)";
    const programFiles = process.env.ProgramFiles ?? "C:\\Program Files";
    out.push(join(programFilesX86, "Windows Kits", "10", "Debuggers"));
    out.push(join(programFiles, "Windows Kits", "10", "Debuggers"));
    try {
      out.push(join(homedir(), "Tools", "cdb"));
    } catch {
      // Homedir unavailable; skip.
    }
  }
  return out;
}

function pathDirectories(): string[] {
  const raw = process.env.PATH ?? "";
  const out: string[] = [];
  for (const part of raw.split(";")) {
    const trimmed = part.trim().replace(/^"(.*)"$/, "$1");
    if (trimmed !== "") {
      out.push(trimmed);
    }
  }
  return out;
}

async function firstExisting(candidates: readonly string[]): Promise<string | undefined> {
  const seen = new Set<string>();
  for (const candidate of candidates) {
    const key = candidate.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    if (await isFile(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

function missingCdbError(arch: X64Arch, checked: readonly string[]): CdbError {
  const listed = checked.length > 0 ? checked.join(", ") : "(no candidates on this platform)";
  return new CdbError(
    "engine_unavailable",
    `cdb.exe for ${arch} not found. Set CDB_DIR to the Debugging Tools "Debuggers" directory ` +
      `(the parent of x64\\ and x86\\). Checked: ${listed}. ${suggestDownload("cdb")}`,
    { arch, checked: [...checked] },
  );
}

/**
 * Resolve `cdb.exe` for a target architecture.
 * `CDB_DIR`, then the Windows Kits defaults, then `cdb.exe` on PATH
 * (a hit in one arch folder also checks the sibling arch folder).
 */
export async function resolveCdbExe(arch: X64Arch): Promise<string> {
  const cached = exeCache[arch];
  if (cached !== undefined) {
    return cached;
  }
  const checked: string[] = [];
  for (const dir of cdbDirCandidates()) {
    const candidates = cdbExeCandidates(dir, arch);
    checked.push(...candidates);
    const found = await firstExisting(candidates);
    if (found !== undefined) {
      exeCache[arch] = found;
      return found;
    }
  }
  for (const dir of pathDirectories()) {
    const onPath = join(dir, "cdb.exe");
    if (!(await isFile(onPath))) {
      continue;
    }
    const candidates = cdbExeCandidates(dir, arch);
    checked.push(...candidates);
    const found = await firstExisting(candidates);
    if (found !== undefined) {
      exeCache[arch] = found;
      return found;
    }
  }
  throw missingCdbError(arch, checked);
}

async function readPeMachine(pePath: string): Promise<number> {
  let handle;
  try {
    handle = await fsOpen(pePath, "r");
  } catch {
    throw new CdbError("invalid_target", `target not found: ${pePath}`);
  }
  try {
    const dos = Buffer.alloc(64);
    if ((await handle.read(dos, 0, 64, 0)).bytesRead < 64 || dos.readUInt16LE(0) !== 0x5a4d) {
      throw new CdbError("invalid_target", `not a valid PE file (bad MZ signature): ${pePath}`);
    }
    const peOffset = dos.readUInt32LE(0x3c);
    if (peOffset > 1024 * 1024) {
      throw new CdbError("invalid_target", `not a valid PE file (e_lfanew out of range): ${pePath}`);
    }
    const head = Buffer.alloc(6);
    if ((await handle.read(head, 0, 6, peOffset)).bytesRead < 6) {
      throw new CdbError("invalid_target", `not a valid PE file (truncated headers): ${pePath}`);
    }
    if (head.readUInt32LE(0) !== 0x00004550) {
      throw new CdbError("invalid_target", `not a valid PE file (bad PE signature): ${pePath}`);
    }
    return head.readUInt16LE(4);
  } finally {
    await handle.close();
  }
}

/** i386 → x86 cdb, AMD64 → x64 cdb. Anything else is rejected. */
export async function detectPeArch(targetPath: string): Promise<X64Arch> {
  const trimmed = targetPath.trim();
  if (trimmed === "" || trimmed.startsWith("-")) {
    throw new CdbError("invalid_target", `refusing to open target: ${JSON.stringify(targetPath)}`);
  }
  const absolute = resolvePath(trimmed);
  try {
    if (!(await stat(absolute)).isFile()) {
      throw new CdbError("invalid_target", `target is not a file: ${trimmed}`);
    }
  } catch (error) {
    if (error instanceof CdbError) {
      throw error;
    }
    throw new CdbError("invalid_target", `target not found: ${trimmed}`);
  }
  const machine = await readPeMachine(absolute);
  if (machine === IMAGE_FILE_MACHINE_I386) {
    return "x86";
  }
  if (machine === IMAGE_FILE_MACHINE_AMD64) {
    return "x64";
  }
  if (machine === IMAGE_FILE_MACHINE_ARM64 || machine === IMAGE_FILE_MACHINE_ARMNT) {
    throw new CdbError(
      "invalid_target",
      `ARM PE detected (machine 0x${machine.toString(16)}): cdb launch supports x86 and x64 targets`,
      { machine: `0x${machine.toString(16)}` },
    );
  }
  throw new CdbError("invalid_target", `unsupported PE machine type 0x${machine.toString(16)}: ${trimmed}`, {
    machine: `0x${machine.toString(16)}`,
  });
}

function normalizeDbgAddress(raw: string): string {
  const hex = raw.replace(/`/g, "").replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new CdbError("engine_error", `cdb returned an unparseable address: ${JSON.stringify(raw)}`);
  }
  return `0x${BigInt(`0x${hex}`).toString(16)}`;
}

/** `|` prints the process id in hex (`id: 5250`). */
export function parseCdbPid(text: string): number {
  const match = /id:\s*([0-9a-fA-F]+)/.exec(text);
  const digits = match?.[1];
  if (digits === undefined) {
    throw new CdbError("engine_error", "cdb process list did not include an id", {
      excerpt: text.trim().slice(0, 400),
    });
  }
  const pid = Number.parseInt(digits, 16);
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new CdbError("engine_error", `cdb process id is not usable: ${digits}`);
  }
  return pid;
}

/** First address column of the `lm` row whose module name matches the exe stem. */
export function parseModuleBase(text: string, targetPath: string): string {
  const stem = basename(targetPath).replace(/\.exe$/i, "").toLowerCase();
  for (const line of text.split("\n")) {
    const match = /^\s*([0-9a-fA-F`]{8,17})\s+[0-9a-fA-F`]{8,17}\s+(\S+)/.exec(line);
    if (match?.[1] !== undefined && match[2]?.toLowerCase() === stem) {
      return normalizeDbgAddress(match[1]);
    }
  }
  throw new CdbError("engine_error", `cdb module list has no row for ${stem}`, {
    excerpt: text.trim().slice(0, 400),
  });
}

/** `? $exentry` prints `Evaluate expression: <dec> = <hex>`. */
export function parseExentry(text: string): string {
  const match = /=\s*([0-9a-fA-F`]{4,})/.exec(text);
  const raw = match?.[1];
  if (raw === undefined) {
    throw new CdbError("engine_error", "cdb did not report $exentry", {
      excerpt: text.trim().slice(0, 400),
    });
  }
  return normalizeDbgAddress(raw);
}

interface PendingCommand {
  nonce: string;
  resolve: (body: string) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

type CdbChild = ChildProcessByStdio<Writable, Readable, Readable>;

/**
 * One cdb process. Commands are serialized. Each command is wrapped as
 * `.echo BEGIN_<nonce>` / command / `.echo END_<nonce>` so startup banners
 * and the `0:000>` prompt cannot be mistaken for the reply.
 */
class CdbPipe {
  private buf = "";
  private pending: PendingCommand | null = null;
  private dead = false;
  private stderrTail = "";
  private exitLabel: string | null = null;
  private nonceSeq = 0;
  private tail: Promise<void> = Promise.resolve();
  private promptWaiter: { resolve: () => void; reject: (error: Error) => void; timer: NodeJS.Timeout } | null =
    null;
  private readonly exitPromise: Promise<void>;

  private constructor(
    private readonly child: CdbChild,
    private readonly target: string,
  ) {
    this.exitPromise = new Promise<void>((resolve) => {
      child.on("exit", (code, signal) => {
        this.exitLabel = code === null ? `signal ${signal ?? "unknown"}` : `code ${code}`;
        this.failLive(
          new CdbError("engine_error", `cdb exited (${this.exitLabel}): ${this.stderrTail}`, { target: this.target }),
        );
        resolve();
      });
      child.on("error", (error: Error) => {
        this.failLive(new CdbError("engine_error", `cdb process error: ${error.message}`, { target: this.target }));
        resolve();
      });
    });
    child.stdout.on("data", (chunk: Buffer) => {
      this.buf += chunk.toString("latin1").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      if (this.buf.length > MAX_BUFFER_CHARS) {
        this.buf = this.buf.slice(-MAX_BUFFER_CHARS);
      }
      this.pump();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      this.stderrTail = `${this.stderrTail}${chunk.toString("latin1")}`.slice(-2048);
    });
  }

  static launch(cdbExe: string, target: string): CdbPipe {
    return CdbPipe.start(cdbExe, [target], target);
  }

  static attachTo(cdbExe: string, pid: number): CdbPipe {
    return CdbPipe.start(cdbExe, ["-p", String(pid)], `<attached-pid-${pid}>`);
  }

  private static start(cdbExe: string, extra: string[], target: string): CdbPipe {
    const child = spawn(cdbExe, ["-sins", "-nosqm", "-noshell", "-snul", "-hd", "-y", tmpdir(), ...extra], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      env: {
        ...process.env,
        _NT_SYMBOL_PATH: tmpdir(),
        _NT_ALT_SYMBOL_PATH: "",
      },
    });
    return new CdbPipe(child as CdbChild, target);
  }

  get exited(): boolean {
    return this.exitLabel !== null;
  }

  /** True while a framed command (typically `g`) is waiting for its end marker. */
  hasPending(): boolean {
    return this.pending !== null;
  }

  waitForPrompt(timeoutMs: number): Promise<void> {
    if (this.dead) {
      return Promise.reject(new CdbError("engine_error", "cdb pipe is closed", { target: this.target }));
    }
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.promptWaiter = null;
        reject(
          new CdbError("engine_timeout", `cdb did not reach a prompt within ${timeoutMs}ms`, {
            target: this.target,
            excerpt: this.buf.slice(-400),
          }),
        );
      }, timeoutMs);
      this.promptWaiter = { resolve, reject, timer };
      this.pump();
    });
  }

  command(command: string, timeoutMs: number): Promise<string> {
    const run = this.tail.then(() => this.exec(command, timeoutMs));
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private exec(command: string, timeoutMs: number): Promise<string> {
    if (this.dead) {
      return Promise.reject(new CdbError("engine_error", "cdb pipe is closed", { target: this.target }));
    }
    if (/[\r\n]/.test(command)) {
      return Promise.reject(new CdbError("engine_error", "cdb command contains a newline"));
    }
    const nonce = `${process.pid.toString(16)}${(this.nonceSeq += 1).toString(16)}`;
    const begin = `DBG_BRIDGE_BEGIN_${nonce}`;
    const end = `DBG_BRIDGE_END_${nonce}`;
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        this.kill(true);
        reject(
          new CdbError("engine_timeout", `cdb command timed out after ${timeoutMs}ms`, {
            target: this.target,
            command,
            excerpt: this.buf.slice(-400),
          }),
        );
      }, timeoutMs);
      this.pending = { nonce, resolve, reject, timer };
      try {
        this.child.stdin.write(`.echo ${begin}\n${command}\n.echo ${end}\n`);
      } catch (error) {
        clearTimeout(timer);
        this.pending = null;
        reject(
          new CdbError("engine_error", `cdb stdin write failed: ${error instanceof Error ? error.message : String(error)}`, {
            target: this.target,
          }),
        );
      }
    });
  }

  private pump(): void {
    if (this.promptWaiter !== null && promptReady(this.buf)) {
      const waiter = this.promptWaiter;
      this.promptWaiter = null;
      clearTimeout(waiter.timer);
      waiter.resolve();
    }
    const pending = this.pending;
    if (pending === null) {
      return;
    }
    const frame = takeFrame(this.buf, pending.nonce);
    if (frame === undefined) {
      return;
    }
    this.buf = frame.rest;
    this.pending = null;
    clearTimeout(pending.timer);
    pending.resolve(frame.body);
  }

  private failLive(error: CdbError): void {
    this.dead = true;
    if (this.promptWaiter !== null) {
      clearTimeout(this.promptWaiter.timer);
      this.promptWaiter.reject(error);
      this.promptWaiter = null;
    }
    if (this.pending !== null) {
      clearTimeout(this.pending.timer);
      this.pending.reject(error);
      this.pending = null;
    }
  }

  private kill(tree: boolean): void {
    this.dead = true;
    const pid = this.child.pid;
    try {
      this.child.kill();
    } catch {
      // Already gone.
    }
    if (process.platform === "win32" && typeof pid === "number") {
      const args = tree ? ["/pid", String(pid), "/T", "/F"] : ["/pid", String(pid), "/F"];
      try {
        spawnSync("taskkill", args, { windowsHide: true, timeout: 10_000 });
      } catch {
        // Best effort.
      }
    }
  }

  /**
   * `q` ends a launched debuggee. `qd` detaches and leaves an attached
   * process running; that close must not tree-kill, or the target dies too.
   */
  async shutdown(detach: boolean): Promise<void> {
    if (!this.dead) {
      this.dead = true;
      try {
        this.child.stdin.write(detach ? "qd\n" : "q\n");
      } catch {
        // Fall through to the kill below.
      }
    }
    await Promise.race([
      this.exitPromise,
      new Promise<void>((resolve) => {
        setTimeout(resolve, QUIT_GRACE_MS);
      }),
    ]);
    this.kill(!detach);
    await this.exitPromise;
  }
}

function promptReady(buffer: string): boolean {
  return /(?:^|\n)\d+:[0-9a-f]+>\s*$/i.test(buffer);
}

function takeFrame(buffer: string, nonce: string): { body: string; rest: string } | undefined {
  const begin = `DBG_BRIDGE_BEGIN_${nonce}`;
  const end = `DBG_BRIDGE_END_${nonce}`;
  const lines = buffer.split("\n");
  let beginAt = -1;
  let endAt = -1;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? "";
    if (beginAt === -1 && lineMarker(line, begin)) {
      beginAt = i;
      continue;
    }
    if (beginAt !== -1 && lineMarker(line, end)) {
      endAt = i;
      break;
    }
  }
  if (beginAt === -1 || endAt === -1) {
    return undefined;
  }
  // The end marker must be a complete line. The final split entry has no
  // trailing newline yet, so an end marker sitting there is still partial.
  if (endAt === lines.length - 1 && !buffer.endsWith("\n")) {
    return undefined;
  }
  const body = lines.slice(beginAt + 1, endAt).map(stripPrompt).join("\n");
  const rest = lines.slice(endAt + 1).join("\n");
  return { body, rest };
}

function lineMarker(line: string, marker: string): boolean {
  return stripPrompt(line).trim() === marker;
}

function stripPrompt(line: string): string {
  let rest = line;
  let previous = "";
  while (rest !== previous) {
    previous = rest;
    rest = rest.replace(/^\d+:[0-9a-f]+>\s*/i, "");
  }
  return rest;
}

interface CdbSession {
  pipe: CdbPipe;
  target: string;
  arch: X64Arch;
  pid: number;
  attached: boolean;
  exited: boolean;
  pauseReason: string | null;
  entryPoint: string;
  moduleBase: string;
  moduleEntry: string;
  openedAt: string;
  pushes: BridgePushHandler[];
  bpTypes: Map<string, BreakpointType>;
}

/** Live debugger engine. One hidden cdb process per application session. */
export class CdbEngine implements DebugEngine {
  readonly id = "cdb" as const;
  readonly capabilities = cdbCapabilities;
  private readonly sessions = new Map<string, CdbSession>();

  async open(sessionId: string, target: string, opts: OpenDebugOptions = {}): Promise<DebugTargetInfo> {
    if (sessionId.trim() === "") {
      throw new CdbError("invalid_argument", "session id must not be empty");
    }
    if (process.platform !== "win32") {
      throw new CdbError("engine_unavailable", `cdb requires Windows (platform: ${process.platform})`);
    }
    if (opts.breakOnEntry === false) {
      throw new CdbError(
        "capability_unsupported",
        "cdb open always stops at the initial loader breakpoint; break_on_entry=false is not implemented",
      );
    }
    if (opts.autoAnalyze === true) {
      throw new CdbError("capability_unsupported", "cdb does not implement auto_analyze");
    }
    if (opts.commandLineArgs !== undefined && opts.commandLineArgs !== "") {
      throw new CdbError("capability_unsupported", "cdb does not implement command_line_args yet");
    }
    const absolute = resolvePath(target.trim());
    const arch = await detectPeArch(absolute);
    const cdbExe = await resolveCdbExe(arch);
    await this.close(sessionId);

    const pipe = CdbPipe.launch(cdbExe, absolute);
    const session: CdbSession = {
      pipe,
      target: absolute,
      arch,
      pid: 0,
      attached: false,
      exited: false,
      pauseReason: "initial_breakpoint",
      entryPoint: "",
      moduleBase: "",
      moduleEntry: "",
      openedAt: new Date().toISOString(),
      pushes: [],
      bpTypes: new Map(),
    };
    this.sessions.set(sessionId, session);
    try {
      await pipe.waitForPrompt(cdbStartTimeoutMs());
      await this.sync(pipe, absolute);
      const listed = await pipe.command("|", cdbCmdTimeoutMs());
      const modules = await pipe.command("lm", cdbCmdTimeoutMs());
      const entry = await pipe.command("? $exentry", cdbCmdTimeoutMs());
      session.pid = parseCdbPid(listed);
      session.moduleBase = parseModuleBase(modules, absolute);
      session.entryPoint = parseExentry(entry);
      session.moduleEntry = session.entryPoint;
      await this.plantEntryBreakpoint(session);
      return {
        pid: session.pid,
        architecture: arch,
        entryPoint: session.entryPoint,
        moduleBase: session.moduleBase,
        moduleEntry: session.moduleEntry,
        attached: false,
      };
    } catch (error) {
      await this.close(sessionId);
      throw error;
    }
  }

  private async sync(pipe: CdbPipe, target: string): Promise<void> {
    for (let attempt = 0; attempt < SYNC_ATTEMPTS; attempt += 1) {
      const body = await pipe.command(".echo DBG_BRIDGE_SYNC", cdbCmdTimeoutMs());
      if (body.includes("DBG_BRIDGE_SYNC")) {
        return;
      }
    }
    throw new CdbError("engine_error", "cdb pipe failed to synchronize (no reply marker)", { target });
  }

  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session === undefined) {
      return;
    }
    this.sessions.delete(sessionId);
    await session.pipe.shutdown(session.attached);
  }

  isOpen(sessionId: string): boolean {
    return this.sessions.has(sessionId);
  }

  openPath(sessionId: string): string | undefined {
    return this.sessions.get(sessionId)?.target;
  }

  onPush(sessionId: string, handler: BridgePushHandler): void {
    this.requireSession(sessionId).pushes.push(handler);
  }

  async state(sessionId: string): Promise<DebugState> {
    const session = this.requireSession(sessionId);
    if (!session.exited) {
      const listed = await session.pipe.command("|", cdbCmdTimeoutMs());
      if (/exited/i.test(listed)) {
        session.exited = true;
      }
    }
    return this.snapshot(sessionId, session);
  }

  async attach(sessionId: string, pid: number, opts: AttachOptions = {}): Promise<DebugTargetInfo> {
    if (sessionId.trim() === "") {
      throw new CdbError("invalid_argument", "session id must not be empty");
    }
    if (process.platform !== "win32") {
      throw new CdbError("engine_unavailable", `cdb requires Windows (platform: ${process.platform})`);
    }
    if (opts.breakOnEntry === false) {
      throw new CdbError("capability_unsupported", "cdb attach always breaks in; break_on_entry=false is not implemented");
    }
    if (opts.autoAnalyze === true) {
      throw new CdbError("capability_unsupported", "cdb does not implement auto_analyze");
    }
    const exePath = await getProcessExePath(pid);
    const arch = await detectPeArch(exePath);
    const cdbExe = await resolveCdbExe(arch);
    await this.close(sessionId);

    const pipe = CdbPipe.attachTo(cdbExe, pid);
    const session: CdbSession = {
      pipe,
      target: exePath,
      arch,
      pid,
      attached: true,
      exited: false,
      pauseReason: "initial_breakpoint",
      entryPoint: "",
      moduleBase: "",
      moduleEntry: "",
      openedAt: new Date().toISOString(),
      pushes: [],
      bpTypes: new Map(),
    };
    this.sessions.set(sessionId, session);
    try {
      await pipe.waitForPrompt(cdbStartTimeoutMs());
      await this.sync(pipe, exePath);
      const listed = await pipe.command("|", cdbCmdTimeoutMs());
      const modules = await pipe.command("lm", cdbCmdTimeoutMs());
      const entry = await pipe.command("? $exentry", cdbCmdTimeoutMs());
      session.pid = parseCdbPid(listed);
      session.moduleBase = parseModuleBase(modules, exePath);
      session.entryPoint = parseExentry(entry);
      session.moduleEntry = session.entryPoint;
      return {
        pid: session.pid,
        architecture: arch,
        entryPoint: session.entryPoint,
        moduleBase: session.moduleBase,
        moduleEntry: session.moduleEntry,
        attached: true,
      };
    } catch (error) {
      await this.close(sessionId);
      throw error;
    }
  }

  async setBreakpoint(sessionId: string, opts: SetBreakpointOptions): Promise<{ address: string; resolved: boolean }> {
    const session = this.requireLive(sessionId);
    if (opts.condition !== undefined || opts.logText !== undefined || opts.name !== undefined) {
      throw new CdbError(
        "capability_unsupported",
        "cdb breakpoints do not implement condition, log_text, or name",
      );
    }
    const type = opts.type ?? "software";
    const canonical = await this.resolveAddress(session, opts.address);
    const command = breakpointCommand(type, canonical);
    assertCdbOk(await session.pipe.command(command, cdbCmdTimeoutMs()), command);
    session.bpTypes.set(canonical, type);
    return { address: canonical, resolved: true };
  }

  async removeBreakpoint(sessionId: string, address: string | number): Promise<{ status: string }> {
    const session = this.requireLive(sessionId);
    const canonical = await this.resolveAddress(session, address);
    const listed = parseBreakpointList(await session.pipe.command("bl", cdbCmdTimeoutMs()), session.bpTypes);
    const hit = listed.find((row) => row.address === canonical);
    if (hit === undefined) {
      throw new CdbError("invalid_argument", `no breakpoint at ${canonical}`, { address: canonical });
    }
    const command = `bc ${hit.id}`;
    assertCdbOk(await session.pipe.command(command, cdbCmdTimeoutMs()), command);
    session.bpTypes.delete(canonical);
    return { status: "removed" };
  }

  async listBreakpoints(sessionId: string): Promise<{ breakpoints: unknown[] }> {
    const session = this.requireLive(sessionId);
    const body = await session.pipe.command("bl", cdbCmdTimeoutMs());
    return { breakpoints: parseBreakpointList(body, session.bpTypes) };
  }

  async continue_(sessionId: string, timeoutMs?: number): Promise<ContinueResult> {
    const session = this.requireSession(sessionId);
    if (session.exited) {
      return { reason: "exited", address: "0x0" };
    }
    const body = await session.pipe.command("g", timeoutMs ?? cdbContinueTimeoutMs());
    const result = await this.finishStop(session, body);
    return result;
  }

  async pause(sessionId: string): Promise<ContinueResult> {
    const session = this.requireSession(sessionId);
    if (session.exited) {
      return { reason: "exited", address: "0x0" };
    }
    if (session.pipe.hasPending()) {
      debugBreakProcess(session.pid);
    }
    const address = await this.readIp(session);
    if (!session.exited) {
      session.pauseReason = "paused";
    }
    return { reason: session.exited ? "exited" : "paused", address };
  }

  async step(sessionId: string, kind: "into" | "over", count = 1): Promise<StepResult> {
    const session = this.requireLive(sessionId);
    if (kind !== "into" && kind !== "over") {
      throw new CdbError("invalid_argument", `"kind" must be "into" or "over"; got ${JSON.stringify(kind)}`);
    }
    if (!Number.isInteger(count) || count < 1 || count > 1000) {
      throw new CdbError("invalid_argument", `"count" must be an integer 1..1000`);
    }
    if (session.exited) {
      throw new CdbError("engine_error", "debuggee has exited");
    }
    const verb = kind === "into" ? "t" : "p";
    const timeout = Math.min(30_000 + count * 1000, cdbContinueTimeoutMs());
    const body = await session.pipe.command(`${verb} ${count}`, timeout);
    const stop = await this.finishStop(session, body);
    if (stop.reason === "exited") {
      throw new CdbError("engine_error", "debuggee exited during step", { session_id: sessionId });
    }
    session.pauseReason = "step";
    return { address: stop.address };
  }

  async registers(
    sessionId: string,
    opts: { includeSegment?: boolean; includeDebug?: boolean } = {},
  ): Promise<RegisterSet> {
    const session = this.requireLive(sessionId);
    const body = await session.pipe.command("r", cdbCmdTimeoutMs());
    const parsed = parseRegisterDump(body);
    let debug: Record<string, string> | undefined;
    if (opts.includeDebug === true) {
      const extra = await session.pipe.command("r dr0,dr1,dr2,dr3,dr6,dr7", cdbCmdTimeoutMs());
      debug = parseRegisterDump(extra).general;
    }
    return {
      general: parsed.general,
      flags: parsed.flags,
      ...(opts.includeSegment === true ? { segment: parsed.segment } : {}),
      ...(debug !== undefined ? { debug } : {}),
    };
  }

  async callStack(sessionId: string, maxFrames = 50): Promise<CallStack> {
    const session = this.requireLive(sessionId);
    if (!Number.isInteger(maxFrames) || maxFrames < 1 || maxFrames > 500) {
      throw new CdbError("invalid_argument", `"max_frames" must be an integer 1..500`);
    }
    const body = await session.pipe.command("k", cdbCmdTimeoutMs());
    const threadBody = await session.pipe.command("~", cdbCmdTimeoutMs());
    return {
      threadId: parseCurrentThread(threadBody),
      frames: parseCallStack(body).slice(0, maxFrames),
    };
  }

  private async plantEntryBreakpoint(session: CdbSession): Promise<void> {
    const command = "bp $exentry";
    assertCdbOk(await session.pipe.command(command, cdbCmdTimeoutMs()), command);
    session.bpTypes.set(session.entryPoint, "software");
  }

  private async resolveAddress(session: CdbSession, address: string | number): Promise<string> {
    const expression = normalizeBreakpointExpression(address);
    try {
      return parseExentry(await session.pipe.command(`? ${expression}`, cdbCmdTimeoutMs()));
    } catch (error) {
      if (error instanceof CdbError && error.code === "engine_error") {
        throw new CdbError("invalid_argument", `cdb could not resolve address ${JSON.stringify(expression)}`, {
          excerpt: error.data?.excerpt,
        });
      }
      throw error;
    }
  }

  private async readIp(session: CdbSession): Promise<string> {
    const name = session.arch === "x64" ? "rip" : "eip";
    const body = await session.pipe.command(`r ${name}`, cdbCmdTimeoutMs());
    const match = new RegExp(`\\b${name}=([0-9a-fA-F]+)`, "i").exec(body);
    const raw = match?.[1];
    if (raw === undefined) {
      throw new CdbError("engine_error", `cdb did not report ${name}`, { excerpt: body.trim().slice(0, 300) });
    }
    return normalizeDbgAddress(raw);
  }

  private async finishStop(session: CdbSession, body: string): Promise<ContinueResult> {
    let result = classifyStop(body);
    if (result.reason === "paused" && !/Break instruction exception/i.test(body)) {
      const listed = await session.pipe.command("|", cdbCmdTimeoutMs());
      if (/exited/i.test(listed)) {
        result = { reason: "exited", address: "0x0" };
      }
    }
    if (result.reason === "exited") {
      session.exited = true;
      session.pauseReason = null;
    } else {
      session.pauseReason = result.reason;
    }
    return result;
  }

  private snapshot(sessionId: string, session: CdbSession): DebugState {
    return {
      sessionId,
      open: true,
      target: session.target,
      arch: session.arch,
      pid: session.pid,
      attached: session.attached,
      entryPoint: session.entryPoint,
      moduleBase: session.moduleBase,
      moduleEntry: session.moduleEntry,
      openedAt: session.openedAt,
      state: session.exited ? "terminated" : "paused",
      pauseReason: session.exited ? null : session.pauseReason,
      terminationReason: session.exited ? "process_exit" : null,
    };
  }

  /** Live debuggee. A target that already exited cannot take breakpoint or step commands. */
  private requireLive(sessionId: string): CdbSession {
    const session = this.requireSession(sessionId);
    if (session.exited) {
      throw new CdbError("engine_error", "debuggee has exited", { session_id: sessionId });
    }
    return session;
  }

  /** One cdb command. The caller builds it; newlines and command separators are rejected. */
  async debuggerCommand(sessionId: string, command: string): Promise<string> {
    const session = this.requireLive(sessionId);
    if (command.length === 0 || command.length > 4000 || /[\r\n;]/.test(command)) {
      throw new CdbError("invalid_argument", "command must be a single line");
    }
    const body = await session.pipe.command(command, cdbCmdTimeoutMs());
    assertCdbOk(body, command);
    return body;
  }

  /** `g <address>` until that address or the process exits. */
  async runTo(sessionId: string, address: string): Promise<ContinueResult> {
    const session = this.requireLive(sessionId);
    const canonical = normalizeBreakpointExpression(address);
    const body = await session.pipe.command(`g ${canonical}`, cdbContinueTimeoutMs());
    return this.finishStop(session, body);
  }

  private requireSession(sessionId: string): CdbSession {
    const session = this.sessions.get(sessionId);
    if (session === undefined) {
      throw new CdbError("target_not_open", `no target open for session ${sessionId}; call debug_open first`, {
        session_id: sessionId,
      });
    }
    if (session.pipe.exited) {
      throw new CdbError("engine_error", `cdb process exited; call debug_open to start a new session`, {
        session_id: sessionId,
      });
    }
    return session;
  }
}

function breakpointCommand(type: BreakpointType, address: string): string {
  switch (type) {
    case "software":
      return `bp ${address}`;
    case "hardware_execute":
      return `ba e 1 ${address}`;
    case "hardware_read":
      return `ba r 1 ${address}`;
    case "hardware_write":
      return `ba w 1 ${address}`;
    case "hardware_access":
    case "memory_read":
    case "memory_write":
    case "memory_access":
      throw new CdbError("capability_unsupported", `cdb does not implement breakpoint type ${type}`);
    default: {
      const unreachable: never = type;
      throw new CdbError("invalid_argument", `unsupported breakpoint type ${String(unreachable)}`);
    }
  }
}

function assertCdbOk(body: string, command: string): void {
  if (/^\s*\^/m.test(body) || /^\s*(Syntax error|Bad |Ambiguous)/im.test(body)) {
    throw new CdbError("engine_error", `cdb rejected command: ${command}`, {
      excerpt: body.trim().slice(0, 400),
    });
  }
}

function normalizeBreakpointExpression(value: string | number): string {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
      throw new CdbError("invalid_argument", `"address" must be a non-negative integer`);
    }
    return `0x${value.toString(16)}`;
  }
  const trimmed = value.trim();
  if (trimmed === "" || trimmed.length > 256 || !/^[0-9A-Za-z_$.+\-*/()]+$/.test(trimmed)) {
    throw new CdbError(
      "invalid_argument",
      `"address" must be hex, decimal, or a cdb expression; got ${JSON.stringify(trimmed)}`,
    );
  }
  return trimmed;
}

function classifyStop(body: string): ContinueResult {
  const found = lastInstructionAddress(body);
  const address = found ?? "0x0";
  if (/Breakpoint\s+\d+\s+hit/i.test(body)) {
    return { reason: "breakpoint", address };
  }
  if (/NtTerminateProcess|RtlExitUserProcess|No runnable debuggees|process exited/i.test(body)) {
    return { reason: "exited", address: "0x0" };
  }
  return { reason: "paused", address };
}

function lastInstructionAddress(body: string): string | undefined {
  // Opcode bytes may be a single byte (`90`) or a run (`b834120000`).
  const re = /^\s*([0-9a-fA-F`]{8,17})\s+[0-9a-fA-F]{2,}\b/gm;
  let last: string | undefined;
  for (const match of body.matchAll(re)) {
    if (match[1] !== undefined) {
      last = match[1];
    }
  }
  return last === undefined ? undefined : normalizeDbgAddress(last);
}

interface ListedBreakpoint {
  id: number;
  address: string;
  enabled: boolean;
  type: BreakpointType;
}

function parseBreakpointList(body: string, types: Map<string, BreakpointType>): ListedBreakpoint[] {
  const out: ListedBreakpoint[] = [];
  for (const line of body.split("\n")) {
    const match = /^\s*(\d+)\s+([ed])\s+([0-9a-fA-F`]{8,17})\b/.exec(stripPrompt(line));
    if (match?.[1] === undefined || match[2] === undefined || match[3] === undefined) {
      continue;
    }
    const address = normalizeDbgAddress(match[3]);
    out.push({
      id: Number(match[1]),
      address,
      enabled: match[2] === "e",
      type: types.get(address) ?? "software",
    });
  }
  return out;
}

const SEGMENT_REGISTERS = new Set(["cs", "ss", "ds", "es", "fs", "gs"]);

const FLAG_BITS: Record<string, readonly [string, boolean]> = {
  ov: ["of", true],
  nv: ["of", false],
  dn: ["df", true],
  up: ["df", false],
  ei: ["if", true],
  di: ["if", false],
  ng: ["sf", true],
  pl: ["sf", false],
  zr: ["zf", true],
  nz: ["zf", false],
  ac: ["af", true],
  na: ["af", false],
  pe: ["pf", true],
  po: ["pf", false],
  cy: ["cf", true],
  nc: ["cf", false],
};

function parseRegisterDump(body: string): {
  general: Record<string, string>;
  flags: Record<string, boolean>;
  segment: Record<string, string>;
} {
  const general: Record<string, string> = {};
  const segment: Record<string, string> = {};
  const flags: Record<string, boolean> = {};
  const re = /\b([A-Za-z][A-Za-z0-9]{1,3})=([0-9a-fA-F]+)/g;
  for (const match of body.matchAll(re)) {
    const name = match[1]?.toLowerCase();
    const raw = match[2];
    if (name === undefined || raw === undefined || name === "iopl") {
      continue;
    }
    const hex = normalizeDbgAddress(raw);
    if (SEGMENT_REGISTERS.has(name)) {
      segment[name] = hex;
    } else {
      general[name] = hex;
    }
  }
  const flagLine = /\b(nv|ov)\s+(up|dn)\s+(ei|di)\s+(pl|ng)\s+(zr|nz)\s+(ac|na)\s+(pe|po)\s+(cy|nc)\b/i.exec(body);
  if (flagLine !== null) {
    for (let i = 1; i <= 8; i += 1) {
      const token = flagLine[i]?.toLowerCase();
      const pair = token === undefined ? undefined : FLAG_BITS[token];
      if (pair !== undefined) {
        flags[pair[0]] = pair[1];
      }
    }
  }
  return { general, flags, segment };
}

function parseCallStack(body: string): CallFrame[] {
  const frames: CallFrame[] = [];
  for (const line of body.split("\n")) {
    const match = /^\s*([0-9a-fA-F`]{8,17})\s+([0-9a-fA-F`]{8,17})\s+(\S+)/.exec(stripPrompt(line));
    if (match?.[1] === undefined || match[2] === undefined || match[3] === undefined) {
      continue;
    }
    const site = match[3];
    const bang = site.indexOf("!");
    const head = bang === -1 ? site : site.slice(0, bang);
    const moduleName = head.split("+")[0] ?? head;
    const ret = normalizeDbgAddress(match[2]);
    frames.push({
      index: frames.length,
      address: ret,
      returnAddress: ret,
      module: moduleName,
      function: site,
    });
  }
  return frames;
}

function parseCurrentThread(body: string): number {
  const match = /^\s*\.\s+(\d+)\s+Id:/m.exec(body);
  const digits = match?.[1];
  if (digits === undefined) {
    return 0;
  }
  const id = Number(digits);
  return Number.isInteger(id) ? id : 0;
}

export async function getProcessExePath(pid: number): Promise<string> {
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new CdbError("invalid_argument", `"pid" must be a positive integer; got ${JSON.stringify(pid)}`);
  }
  if (pid === process.pid) {
    throw new CdbError("invalid_argument", "cannot attach to the bridge's own process");
  }
  let stdout = "";
  try {
    const res = spawnSync(
      "powershell",
      ["-NoProfile", "-NonInteractive", "-Command", `(Get-Process -Id ${pid}).Path`],
      { encoding: "utf8", timeout: 15_000, windowsHide: true },
    );
    stdout = typeof res.stdout === "string" ? res.stdout.trim() : "";
    if (res.error !== undefined || res.status !== 0 || stdout === "") {
      throw new Error("lookup failed");
    }
  } catch {
    throw new CdbError(
      "invalid_target",
      `no accessible process with pid ${pid} (it may have exited, or querying it may require elevation)`,
      { pid },
    );
  }
  return stdout;
}

function debugBreakProcess(pid: number): void {
  const ps = [
    "$src = 'using System; using System.Runtime.InteropServices; public class BridgeBreak {",
    "[DllImport(\"kernel32.dll\", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, int p);",
    "[DllImport(\"kernel32.dll\", SetLastError=true)] public static extern bool DebugBreakProcess(IntPtr h);",
    "[DllImport(\"kernel32.dll\")] public static extern bool CloseHandle(IntPtr h); }'",
    "Add-Type -TypeDefinition $src -ErrorAction Stop",
    `$h = [BridgeBreak]::OpenProcess(2035711, $false, ${pid})`,
    "if ($h -eq [IntPtr]::Zero) { Write-Output ('open-fail ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()); exit 2 }",
    "$ok = [BridgeBreak]::DebugBreakProcess($h)",
    "[BridgeBreak]::CloseHandle($h) | Out-Null",
    "Write-Output ('break=' + $ok)",
  ].join("\n");
  const res = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps], {
    encoding: "utf8",
    timeout: 20_000,
    windowsHide: true,
  });
  const stdout = typeof res.stdout === "string" ? res.stdout : "";
  if (res.status !== 0 || !/break=True/i.test(stdout)) {
    throw new CdbError("engine_error", `could not break pid ${pid}`, {
      pid,
      excerpt: `${stdout} ${typeof res.stderr === "string" ? res.stderr : ""}`.trim().slice(0, 400),
    });
  }
}

export const cdbEngine = new CdbEngine();
