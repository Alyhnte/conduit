import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { copyFile, mkdir, open as fsOpen, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";

import { suggestDownload } from "../catalog.js";
import type { Capabilities, DebugEngine } from "./types.js";

/**
 * Live-debug adapter for x64dbg (ouonet pattern).
 *
 * Each application session owns one hidden x64dbg process (x32dbg for x86
 * targets, x64dbg for x64 targets). A prebuilt C loader plugin
 * (`plugin/x64dbg/prebuilt/x64dbg_mcp_loader.dp32|.dp64`, no compiler needed)
 * embeds Python 3 inside the debugger and auto-starts a TCP bridge that calls
 * x64bridge.dll / x32bridge.dll directly via ctypes. This engine speaks the
 * bridge's newline-delimited JSON protocol over 127.0.0.1.
 *
 * Vendored bridge sources + third-party notices live in `plugin/x64dbg/`.
 * The engine copies the loader + Python files into the debugger's
 * `plugins/` directory on first use, spawns the debugger hidden, waits for
 * the TCP port, probes the protocol version, then loads the target.
 */
export const x64dbgCapabilities: Capabilities = {
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

export type X64Arch = "x86" | "x64";

export type X64dbgErrorCode =
  | "engine_unavailable"
  | "invalid_target"
  | "target_not_open"
  | "invalid_argument"
  | "engine_timeout"
  | "engine_error"
  | "bridge_error";

export class X64dbgError extends Error {
  readonly code: X64dbgErrorCode;
  readonly data?: Record<string, unknown>;

  constructor(code: X64dbgErrorCode, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "X64dbgError";
    this.code = code;
    this.data = data;
  }
}

export const DEFAULT_CMD_TIMEOUT_MS = 30_000;
export const DEFAULT_START_TIMEOUT_MS = 60_000;
export const DEFAULT_LOAD_TIMEOUT_MS = 150_000;
export const DEFAULT_CONTINUE_TIMEOUT_MS = 125_000;
export const DEFAULT_STEP_TIMEOUT_MS = 60_000;
export const BRIDGE_PROTOCOL_VERSION = "2";
export const BRIDGE_HOST = "127.0.0.1";

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

export function x64dbgCmdTimeoutMs(): number {
  return envTimeout("DBG_BRIDGE_X64DBG_CMD_TIMEOUT_MS", DEFAULT_CMD_TIMEOUT_MS);
}

export function x64dbgStartTimeoutMs(): number {
  return envTimeout("DBG_BRIDGE_X64DBG_START_TIMEOUT_MS", DEFAULT_START_TIMEOUT_MS);
}

export function x64dbgLoadTimeoutMs(): number {
  return envTimeout("DBG_BRIDGE_X64DBG_LOAD_TIMEOUT_MS", DEFAULT_LOAD_TIMEOUT_MS);
}

export function x64dbgContinueTimeoutMs(): number {
  return envTimeout("DBG_BRIDGE_X64DBG_CONTINUE_TIMEOUT_MS", DEFAULT_CONTINUE_TIMEOUT_MS);
}

// ---------------------------------------------------------------------------
// Install resolution: X64DBG_DIR + well-known portable locations
// ---------------------------------------------------------------------------

let dirCache: string | null | undefined;

export function resetX64dbgDirCache(): void {
  dirCache = undefined;
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

function debuggerExeCandidates(dir: string, arch: X64Arch): string[] {
  const sub = arch === "x64" ? "x64" : "x32";
  const exe = arch === "x64" ? "x64dbg.exe" : "x32dbg.exe";
  return [join(dir, "release", sub, exe), join(dir, sub, exe), join(dir, exe)];
}

/** Candidate install roots, in priority order. */
export function x64dbgDirCandidates(): string[] {
  const out: string[] = [];
  const override = process.env.X64DBG_DIR;
  if (override !== undefined && override !== "") {
    out.push(resolvePath(override));
  }
  if (process.platform === "win32") {
    const programFiles = process.env["ProgramFiles"] ?? "C:\\Program Files";
    out.push(join(programFiles, "x64dbg"));
    out.push("C:\\x64dbg");
    try {
      out.push(join(homedir(), "Tools", "x64dbg"));
    } catch {
      // Homedir unavailable; skip.
    }
  }
  return out;
}

async function hasDebugger(dir: string): Promise<boolean> {
  for (const arch of ["x64", "x86"] as X64Arch[]) {
    for (const candidate of debuggerExeCandidates(dir, arch)) {
      if (await isFile(candidate)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Resolve the x64dbg install root. `X64DBG_DIR` wins; otherwise the portable
 * defaults are probed. Throws `engine_unavailable` with the checked paths.
 */
export async function resolveX64dbgDir(): Promise<string> {
  if (dirCache !== undefined) {
    if (dirCache === null) {
      throw x64dbgMissingError(x64dbgDirCandidates());
    }
    return dirCache;
  }
  const candidates = x64dbgDirCandidates();
  for (const dir of candidates) {
    if (await hasDebugger(dir)) {
      dirCache = dir;
      return dir;
    }
  }
  // An explicit X64DBG_DIR that exists but holds no debugger is still a miss,
  // reported with the same actionable error.
  dirCache = null;
  throw x64dbgMissingError(candidates);
}

function x64dbgMissingError(candidates: string[]): X64dbgError {
  const checked = candidates.length > 0 ? candidates.join(", ") : "(no candidates on this platform)";
  return new X64dbgError(
    "engine_unavailable",
    `x64dbg not found. Set X64DBG_DIR to a portable x64dbg snapshot (checked: ${checked}). ` +
      `No installer or PATH edit needed; both x32/ and x64/ sublayouts are recognized. ${suggestDownload("x64dbg")}`,
  );
}

/** Resolve x32dbg.exe / x64dbg.exe inside an install root. */
export async function resolveDebuggerExe(dir: string, arch: X64Arch): Promise<string> {
  const candidates = debuggerExeCandidates(dir, arch);
  for (const candidate of candidates) {
    if (await isFile(candidate)) {
      return candidate;
    }
  }
  const label = arch === "x64" ? "x64dbg.exe" : "x32dbg.exe";
  throw new X64dbgError("engine_unavailable", `No ${label} for ${arch} targets under ${dir}`, {
    dir,
    arch,
    checked: candidates,
  });
}

/** Directory holding the debugger exe (…/x64 or …/x32); owns plugins/. */
export function debuggerArchDir(debuggerExe: string): string {
  return dirname(debuggerExe);
}

// ---------------------------------------------------------------------------
// PE architecture detection (target + bitness probes)
// ---------------------------------------------------------------------------

const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_FILE_MACHINE_ARMNT = 0x01c4;
const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;

/** Read the COFF Machine field of a PE file. */
export async function readPeMachine(pePath: string): Promise<number> {
  let handle;
  try {
    handle = await fsOpen(pePath, "r");
  } catch {
    throw new X64dbgError("invalid_target", `target not found: ${pePath}`);
  }
  try {
    const dos = Buffer.alloc(64);
    if ((await handle.read(dos, 0, 64, 0)).bytesRead < 64 || dos.readUInt16LE(0) !== 0x5a4d) {
      throw new X64dbgError("invalid_target", `not a valid PE file (bad MZ signature): ${pePath}`);
    }
    const peOffset = dos.readUInt32LE(0x3c);
    if (peOffset > 1024 * 1024) {
      throw new X64dbgError("invalid_target", `not a valid PE file (e_lfanew out of range): ${pePath}`);
    }
    const head = Buffer.alloc(6);
    if ((await handle.read(head, 0, 6, peOffset)).bytesRead < 6) {
      throw new X64dbgError("invalid_target", `not a valid PE file (truncated headers): ${pePath}`);
    }
    if (head.readUInt32LE(0) !== 0x00004550) {
      throw new X64dbgError("invalid_target", `not a valid PE file (bad PE signature): ${pePath}`);
    }
    return head.readUInt16LE(4);
  } finally {
    await handle.close();
  }
}

/**
 * Auto-detect target architecture from the PE header. Mirrors the x96dbg
 * launcher rule: i386 -> x32dbg, AMD64 -> x64dbg, anything else rejected.
 */
export async function detectPeArch(targetPath: string): Promise<X64Arch> {
  const trimmed = targetPath.trim();
  if (trimmed === "" || trimmed.startsWith("-")) {
    throw new X64dbgError("invalid_target", `refusing to open target: ${JSON.stringify(targetPath)}`);
  }
  const absolute = resolvePath(trimmed);
  try {
    if (!(await stat(absolute)).isFile()) {
      throw new X64dbgError("invalid_target", `target is not a file: ${trimmed}`);
    }
  } catch (error) {
    if (error instanceof X64dbgError) {
      throw error;
    }
    throw new X64dbgError("invalid_target", `target not found: ${trimmed}`);
  }
  const machine = await readPeMachine(absolute);
  if (machine === IMAGE_FILE_MACHINE_I386) {
    return "x86";
  }
  if (machine === IMAGE_FILE_MACHINE_AMD64) {
    return "x64";
  }
  if (machine === IMAGE_FILE_MACHINE_ARM64 || machine === IMAGE_FILE_MACHINE_ARMNT) {
    throw new X64dbgError(
      "invalid_target",
      `ARM PE detected (machine 0x${machine.toString(16)}): x64dbg only supports x86 and x64 targets`,
      { machine: `0x${machine.toString(16)}` },
    );
  }
  throw new X64dbgError("invalid_target", `unsupported PE machine type 0x${machine.toString(16)}: ${trimmed}`, {
    machine: `0x${machine.toString(16)}`,
  });
}

/**
 * Resolve a live process to its executable path (for arch detection before
 * attach). PowerShell is used because Node cannot query Windows process
 * paths natively; the pid is validated digits-only so interpolation is safe.
 */
export async function getProcessExePath(pid: number): Promise<string> {
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new X64dbgError("invalid_argument", `"pid" must be a positive integer; got ${JSON.stringify(pid)}`);
  }
  if (pid === process.pid) {
    throw new X64dbgError("invalid_argument", "cannot attach to the bridge's own process");
  }
  let stdout = "";
  try {
    const res = spawnSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", `(Get-Process -Id ${pid}).Path`], {
      encoding: "utf8",
      timeout: 15_000,
      windowsHide: true,
    });
    stdout = typeof res.stdout === "string" ? res.stdout.trim() : "";
    if (res.error !== undefined || res.status !== 0 || stdout === "") {
      throw new Error("lookup failed");
    }
  } catch {
    throw new X64dbgError(
      "invalid_target",
      `no accessible process with pid ${pid} (it may have exited, or querying it may require elevation)`,
      { pid },
    );
  }
  return stdout;
}

// ---------------------------------------------------------------------------
// Bridge files: vendored loader + Python (auto-install into x64dbg plugins/)
// ---------------------------------------------------------------------------

/** Package dir of the running build (`dist/` -> package root). */
export function packageRoot(): string {
  return dirname(dirname(dirname(fileURLToPath(import.meta.url))));
}

/** Vendored ouonet-pattern bridge sources shipped with Conduit. */
export function pluginSourceDir(): string {
  return join(packageRoot(), "plugin", "x64dbg");
}

export interface BridgeFileSet {
  loaderName: string;
  loaderSource: string;
  sdkSource: string;
  bridgeSource: string;
}

export function bridgeFileSet(arch: X64Arch): BridgeFileSet {
  const src = pluginSourceDir();
  const loaderName = arch === "x64" ? "x64dbg_mcp_loader.dp64" : "x64dbg_mcp_loader.dp32";
  return {
    loaderName,
    loaderSource: join(src, "prebuilt", loaderName),
    sdkSource: join(src, "x64dbg_bridge_sdk.py"),
    bridgeSource: join(src, "x64dbg_mcp_bridge.py"),
  };
}

async function copyIfDifferent(source: string, dest: string): Promise<void> {
  let copy = true;
  try {
    const [a, b] = await Promise.all([stat(source), stat(dest)]);
    copy = a.size !== b.size;
  } catch {
    copy = true;
  }
  if (copy) {
    await copyFile(source, dest);
  }
}

/**
 * Ensure the loader plugin + bridge scripts exist in the debugger's
 * `plugins/` directory (created on first use). The debugger auto-loads
 * `*.dp32|*.dp64` at startup, so no registration step exists.
 */
export async function ensureBridgeFiles(debuggerExe: string, arch: X64Arch): Promise<string> {
  const pluginsDir = join(debuggerArchDir(debuggerExe), "plugins");
  const files = bridgeFileSet(arch);
  if (!(await isFile(files.loaderSource))) {
    throw new X64dbgError(
      "engine_unavailable",
      `prebuilt loader missing for ${arch} targets: ${files.loaderSource}. ` +
        `Rebuild it per plugin/x64dbg/THIRD_PARTY_NOTICES.md (MinGW, no VS Build Tools needed).`,
      { arch, loader: files.loaderSource },
    );
  }
  for (const source of [files.sdkSource, files.bridgeSource]) {
    if (!(await isFile(source))) {
      throw new X64dbgError("engine_unavailable", `bridge source missing: ${source}`, { arch });
    }
  }
  await mkdir(pluginsDir, { recursive: true });
  await copyIfDifferent(files.loaderSource, join(pluginsDir, files.loaderName));
  await copyIfDifferent(files.sdkSource, join(pluginsDir, "x64dbg_bridge_sdk.py"));
  await copyIfDifferent(files.bridgeSource, join(pluginsDir, "x64dbg_mcp_bridge.py"));
  return pluginsDir;
}

// ---------------------------------------------------------------------------
// Python home resolution (the loader embeds matching-bitness Python 3)
// ---------------------------------------------------------------------------

interface PythonProbe {
  executable: string;
  bits: number;
}

let pythonProbeCache: PythonProbe | null | undefined;

export function resetPythonProbeCache(): void {
  pythonProbeCache = undefined;
}

function pythonInterpreter(): string {
  return process.env.DBG_BRIDGE_PYTHON ?? "python";
}

function probeSystemPython(): PythonProbe | null {
  if (pythonProbeCache !== undefined) {
    return pythonProbeCache;
  }
  const code = "import sys,struct;print(sys.executable);print(struct.calcsize('P')*8)";
  const launchers: Array<{ cmd: string; prefix: string[] }> = [
    { cmd: pythonInterpreter(), prefix: [] },
    { cmd: "py", prefix: ["-3"] },
  ];
  for (const launcher of launchers) {
    try {
      const res = spawnSync(launcher.cmd, [...launcher.prefix, "-c", code], {
        encoding: "utf8",
        timeout: 15_000,
        windowsHide: true,
      });
      if (res.error !== undefined || res.status !== 0) {
        continue;
      }
      const lines = String(res.stdout).split(/\r?\n/).filter((l) => l.trim() !== "");
      const bits = Number(lines[1]);
      if (lines[0] && (bits === 32 || bits === 64)) {
        pythonProbeCache = { executable: lines[0].trim(), bits };
        return pythonProbeCache;
      }
    } catch {
      // Try the next launcher.
    }
  }
  pythonProbeCache = null;
  return null;
}

async function pythonDllPresent(dir: string): Promise<boolean> {
  // Any versioned python3XY.dll (or the stable-ABI stub) satisfies the loader.
  const { readdir } = await import("node:fs/promises");
  try {
    const entries = await readdir(dir);
    return entries.some((name) => /^python3\d*\.dll$/i.test(name));
  } catch {
    return false;
  }
}

/**
 * Resolve the Python home whose DLL the loader embeds. Explicit arch env vars
 * win (`PYTHON_HOME_X64` / `PYTHON_HOME_X86`); otherwise the system
 * interpreter is used when its bitness matches the target arch.
 */
export async function resolvePythonHome(arch: X64Arch): Promise<string> {
  const envName = arch === "x64" ? "PYTHON_HOME_X64" : "PYTHON_HOME_X86";
  const explicit = process.env[envName] ?? process.env.PYTHON_HOME;
  if (explicit !== undefined && explicit !== "") {
    const dir = resolvePath(explicit);
    if (!(await pythonDllPresent(dir))) {
      throw new X64dbgError(
        "engine_unavailable",
        `${envName} has no python3*.dll: ${dir}. Point it at a ${arch === "x64" ? "64" : "32"}-bit Python 3.10+ install.`,
        { arch, dir },
      );
    }
    return dir;
  }
  if (arch === "x86") {
    // Portable 32-bit Python provisioned next to the portable x64dbg install.
    try {
      const portable = join(homedir(), "Tools", "python-x86");
      if (await pythonDllPresent(portable)) {
        return portable;
      }
    } catch {
      // Homedir unavailable; fall through.
    }
  }
  const probe = probeSystemPython();
  const wantBits = arch === "x64" ? 64 : 32;
  if (probe !== null && probe.bits === wantBits) {
    return dirname(probe.executable);
  }
  if (arch === "x86") {
    throw new X64dbgError(
      "engine_unavailable",
      "x86 targets need a 32-bit Python 3.10+ (the loader embeds matching-bitness Python). " +
        `Set PYTHON_HOME_X86 to a portable 32-bit Python directory; no install or PATH edit needed. ${suggestDownload("python32")}`,
      { arch },
    );
  }
  throw new X64dbgError(
    "engine_unavailable",
    "No 64-bit Python 3.10+ found for the x64dbg bridge. Install CPython 3.10+ (python3.dll must be loadable) " +
      `or set PYTHON_HOME_X64. ${suggestDownload("python64")}`,
    { arch },
  );
}

// ---------------------------------------------------------------------------
// TCP plumbing: free port, bridge readiness
// ---------------------------------------------------------------------------

/**
 * Pick a free loopback port outside the Windows ephemeral pool (same
 * rationale as upstream: ephemeral ports yield false-positive probes).
 */
export async function pickFreePort(min = 30000, max = 44999, attempts = 20): Promise<number> {
  for (let i = 0; i < attempts; i += 1) {
    const candidate = Math.floor(min + Math.random() * (max - min + 1));
    const free = await new Promise<boolean>((resolve) => {
      const server = net.createServer();
      server.once("error", () => {
        server.close();
        resolve(false);
      });
      server.listen(candidate, BRIDGE_HOST, () => {
        server.close(() => resolve(true));
      });
    });
    if (free) {
      return candidate;
    }
  }
  throw new X64dbgError("engine_error", `could not allocate a free TCP port in [${min}, ${max}]`, {
    min,
    max,
    attempts,
  });
}

async function probePort(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const sock = new net.Socket();
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => {
      sock.destroy();
      resolve(true);
    });
    sock.once("error", () => {
      sock.destroy();
      resolve(false);
    });
    sock.once("timeout", () => {
      sock.destroy();
      resolve(false);
    });
    sock.connect(port, host);
  });
}

/** Wait until the in-debugger bridge accepts TCP connections. */
export async function waitForBridge(host: string, port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await probePort(host, port, 500)) {
      // The probe can succeed before the accept loop is primed; settle briefly.
      await new Promise((r) => setTimeout(r, 300));
      return;
    }
  }
  throw new X64dbgError(
    "engine_timeout",
    `x64dbg bridge did not listen on ${host}:${port} within ${timeoutMs}ms. ` +
      `Check the debugger's plugins/mcp_loader_debug.log for loader errors.`,
    { host, port, timeoutMs },
  );
}

// ---------------------------------------------------------------------------
// Bridge TCP client (newline-delimited JSON, id-demuxed, push-aware)
// ---------------------------------------------------------------------------

export interface BridgePushHandler {
  (type: "stateChange" | "debugEvent", payload: unknown): void;
}

interface PendingCall {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

const CONNECT_TIMEOUT_MS = 10_000;
const PROBE_TIMEOUT_MS = 10_000;
const MAX_BUFFER_BYTES = 16 * 1024 * 1024;
/** Backoff before the single retry of an idempotent bridge read (see call()). */
const LOCKLESS_RETRY_BACKOFF_MS = 250;

/** Read-only bridge methods that bypass the request queue (see X64dbgEngine). */
const LOCKLESS_METHODS = new Set(["protocol.probe", "debug.getState", "state.get", "debug.listBreakpoints"]);

export class BridgeClient extends EventEmitter {
  private socket: net.Socket | null = null;
  private buffer = "";
  private readonly pending = new Map<string, PendingCall>();
  private connected = false;

  constructor(
    private readonly host: string,
    private readonly port: number,
    private readonly authToken: string,
  ) {
    super();
  }

  get isConnected(): boolean {
    return this.connected;
  }

  async connect(): Promise<void> {
    if (this.connected) {
      return;
    }
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.destroySocket();
        reject(new X64dbgError("engine_timeout", `bridge connect to ${this.host}:${this.port} timed out`, {
          host: this.host,
          port: this.port,
        }));
      }, CONNECT_TIMEOUT_MS);
      const sock = new net.Socket();
      this.socket = sock;
      sock.once("connect", () => {
        clearTimeout(timer);
        this.connected = true;
        this.buffer = "";
        resolve();
      });
      sock.on("data", (chunk: Buffer) => this.onData(chunk));
      sock.once("error", (error: Error) => {
        clearTimeout(timer);
        this.destroySocket();
        reject(new X64dbgError("engine_error", `bridge socket error: ${error.message}`, {
          host: this.host,
          port: this.port,
        }));
      });
      sock.once("close", () => {
        const was = this.connected;
        this.connected = false;
        this.rejectAllPending(new X64dbgError("engine_error", "bridge connection closed", {
          host: this.host,
          port: this.port,
        }));
        if (was) {
          this.emit("disconnected");
        }
      });
      sock.connect(this.port, this.host);
    });
    // Version handshake before any debug method runs.
    const probe = await this.call<Record<string, unknown>>("protocol.probe", {}, PROBE_TIMEOUT_MS);
    if (probe.protocolVersion !== BRIDGE_PROTOCOL_VERSION) {
      await this.disconnect().catch(() => undefined);
      throw new X64dbgError(
        "engine_error",
        `bridge protocol mismatch: got ${JSON.stringify(probe.protocolVersion)}, want "${BRIDGE_PROTOCOL_VERSION}"`,
        { got: probe.protocolVersion, want: BRIDGE_PROTOCOL_VERSION },
      );
    }
  }

  async disconnect(): Promise<void> {
    this.rejectAllPending(new X64dbgError("engine_error", "bridge disconnecting"));
    const sock = this.socket;
    this.socket = null;
    this.connected = false;
    if (sock && !sock.destroyed) {
      await new Promise<void>((resolve) => {
        let done = false;
        const finish = (): void => {
          if (!done) {
            done = true;
            resolve();
          }
        };
        sock.once("close", finish);
        sock.removeAllListeners("data");
        sock.removeAllListeners("error");
        sock.destroy();
        setTimeout(finish, 500);
      });
    }
  }

  /**
   * Send a request; resolves with `data`, rejects with X64dbgError.
   * Idempotent reads (LOCKLESS_METHODS) get one retry on timeout: the bridge
   * is single-threaded, so a read racing a long continue can starve once.
   * State-changing calls are never retried (at-most-once execution).
   */
  async call<T = unknown>(method: string, params: Record<string, unknown> = {}, timeoutMs?: number): Promise<T> {
    try {
      return await this.callOnce<T>(method, params, timeoutMs);
    } catch (error) {
      if (
        error instanceof X64dbgError
        && error.code === "engine_timeout"
        && isLocklessMethod(method)
        && this.connected
      ) {
        await new Promise((r) => setTimeout(r, LOCKLESS_RETRY_BACKOFF_MS));
        return this.callOnce<T>(method, params, timeoutMs);
      }
      throw error;
    }
  }

  private callOnce<T = unknown>(
    method: string,
    params: Record<string, unknown> = {},
    timeoutMs?: number,
  ): Promise<T> {
    if (!this.connected || this.socket === null) {
      return Promise.reject(new X64dbgError("engine_error", "bridge is not connected"));
    }
    const id = randomUUID();
    const payload =
      JSON.stringify({
        id,
        method,
        params,
        authToken: this.authToken,
        protocolVersion: BRIDGE_PROTOCOL_VERSION,
      }) + "\n";
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(
          new X64dbgError("engine_timeout", `bridge request timed out: ${method}`, { method, timeoutMs }),
        );
      }, timeoutMs ?? x64dbgCmdTimeoutMs());
      this.pending.set(id, {
        resolve: (value: unknown) => resolve(value as T),
        reject,
        timer,
      });
      this.socket?.write(payload, "utf8", (error) => {
        if (error) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(new X64dbgError("engine_error", `bridge write failed: ${error.message}`, { method }));
        }
      });
    });
  }

  private onData(chunk: Buffer): void {
    this.buffer += chunk.toString("utf8");
    if (this.buffer.length > MAX_BUFFER_BYTES) {
      this.buffer = "";
      this.rejectAllPending(new X64dbgError("engine_error", "bridge buffer overflow; disconnecting"));
      void this.disconnect().catch(() => undefined);
      return;
    }
    let index: number;
    while ((index = this.buffer.indexOf("\n")) !== -1) {
      const line = this.buffer.slice(0, index).trim();
      this.buffer = this.buffer.slice(index + 1);
      if (line === "") {
        continue;
      }
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue; // Malformed line; the bridge logs the cause itself.
      }
      if (msg.type === "stateChange" || msg.type === "debugEvent") {
        this.emit("push", msg.type, msg.type === "stateChange" ? msg.state : msg.event);
        continue;
      }
      if (typeof msg.id === "string") {
        const entry = this.pending.get(msg.id);
        if (entry === undefined) {
          continue;
        }
        clearTimeout(entry.timer);
        this.pending.delete(msg.id);
        if (msg.success === true) {
          entry.resolve(msg.data);
        } else {
          entry.reject(
            new X64dbgError("bridge_error", typeof msg.error === "string" ? msg.error : "bridge call failed", {
              response: msg.error ?? null,
            }),
          );
        }
      }
    }
  }

  private rejectAllPending(error: Error): void {
    for (const entry of this.pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(error);
    }
    this.pending.clear();
  }

  private destroySocket(): void {
    this.connected = false;
    if (this.socket) {
      this.socket.removeAllListeners();
      this.socket.destroy();
      this.socket = null;
    }
  }
}

export function isLocklessMethod(method: string): boolean {
  return LOCKLESS_METHODS.has(method);
}

// ---------------------------------------------------------------------------
// Debug engine: one hidden x64dbg per session
// ---------------------------------------------------------------------------

export interface OpenDebugOptions {
  breakOnEntry?: boolean;
  autoAnalyze?: boolean;
  commandLineArgs?: string;
}

export interface DebugTargetInfo {
  pid: number;
  architecture: string;
  entryPoint: string;
  moduleBase: string | null;
  moduleEntry: string | null;
  attached: boolean;
}

export interface AttachOptions {
  breakOnEntry?: boolean;
  autoAnalyze?: boolean;
}

export interface DebugLiveState {
  state: string;
  pauseReason: string | null;
  terminationReason: string | null;
}

export interface DebugState extends DebugLiveState {
  sessionId: string;
  open: boolean;
  target: string | null;
  arch: X64Arch | null;
  pid: number | null;
  attached: boolean;
  entryPoint: string | null;
  moduleBase: string | null;
  moduleEntry: string | null;
  openedAt: string | null;
}

export interface MainModuleInfo {
  name: string;
  base: string;
  size: string;
  path: string;
  entry: string;
}

export type BreakpointType =
  | "software"
  | "hardware_execute"
  | "hardware_read"
  | "hardware_write"
  | "hardware_access"
  | "memory_read"
  | "memory_write"
  | "memory_access";

const BREAKPOINT_TYPES: ReadonlySet<string> = new Set([
  "software",
  "hardware_execute",
  "hardware_read",
  "hardware_write",
  "hardware_access",
  "memory_read",
  "memory_write",
  "memory_access",
]);

export interface SetBreakpointOptions {
  address: string | number;
  type?: BreakpointType;
  condition?: string;
  logText?: string;
  name?: string;
}

export interface ContinueResult {
  reason: string;
  address: string;
}

export interface StepResult {
  address: string;
  disassembly?: string;
  module?: string;
  function?: string;
  registers?: Record<string, string>;
}

export interface RegisterSet {
  general: Record<string, string>;
  flags: Record<string, boolean>;
  segment?: Record<string, string>;
  debug?: Record<string, string>;
}

export interface CallFrame {
  index: number;
  address: string;
  returnAddress?: string;
  module?: string;
  function?: string;
}

export interface CallStack {
  threadId: number;
  frames: CallFrame[];
}

interface OpenDebug {
  child: ChildProcess;
  client: BridgeClient;
  port: number;
  arch: X64Arch;
  target: string;
  pid: number;
  attached: boolean;
  entryPoint: string;
  moduleBase: string | null;
  moduleEntry: string | null;
  openedAt: string;
  exited: boolean;
  debuggerExit: string | null;
  tail: Promise<void>;
}

function normalizeAddress(value: string | number, name: string): string {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
      throw new X64dbgError("invalid_argument", `"${name}" must be a non-negative integer`);
    }
    return `0x${value.toString(16)}`;
  }
  const trimmed = value.trim();
  if (trimmed === "" || trimmed.length > 256) {
    throw new X64dbgError("invalid_argument", `"${name}" must be a non-empty address or symbol (max 256 chars)`);
  }
  // x64dbg expressions (symbols, registers, arithmetic) pass through; only
  // control characters and newlines are rejected (protocol framing).
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new X64dbgError("invalid_argument", `"${name}" contains control characters`);
  }
  return trimmed;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value === "object" && value !== null) {
    return value as Record<string, unknown>;
  }
  return {};
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asNullableString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/** Live debugger engine. One hidden x64dbg process per application session. */
export class X64dbgEngine implements DebugEngine {
  readonly id = "x64dbg" as const;
  readonly capabilities = x64dbgCapabilities;
  private readonly sessions = new Map<string, OpenDebug>();

  async open(sessionId: string, target: string, opts: OpenDebugOptions = {}): Promise<DebugTargetInfo> {
    if (sessionId.trim() === "") {
      throw new X64dbgError("invalid_argument", "session id must not be empty");
    }
    if (process.platform !== "win32") {
      throw new X64dbgError("engine_unavailable", `x64dbg requires Windows (platform: ${process.platform})`);
    }
    const arch = await detectPeArch(target);
    const absolute = resolvePath(target.trim());
    const dir = await resolveX64dbgDir();
    const debuggerExe = await resolveDebuggerExe(dir, arch);
    await ensureBridgeFiles(debuggerExe, arch);
    const pythonHome = await resolvePythonHome(arch);

    // Re-open replaces the previous debuggee, mirroring the static engine.
    await this.close(sessionId);

    let entry: OpenDebug;
    try {
      entry = await this.spawnDebugger(sessionId, arch, debuggerExe, pythonHome, absolute, false);
      const loaded = await entry.client.call<Record<string, unknown>>(
        "debug.load",
        {
          executablePath: absolute,
          breakOnEntry: opts.breakOnEntry ?? true,
          autoAnalyze: opts.autoAnalyze ?? false,
          ...(opts.commandLineArgs ? { commandLineArgs: opts.commandLineArgs } : {}),
        },
        x64dbgLoadTimeoutMs(),
      );
      entry.pid = typeof loaded.pid === "number" ? loaded.pid : 0;
      entry.entryPoint = asString(loaded.entryPoint, "");
      await this.resolveModuleEntry(entry);
      return {
        pid: entry.pid,
        architecture: asString(loaded.architecture, arch),
        entryPoint: entry.entryPoint,
        moduleBase: entry.moduleBase,
        moduleEntry: entry.moduleEntry,
        attached: false,
      };
    } catch (error) {
      await this.close(sessionId);
      throw error;
    }
  }

  /**
   * Attach to a live process. The debugger arch comes from the target's own
   * executable (queried by pid), so x86/x64 attach picks the right debugger.
   * Replaces any previous debuggee on the session, like open().
   */
  async attach(sessionId: string, pid: number, opts: AttachOptions = {}): Promise<DebugTargetInfo> {
    if (sessionId.trim() === "") {
      throw new X64dbgError("invalid_argument", "session id must not be empty");
    }
    if (process.platform !== "win32") {
      throw new X64dbgError("engine_unavailable", `x64dbg requires Windows (platform: ${process.platform})`);
    }
    const exePath = await getProcessExePath(pid);
    const arch = await detectPeArch(exePath);
    const dir = await resolveX64dbgDir();
    const debuggerExe = await resolveDebuggerExe(dir, arch);
    await ensureBridgeFiles(debuggerExe, arch);
    const pythonHome = await resolvePythonHome(arch);

    await this.close(sessionId);

    let entry: OpenDebug;
    try {
      entry = await this.spawnDebugger(sessionId, arch, debuggerExe, pythonHome, exePath, true);
      const attached = await entry.client.call<Record<string, unknown>>(
        "debug.attach",
        {
          pid,
          breakOnEntry: opts.breakOnEntry ?? true,
          autoAnalyze: opts.autoAnalyze ?? false,
        },
        x64dbgLoadTimeoutMs(),
      );
      entry.pid = typeof attached.pid === "number" ? attached.pid : pid;
      entry.entryPoint = asString(attached.entryPoint, "");
      await this.resolveModuleEntry(entry);
      return {
        pid: entry.pid,
        architecture: asString(attached.architecture, arch),
        entryPoint: entry.entryPoint,
        moduleBase: entry.moduleBase,
        moduleEntry: entry.moduleEntry,
        attached: true,
      };
    } catch (error) {
      await this.close(sessionId);
      throw error;
    }
  }

  /**
   * Detach from the current debuggee, leaving the target process running.
   * Only valid for attached sessions; launched targets stop with debug_close.
   * The hidden debugger stays alive but idle; debug_close tears it down.
   */
  async detach(sessionId: string): Promise<{ detached: boolean; pid: number }> {
    const entry = this.requireSession(sessionId);
    if (!entry.attached) {
      throw new X64dbgError(
        "invalid_argument",
        `session ${sessionId} holds a launched target, not an attached one; use debug_close to stop it`,
        { session_id: sessionId },
      );
    }
    const pid = entry.pid;
    try {
      await this.bridge<Record<string, unknown>>(entry, "debug.detach", {}, 15_000);
    } catch (error) {
      this.bridgeError(error, "debug.detach", sessionId);
    }
    entry.attached = false;
    entry.pid = 0;
    entry.exited = false;
    return { detached: true, pid };
  }

  async close(sessionId: string): Promise<void> {
    const entry = this.sessions.get(sessionId);
    if (entry === undefined) {
      return;
    }
    this.sessions.delete(sessionId);
    // Best-effort in-debugger teardown first: attached targets are DETACHED
    // (left running), launched targets are STOPPED (killed with the session).
    if (entry.client.isConnected && !entry.exited) {
      try {
        if (entry.attached) {
          await entry.client.call("debug.detach", {}, 15_000);
        } else {
          await entry.client.call("debug.stop", {}, 5000);
        }
      } catch {
        // Fall through to process kill.
      }
    }
    await entry.client.disconnect().catch(() => undefined);
    killDebugger(entry);
  }

  /**
   * Spawn a hidden debugger + bridge for a session (shared by open/attach).
   * Registers the session before connecting so failures clean up via close().
   */
  private async spawnDebugger(
    sessionId: string,
    arch: X64Arch,
    debuggerExe: string,
    pythonHome: string,
    target: string,
    attached: boolean,
  ): Promise<OpenDebug> {
    const port = await pickFreePort();
    const token = randomUUID().replace(/-/g, "");
    const pythonEnv = arch === "x64" ? "PYTHON_HOME_X64" : "PYTHON_HOME_X86";
    const child = spawn(debuggerExe, [], {
      detached: true,
      stdio: "ignore",
      windowsHide: true,
      env: {
        ...process.env,
        BRIDGE_HOST: BRIDGE_HOST,
        BRIDGE_PORT: String(port),
        BRIDGE_AUTH_TOKEN: token,
        [pythonEnv]: pythonHome,
      },
    });
    const entry: OpenDebug = {
      child,
      client: new BridgeClient(BRIDGE_HOST, port, token),
      port,
      arch,
      target,
      pid: 0,
      attached,
      entryPoint: "",
      moduleBase: null,
      moduleEntry: null,
      openedAt: new Date().toISOString(),
      exited: false,
      debuggerExit: null,
      tail: Promise.resolve(),
    };
    child.once("error", () => {
      entry.debuggerExit = "spawn error";
    });
    child.once("exit", (code, signal) => {
      entry.debuggerExit = code === null ? `signal ${signal ?? "unknown"}` : `code ${code}`;
    });
    if (typeof child.unref === "function") {
      child.unref();
    }
    this.sessions.set(sessionId, entry);
    await waitForBridge(BRIDGE_HOST, port, x64dbgStartTimeoutMs());
    await entry.client.connect();
    return entry;
  }

  /**
   * Resolve the true main-module entry (load/attach report the system entry
   * point). Best-effort: module enumeration can fail on minimal or exiting
   * targets, and must not fail the open/attach itself.
   */
  private async resolveModuleEntry(entry: OpenDebug): Promise<void> {
    try {
      const main = await this.mainModule(entry);
      entry.moduleBase = main.base;
      entry.moduleEntry = main.entry;
    } catch {
      entry.moduleBase = null;
      entry.moduleEntry = null;
    }
  }

  isOpen(sessionId: string): boolean {
    return this.sessions.has(sessionId);
  }

  openPath(sessionId: string): string | undefined {
    return this.sessions.get(sessionId)?.target;
  }

  openArch(sessionId: string): X64Arch | undefined {
    return this.sessions.get(sessionId)?.arch;
  }

  /** Subscribe to async bridge pushes (stateChange/debugEvent) for a session. */
  onPush(sessionId: string, handler: BridgePushHandler): void {
    this.requireSession(sessionId).client.on("push", handler);
  }

  /**
   * Main-module info (base + true entry VA) via the bridge module list.
   * The debuggee must be loaded; match by target file name, else first .exe.
   */
  async mainModule(sessionId: string): Promise<MainModuleInfo>;
  async mainModule(entry: OpenDebug): Promise<MainModuleInfo>;
  async mainModule(sessionOrEntry: string | OpenDebug): Promise<MainModuleInfo> {
    const entry = typeof sessionOrEntry === "string" ? this.requireSession(sessionOrEntry) : sessionOrEntry;
    let res: Record<string, unknown>;
    try {
      res = await this.bridge<Record<string, unknown>>(entry, "analysis.getModules", {});
    } catch (error) {
      this.bridgeError(error, "analysis.getModules", entry.target);
    }
    const modules = Array.isArray(res.modules) ? res.modules : [];
    const want = entry.target.toLowerCase().replace(/\//g, "\\").split("\\").pop() ?? "";
    let pick: Record<string, unknown> | undefined;
    for (const mod of modules) {
      const rec = asRecord(mod);
      const path = asString(rec.path, "").toLowerCase().replace(/\//g, "\\");
      if (want !== "" && path.endsWith(`\\${want}`) || path === want) {
        pick = rec;
        break;
      }
    }
    if (pick === undefined) {
      for (const mod of modules) {
        const rec = asRecord(mod);
        if (asString(rec.path, "").toLowerCase().endsWith(".exe")) {
          pick = rec;
          break;
        }
      }
    }
    if (pick === undefined && modules.length > 0) {
      pick = asRecord(modules[0]);
    }
    if (pick === undefined) {
      throw new X64dbgError("engine_error", "bridge returned no modules for the debuggee");
    }
    return {
      name: asString(pick.name, ""),
      base: asString(pick.base, "0x0"),
      size: asString(pick.size, "0x0"),
      path: asString(pick.path, ""),
      entry: asString(pick.entry, "0x0"),
    };
  }

  private requireSession(sessionId: string): OpenDebug {
    const entry = this.sessions.get(sessionId);
    if (entry === undefined) {
      throw new X64dbgError(
        "target_not_open",
        `no target open for session ${sessionId}; call debug_open first`,
        { session_id: sessionId },
      );
    }
    if (entry.debuggerExit !== null) {
      throw new X64dbgError(
        "engine_error",
        `x64dbg process exited (${entry.debuggerExit}); call debug_open to start a new session`,
        { session_id: sessionId, exit: entry.debuggerExit },
      );
    }
    return entry;
  }

  /**
   * Serialize state-changing calls per session (the bridge is single-
   * threaded too); read-only calls bypass the queue so status stays
   * responsive during a long continue.
   */
  private bridge<T>(
    entry: OpenDebug,
    method: string,
    params: Record<string, unknown>,
    timeoutMs?: number,
  ): Promise<T> {
    if (isLocklessMethod(method)) {
      return entry.client.call<T>(method, params, timeoutMs);
    }
    const run = entry.tail.then(() => entry.client.call<T>(method, params, timeoutMs));
    entry.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private bridgeError(error: unknown, method: string, sessionId: string): never {
    if (error instanceof X64dbgError) {
      throw error;
    }
    throw new X64dbgError("engine_error", `bridge call failed: ${method}: ${String(error)}`, {
      session_id: sessionId,
      method,
    });
  }

  async state(sessionId: string): Promise<DebugState> {
    const entry = this.requireSession(sessionId);
    const base: DebugState = {
      sessionId,
      open: true,
      target: entry.target,
      arch: entry.arch,
      pid: entry.pid,
      attached: entry.attached,
      entryPoint: entry.entryPoint,
      moduleBase: entry.moduleBase,
      moduleEntry: entry.moduleEntry,
      openedAt: entry.openedAt,
      state: entry.exited ? "terminated" : "unknown",
      pauseReason: null,
      terminationReason: entry.exited ? "process_exit" : null,
    };
    if (entry.exited) {
      return base;
    }
    try {
      const live = await this.bridge<Record<string, unknown>>(entry, "debug.getState", {});
      return { ...base, ...pickLiveState(live) };
    } catch (error) {
      this.bridgeError(error, "debug.getState", sessionId);
    }
  }

  async setBreakpoint(sessionId: string, opts: SetBreakpointOptions): Promise<{ address: string; resolved: boolean }> {
    const entry = this.requireSession(sessionId);
    const address = normalizeAddress(opts.address, "address");
    const type = opts.type ?? "software";
    if (!BREAKPOINT_TYPES.has(type)) {
      throw new X64dbgError(
        "invalid_argument",
        `"type" must be one of ${[...BREAKPOINT_TYPES].join(", ")}; got ${JSON.stringify(type)}`,
      );
    }
    const params: Record<string, unknown> = { address, type };
    if (opts.condition !== undefined) {
      params.condition = opts.condition;
    }
    if (opts.logText !== undefined) {
      params.logText = opts.logText;
    }
    if (opts.name !== undefined) {
      params.name = opts.name;
    }
    try {
      const res = await this.bridge<Record<string, unknown>>(entry, "debug.setBreakpoint", params);
      return { address: asString(res.address, address), resolved: res.resolved !== false };
    } catch (error) {
      this.bridgeError(error, "debug.setBreakpoint", sessionId);
    }
  }

  async removeBreakpoint(sessionId: string, address: string | number): Promise<{ status: string }> {
    const entry = this.requireSession(sessionId);
    try {
      const res = await this.bridge<Record<string, unknown>>(
        entry,
        "debug.removeBreakpoint",
        { address: normalizeAddress(address, "address") },
      );
      return { status: asString(res.status, "removed") };
    } catch (error) {
      this.bridgeError(error, "debug.removeBreakpoint", sessionId);
    }
  }

  async listBreakpoints(sessionId: string): Promise<{ breakpoints: unknown[] }> {
    const entry = this.requireSession(sessionId);
    try {
      const res = await this.bridge<Record<string, unknown>>(entry, "debug.listBreakpoints", {});
      const list = Array.isArray(res.breakpoints) ? res.breakpoints : [];
      return { breakpoints: list };
    } catch (error) {
      this.bridgeError(error, "debug.listBreakpoints", sessionId);
    }
  }

  async continue_(sessionId: string, timeoutMs?: number): Promise<ContinueResult> {
    const entry = this.requireSession(sessionId);
    try {
      const res = await this.bridge<Record<string, unknown>>(
        entry,
        "debug.continue",
        {},
        timeoutMs ?? x64dbgContinueTimeoutMs(),
      );
      return await this.withExitOverride(entry, {
        reason: asString(res.reason, "paused"),
        address: asString(res.address, "0x0"),
      });
    } catch (error) {
      this.bridgeError(error, "debug.continue", sessionId);
    }
  }

  async pause(sessionId: string): Promise<ContinueResult> {
    const entry = this.requireSession(sessionId);
    try {
      const res = await this.bridge<Record<string, unknown>>(entry, "debug.pause", {}, 15_000);
      return await this.withExitOverride(entry, {
        reason: asString(res.reason, "paused"),
        address: asString(res.address, "0x0"),
      });
    } catch (error) {
      this.bridgeError(error, "debug.pause", sessionId);
    }
  }

  /**
   * Ground the stop reason in the OS process table. x32dbg's debugger flags
   * lag reality around process exit (observed: "paused" at 0x0 while the
   * debuggee is mid-teardown, gone a few seconds later), so a non-exit
   * reason with a dead pid is corrected to "exited". Breakpoint/step stops
   * imply a live debuggee and return immediately; a pause at a valid
   * address with a live pid is a genuine pause. Only the ambiguous case —
   * paused at 0x0 with a live pid — polls the pid (up to 10 s) to let the
   * teardown race settle. Unknown PIDs and query errors conservatively
   * keep the bridge's answer.
   */
  private async withExitOverride(entry: OpenDebug, result: ContinueResult): Promise<ContinueResult> {
    if (result.reason === "exited") {
      entry.exited = true;
      return result;
    }
    if (entry.pid <= 0 || result.reason === "breakpoint" || result.reason === "single_step") {
      return result;
    }
    if (!isPidAlive(entry.pid)) {
      entry.exited = true;
      return { reason: "exited", address: "0x0" };
    }
    if (safeParseAddress(result.address) !== 0) {
      return result;
    }
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 250));
      if (!isPidAlive(entry.pid)) {
        entry.exited = true;
        return { reason: "exited", address: "0x0" };
      }
    }
    return result;
  }

  async step(sessionId: string, kind: "into" | "over", count = 1): Promise<StepResult> {
    const entry = this.requireSession(sessionId);
    if (kind !== "into" && kind !== "over") {
      throw new X64dbgError("invalid_argument", `"kind" must be "into" or "over"; got ${JSON.stringify(kind)}`);
    }
    if (!Number.isInteger(count) || count < 1 || count > 1000) {
      throw new X64dbgError("invalid_argument", `"count" must be an integer 1..1000`);
    }
    const method = kind === "into" ? "debug.stepInto" : "debug.stepOver";
    try {
      const res = await this.bridge<Record<string, unknown>>(
        entry,
        method,
        { count },
        Math.min(30_000 + count * 5000, x64dbgContinueTimeoutMs()),
      );
      return {
        address: asString(res.address, "0x0"),
        ...(typeof res.disassembly === "string" ? { disassembly: res.disassembly } : {}),
        ...(typeof res.module === "string" ? { module: res.module } : {}),
        ...(typeof res.function === "string" ? { function: res.function } : {}),
        ...(typeof res.registers === "object" && res.registers !== null
          ? { registers: res.registers as Record<string, string> }
          : {}),
      };
    } catch (error) {
      this.bridgeError(error, method, sessionId);
    }
  }

  async registers(
    sessionId: string,
    opts: { includeSegment?: boolean; includeDebug?: boolean } = {},
  ): Promise<RegisterSet> {
    const entry = this.requireSession(sessionId);
    try {
      const res = await this.bridge<Record<string, unknown>>(entry, "registers.get", {
        ...(opts.includeSegment ? { includeSegment: true } : {}),
        ...(opts.includeDebug ? { includeDebug: true } : {}),
      });
      return {
        general: asRecord(res.general) as Record<string, string>,
        flags: asRecord(res.flags) as unknown as Record<string, boolean>,
        ...(res.segment !== undefined ? { segment: asRecord(res.segment) as Record<string, string> } : {}),
        ...(res.debug !== undefined ? { debug: asRecord(res.debug) as Record<string, string> } : {}),
      };
    } catch (error) {
      this.bridgeError(error, "registers.get", sessionId);
    }
  }

  async callStack(sessionId: string, maxFrames = 50): Promise<CallStack> {
    const entry = this.requireSession(sessionId);
    if (!Number.isInteger(maxFrames) || maxFrames < 1 || maxFrames > 500) {
      throw new X64dbgError("invalid_argument", `"max_frames" must be an integer 1..500`);
    }
    try {
      const res = await this.bridge<Record<string, unknown>>(entry, "stack.getCallStack", {
        maxFrames,
      });
      const frames = Array.isArray(res.frames) ? res.frames : [];
      return {
        threadId: typeof res.threadId === "number" ? res.threadId : 0,
        frames: frames.map((frame, index): CallFrame => {
          const rec = asRecord(frame);
          return {
            index: typeof rec.index === "number" ? rec.index : index,
            address: asString(rec.address, "0x0"),
            ...(typeof rec.returnAddress === "string" ? { returnAddress: rec.returnAddress } : {}),
            ...(typeof rec.module === "string" ? { module: rec.module } : {}),
            ...(typeof rec.function === "string" ? { function: rec.function } : {}),
          };
        }),
      };
    } catch (error) {
      this.bridgeError(error, "stack.getCallStack", sessionId);
    }
  }

  /** Raw bridge call for live memory, code, and thread operations. */
  async bridgeCall<T>(
    sessionId: string,
    method: string,
    params: Record<string, unknown> = {},
    timeoutMs?: number,
  ): Promise<T> {
    const entry = this.requireSession(sessionId);
    try {
      return await this.bridge<T>(entry, method, params, timeoutMs);
    } catch (error) {
      this.bridgeError(error, method, sessionId);
    }
  }
}

/** Parse a bridge address; unparseable values stay nonzero (conservative). */
function safeParseAddress(address: string): number {
  const parsed = parseInt(address, 16);
  return Number.isNaN(parsed) ? 1 : parsed;
}

/** Signal-0 existence probe. EPERM (alive, denied) counts as alive. */
function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | null)?.code;
    if (code === "ESRCH") {
      return false;
    }
    return true;
  }
}

function pickLiveState(live: Record<string, unknown>): DebugLiveState {
  return {
    state: asString(live.state, "unknown"),
    pauseReason: asNullableString(live.pauseReason),
    terminationReason: asNullableString(live.terminationReason),
  };
}

function killDebugger(entry: OpenDebug): void {
  if (process.env.KEEP_DEBUGGER === "1") {
    return;
  }
  const pid = entry.child.pid;
  try {
    entry.child.kill();
  } catch {
    // Already gone; fall through to the tree kill below.
  }
  if (process.platform === "win32" && typeof pid === "number") {
    // Tree-kill so a surviving debuggee (child of x64dbg) dies too.
    try {
      spawnSync("taskkill", ["/pid", String(pid), "/T", "/F"], { windowsHide: true, timeout: 10_000 });
    } catch {
      // Best effort only.
    }
  }
}

/** Process-wide engine shared by stdio and every stateless HTTP request. */
export const x64dbgEngine = new X64dbgEngine();
