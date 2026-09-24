import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { open as fsOpen, stat } from "node:fs/promises";
import { basename, dirname, join, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

import {
  attach,
  getDeviceManager,
  getUsbDevice,
  kill,
  resume,
  spawn,
  SessionDetachReason,
  type Device,
  type Script,
  type Session,
} from "frida";

import type { Capabilities, DebugEngine } from "./types.js";
import type {
  AttachOptions,
  BreakpointType,
  BridgePushHandler,
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
 * Windowless Frida adapter. One injected script per application session.
 *
 * Spawn follows the installed frida 17.18.0 typing:
 * `spawn(program: string | string[], options?: SpawnOptions): Promise<number>`.
 * The new process stays suspended until `resume(pid)`.
 *
 * Hardware execute breakpoints are slots 0..3 on the main thread. The guest
 * API accepts slot 4 without throwing and then does not trap, so a fifth
 * breakpoint is refused here as `no_breakpoint_slot`.
 *
 * Registers and the call stack are the last exception context (`send` from
 * the guest), not a live read. Continuing past that hit disarms the slot:
 * CpuContext has no rflags field, and leaving the breakpoint armed re-traps
 * the same instruction. `step` and `pause` have no API (`Thread.sleep` only)
 * and answer `capability_unsupported`.
 *
 * When pid attach is impossible, `attachRemote` connects to a Frida Gadget
 * already listening (`host:port`, process name defaults to `Gadget`) or to
 * a running mobile package on a USB device. Both are detach-only.
 */
export const fridaCapabilities: Capabilities = {
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

export type FridaErrorCode =
  | "engine_unavailable"
  | "invalid_target"
  | "target_not_open"
  | "invalid_argument"
  | "engine_timeout"
  | "engine_error"
  | "capability_unsupported"
  | "no_breakpoint_slot";

export class FridaError extends Error {
  readonly code: FridaErrorCode;
  readonly data?: Record<string, unknown>;

  constructor(code: FridaErrorCode, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "FridaError";
    this.code = code;
    this.data = data;
  }
}

const DEFAULT_TIMEOUT_MS = 30_000;
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

export function fridaTimeoutMs(): number {
  return envTimeout("DBG_BRIDGE_FRIDA_TIMEOUT_MS", DEFAULT_TIMEOUT_MS);
}

interface AgentInfo {
  arch: X64Arch;
  moduleBase: string;
  entry: string;
  module: string;
  path: string;
}

interface HitFrame {
  index: number;
  address: string;
  module: string | null;
}

interface HitMessage {
  type: "breakpoint_hit";
  exception: string;
  address: string;
  threadId: number;
  arch: string;
  general: Record<string, string>;
  frames: HitFrame[];
}

interface AgentExports {
  describe(): Promise<AgentInfo>;
  setBreakpoint(address: string): Promise<{ address: string; slot: number }>;
  removeBreakpoint(address: string): Promise<{ removed: boolean; address: string }>;
  listBreakpoints(): Promise<Array<{ slot: number; address: string; type: string; enabled: boolean }>>;
}

type Phase = "suspended" | "running" | "stopped" | "exited";

interface StopWaiter {
  resolve: (result: ContinueResult) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

interface FridaSession {
  pid: number;
  attached: boolean;
  target: string;
  arch: X64Arch;
  entryPoint: string;
  moduleBase: string;
  moduleEntry: string;
  openedAt: string;
  phase: Phase;
  pauseReason: string | null;
  lastHit: HitMessage | null;
  script: Script;
  session: Session;
  waiter: StopWaiter | null;
  closing: boolean;
  pushes: BridgePushHandler[];
  /** Set when the session came from DeviceManager.addRemoteDevice. */
  remoteAddress: string | null;
}

function agentSource(targetName: string): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "frida-agent.js"),
    join(here, "..", "..", "src", "engines", "frida-agent.js"),
  ];
  for (const path of candidates) {
    try {
      const body = readFileSync(path, "utf8");
      return `const TARGET_NAME = ${JSON.stringify(targetName)};\n${body}`;
    } catch {
      // Try the next location (dist vs src).
    }
  }
  throw new FridaError("engine_unavailable", "frida agent script is missing (src/engines/frida-agent.js)");
}

function normalizeAddress(value: string | number): string {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
      throw new FridaError("invalid_argument", `"address" must be a non-negative integer`);
    }
    return `0x${value.toString(16)}`;
  }
  const trimmed = value.trim();
  if (!/^0x[0-9a-fA-F]+$/.test(trimmed) && !/^[0-9]+$/.test(trimmed)) {
    throw new FridaError(
      "invalid_argument",
      `"address" must be hex (0x...) or decimal; got ${JSON.stringify(trimmed)}`,
    );
  }
  return `0x${BigInt(trimmed).toString(16)}`;
}

function parseGadgetAddress(raw: string): string {
  const trimmed = raw.trim();
  const match = /^(.+):(\d+)$/.exec(trimmed);
  const port = match === null ? Number.NaN : Number(match[2]);
  if (match === null || trimmed.length > 256 || /[\s;|&]/.test(trimmed) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new FridaError(
      "invalid_argument",
      `gadget must be host:port; got ${JSON.stringify(raw)}`,
    );
  }
  return trimmed;
}

function parsePackageName(raw: string): string {
  const trimmed = raw.trim();
  if (!/^[A-Za-z0-9._-]{1,256}$/.test(trimmed)) {
    throw new FridaError(
      "invalid_argument",
      `package must be a process or bundle id; got ${JSON.stringify(raw)}`,
    );
  }
  return trimmed;
}

async function findRemoteProcess(device: Device, name: string, address: string): Promise<{ pid: number; name: string }> {
  try {
    const proc = await device.getProcess(name);
    return { pid: proc.pid, name: proc.name };
  } catch (error) {
    let saw = "";
    try {
      const list = await device.enumerateProcesses();
      saw = list.slice(0, 8).map((proc) => proc.name).join(", ");
    } catch {
      saw = error instanceof Error ? error.message : String(error);
    }
    throw new FridaError("engine_unavailable", `no process '${name}' on gadget at ${address}`, {
      address,
      package: name,
      saw,
    });
  }
}

function mapAgentError(error: unknown): FridaError {
  if (error instanceof FridaError) {
    return error;
  }
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("capability_unsupported")) {
    return new FridaError("capability_unsupported", message);
  }
  if (message.includes("no_breakpoint_slot")) {
    return new FridaError("no_breakpoint_slot", "no hardware breakpoint slot is free (slots 0..3)", {
      slots: 4,
    });
  }
  if (message.includes("missing breakpoint")) {
    return new FridaError("invalid_argument", message);
  }
  return new FridaError("engine_error", message);
}

async function readPeMachine(pePath: string): Promise<number> {
  let handle;
  try {
    handle = await fsOpen(pePath, "r");
  } catch {
    throw new FridaError("invalid_target", `target not found: ${pePath}`);
  }
  try {
    const dos = Buffer.alloc(64);
    if ((await handle.read(dos, 0, 64, 0)).bytesRead < 64 || dos.readUInt16LE(0) !== 0x5a4d) {
      throw new FridaError("invalid_target", `not a valid PE file (bad MZ signature): ${pePath}`);
    }
    const peOffset = dos.readUInt32LE(0x3c);
    if (peOffset > 1024 * 1024) {
      throw new FridaError("invalid_target", `not a valid PE file (e_lfanew out of range): ${pePath}`);
    }
    const head = Buffer.alloc(6);
    if ((await handle.read(head, 0, 6, peOffset)).bytesRead < 6) {
      throw new FridaError("invalid_target", `not a valid PE file (truncated headers): ${pePath}`);
    }
    if (head.readUInt32LE(0) !== 0x00004550) {
      throw new FridaError("invalid_target", `not a valid PE file (bad PE signature): ${pePath}`);
    }
    return head.readUInt16LE(4);
  } finally {
    await handle.close();
  }
}

export async function detectPeArch(targetPath: string): Promise<X64Arch> {
  const trimmed = targetPath.trim();
  if (trimmed === "" || trimmed.startsWith("-")) {
    throw new FridaError("invalid_target", `refusing to open target: ${JSON.stringify(targetPath)}`);
  }
  const absolute = resolvePath(trimmed);
  try {
    if (!(await stat(absolute)).isFile()) {
      throw new FridaError("invalid_target", `target is not a file: ${trimmed}`);
    }
  } catch (error) {
    if (error instanceof FridaError) {
      throw error;
    }
    throw new FridaError("invalid_target", `target not found: ${trimmed}`);
  }
  const machine = await readPeMachine(absolute);
  if (machine === IMAGE_FILE_MACHINE_I386) {
    return "x86";
  }
  if (machine === IMAGE_FILE_MACHINE_AMD64) {
    return "x64";
  }
  if (machine === IMAGE_FILE_MACHINE_ARM64 || machine === IMAGE_FILE_MACHINE_ARMNT) {
    throw new FridaError("invalid_target", `ARM PE detected (machine 0x${machine.toString(16)})`, {
      machine: `0x${machine.toString(16)}`,
    });
  }
  throw new FridaError("invalid_target", `unsupported PE machine type 0x${machine.toString(16)}: ${trimmed}`, {
    machine: `0x${machine.toString(16)}`,
  });
}

export async function getProcessExePath(pid: number): Promise<string> {
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new FridaError("invalid_argument", `"pid" must be a positive integer; got ${JSON.stringify(pid)}`);
  }
  if (pid === process.pid) {
    throw new FridaError("invalid_argument", "cannot attach to the bridge's own process");
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
    throw new FridaError("invalid_target", `no accessible process with pid ${pid}`, { pid });
  }
  return stdout;
}

function isHitMessage(value: unknown): value is HitMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const rec = value as Record<string, unknown>;
  return rec.type === "breakpoint_hit" && typeof rec.address === "string" && Array.isArray(rec.frames);
}

function exportsOf(script: Script): AgentExports {
  return script.exports as unknown as AgentExports;
}

/** Live debugger engine. One Frida session per application session. */
export class FridaEngine implements DebugEngine {
  readonly id = "frida" as const;
  readonly capabilities = fridaCapabilities;
  private readonly sessions = new Map<string, FridaSession>();

  async open(sessionId: string, target: string, opts: OpenDebugOptions = {}): Promise<DebugTargetInfo> {
    this.rejectUnsupportedOpen(sessionId, opts);
    if (process.platform !== "win32") {
      throw new FridaError("engine_unavailable", `frida launch requires Windows (platform: ${process.platform})`);
    }
    const absolute = resolvePath(target.trim());
    await detectPeArch(absolute);
    await this.close(sessionId);
    let pid: number;
    try {
      pid = await spawn(absolute);
    } catch (error) {
      throw mapAgentError(error);
    }
    try {
      const held = await this.inject(
        sessionId,
        pid,
        absolute,
        false,
        opts.breakOnEntry === false ? "running" : "suspended",
        null,
      );
      if (opts.breakOnEntry === false) {
        held.phase = "running";
        held.pauseReason = null;
        await resume(pid);
      }
      return this.targetInfo(held);
    } catch (error) {
      await this.close(sessionId);
      try {
        await kill(pid);
      } catch {
        // Already gone.
      }
      throw error instanceof FridaError ? error : mapAgentError(error);
    }
  }

  async attach(sessionId: string, pid: number, opts: AttachOptions = {}): Promise<DebugTargetInfo> {
    if (sessionId.trim() === "") {
      throw new FridaError("invalid_argument", "session id must not be empty");
    }
    if (process.platform !== "win32") {
      throw new FridaError("engine_unavailable", `frida attach requires Windows (platform: ${process.platform})`);
    }
    if (opts.breakOnEntry === false) {
      throw new FridaError(
        "capability_unsupported",
        "frida attach cannot suspend the target; break_on_entry=false is not a distinct mode",
      );
    }
    if (opts.autoAnalyze === true) {
      throw new FridaError("capability_unsupported", "frida does not implement auto_analyze");
    }
    const exePath = await getProcessExePath(pid);
    await detectPeArch(exePath);
    await this.close(sessionId);
    const held = await this.inject(sessionId, pid, exePath, true, "running", null);
    return this.targetInfo(held);
  }

  /**
   * Connect to a target that cannot be attached by pid.
   * `gadget` is a listen address (`127.0.0.1:27042`). `usb` uses the phone
   * or tablet on USB. `packageName` is the process or bundle id (`Gadget`
   * when a listen address omits it).
   */
  async attachRemote(
    sessionId: string,
    spec: { gadget?: string; usb?: boolean; packageName?: string },
  ): Promise<DebugTargetInfo> {
    if (sessionId.trim() === "") {
      throw new FridaError("invalid_argument", "session id must not be empty");
    }
    if (process.platform !== "win32") {
      throw new FridaError("engine_unavailable", `frida requires Windows (platform: ${process.platform})`);
    }
    if (spec.gadget !== undefined && spec.usb === true) {
      throw new FridaError("invalid_argument", "pass either gadget or usb, not both");
    }
    if (spec.gadget === undefined && spec.usb !== true) {
      throw new FridaError("invalid_argument", "gadget address or usb is required");
    }
    await this.close(sessionId);
    if (spec.usb === true) {
      return this.attachUsbPackage(sessionId, spec.packageName);
    }
    return this.attachGadgetListen(sessionId, spec.gadget ?? "", spec.packageName ?? "Gadget");
  }

  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session === undefined) {
      return;
    }
    this.sessions.delete(sessionId);
    session.closing = true;
    this.settleWaiter(session, { reason: "exited", address: "0x0" });
    try {
      await session.script.unload();
    } catch {
      // Script may already be destroyed.
    }
    try {
      await session.session.detach();
    } catch {
      // Already detached.
    }
    if (!session.attached) {
      try {
        await kill(session.pid);
      } catch {
        // Process already exited.
      }
    }
    if (session.remoteAddress !== null) {
      try {
        await getDeviceManager().removeRemoteDevice(session.remoteAddress);
      } catch {
        // Device entry may already be gone.
      }
    }
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
    const paused = session.phase === "suspended" || session.phase === "stopped";
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
      state: session.phase === "exited" ? "terminated" : paused ? "paused" : "running",
      pauseReason: session.phase === "exited" ? null : session.pauseReason,
      terminationReason: session.phase === "exited" ? "process_exit" : null,
    };
  }

  async setBreakpoint(sessionId: string, opts: SetBreakpointOptions): Promise<{ address: string; resolved: boolean }> {
    const session = this.requireLive(sessionId);
    if (opts.condition !== undefined || opts.logText !== undefined || opts.name !== undefined) {
      throw new FridaError("capability_unsupported", "frida breakpoints do not implement condition, log_text, or name");
    }
    const type = opts.type ?? "software";
    this.requireHardwareExecute(type);
    const address = normalizeAddress(opts.address);
    try {
      const set = await exportsOf(session.script).setBreakpoint(address);
      return { address: set.address, resolved: true };
    } catch (error) {
      throw mapAgentError(error);
    }
  }

  async removeBreakpoint(sessionId: string, address: string | number): Promise<{ status: string }> {
    const session = this.requireLive(sessionId);
    const canonical = normalizeAddress(address);
    try {
      await exportsOf(session.script).removeBreakpoint(canonical);
      return { status: "removed" };
    } catch (error) {
      throw mapAgentError(error);
    }
  }

  async listBreakpoints(sessionId: string): Promise<{ breakpoints: unknown[] }> {
    const session = this.requireLive(sessionId);
    try {
      const rows = await exportsOf(session.script).listBreakpoints();
      return { breakpoints: rows };
    } catch (error) {
      throw mapAgentError(error);
    }
  }

  async continue_(sessionId: string, timeoutMs?: number): Promise<ContinueResult> {
    const session = this.requireSession(sessionId);
    if (session.phase === "exited") {
      return { reason: "exited", address: "0x0" };
    }
    const pending = this.expectStop(session, timeoutMs ?? fridaTimeoutMs());
    try {
      if (session.phase === "suspended") {
        session.phase = "running";
        session.pauseReason = null;
        await resume(session.pid);
      } else if (session.phase === "stopped") {
        session.phase = "running";
        session.pauseReason = null;
        session.script.post({ type: "resume" });
      }
    } catch (error) {
      this.failWaiter(session, mapAgentError(error));
    }
    return pending;
  }

  async pause(sessionId: string): Promise<ContinueResult> {
    this.requireSession(sessionId);
    throw new FridaError(
      "capability_unsupported",
      "frida has no thread-suspend API (only Thread.sleep); pause is not implemented",
    );
  }

  async step(sessionId: string, kind: "into" | "over", _count = 1): Promise<StepResult> {
    this.requireSession(sessionId);
    throw new FridaError("capability_unsupported", `frida has no single-step API; step ${kind} is not implemented`);
  }

  async registers(
    sessionId: string,
    opts: { includeSegment?: boolean; includeDebug?: boolean } = {},
  ): Promise<RegisterSet> {
    const session = this.requireLive(sessionId);
    if (opts.includeSegment === true || opts.includeDebug === true) {
      throw new FridaError(
        "capability_unsupported",
        "frida registers are the general registers from the last hardware-breakpoint hit",
      );
    }
    if (session.lastHit === null) {
      throw new FridaError("engine_error", "no hardware breakpoint has been hit yet; frida registers come from that hit", {
        session_id: sessionId,
      });
    }
    return { general: session.lastHit.general, flags: {} };
  }

  async callStack(sessionId: string, maxFrames = 50): Promise<CallStack> {
    const session = this.requireLive(sessionId);
    if (!Number.isInteger(maxFrames) || maxFrames < 1 || maxFrames > 500) {
      throw new FridaError("invalid_argument", `"max_frames" must be an integer 1..500`);
    }
    if (session.lastHit === null) {
      throw new FridaError("engine_error", "no hardware breakpoint has been hit yet; frida call stack comes from that hit", {
        session_id: sessionId,
      });
    }
    return {
      threadId: session.lastHit.threadId,
      frames: session.lastHit.frames.slice(0, maxFrames).map((frame) => ({
        index: frame.index,
        address: frame.address,
        ...(frame.module !== null ? { module: frame.module } : {}),
      })),
    };
  }

  private rejectUnsupportedOpen(sessionId: string, opts: OpenDebugOptions): void {
    if (sessionId.trim() === "") {
      throw new FridaError("invalid_argument", "session id must not be empty");
    }
    if (opts.autoAnalyze === true) {
      throw new FridaError("capability_unsupported", "frida does not implement auto_analyze");
    }
    if (opts.commandLineArgs !== undefined && opts.commandLineArgs !== "") {
      throw new FridaError("capability_unsupported", "frida does not implement command_line_args yet");
    }
  }

  private requireHardwareExecute(type: BreakpointType): void {
    switch (type) {
      case "hardware_execute":
        return;
      case "software":
      case "hardware_read":
      case "hardware_write":
      case "hardware_access":
      case "memory_read":
      case "memory_write":
      case "memory_access":
        throw new FridaError("capability_unsupported", `frida breakpoints support hardware_execute only; got ${type}`);
      default: {
        const unreachable: never = type;
        throw new FridaError("invalid_argument", `unsupported breakpoint type ${String(unreachable)}`);
      }
    }
  }

  private async attachGadgetListen(sessionId: string, gadget: string, packageName: string): Promise<DebugTargetInfo> {
    const address = parseGadgetAddress(gadget);
    const name = parsePackageName(packageName);
    const manager = getDeviceManager();
    let device;
    try {
      device = await manager.addRemoteDevice(address);
    } catch (error) {
      throw new FridaError("engine_unavailable", `frida gadget is not listening at ${address}`, {
        address,
        detail: error instanceof Error ? error.message : String(error),
      });
    }
    try {
      const proc = await findRemoteProcess(device, name, address);
      const fridaSession = await device.attach(proc.pid);
      const held = await this.inject(sessionId, proc.pid, `${name}@${address}`, true, "running", address, fridaSession);
      return this.targetInfo(held);
    } catch (error) {
      await this.close(sessionId);
      try {
        await manager.removeRemoteDevice(address);
      } catch {
        // Already removed by close, or never registered.
      }
      throw error instanceof FridaError ? error : mapAgentError(error);
    }
  }

  private async attachUsbPackage(sessionId: string, packageName: string | undefined): Promise<DebugTargetInfo> {
    if (packageName === undefined) {
      throw new FridaError("invalid_argument", "usb attach requires package (bundle id or process name)");
    }
    const name = parsePackageName(packageName);
    let device;
    try {
      device = await getUsbDevice({ timeout: 8_000 });
    } catch (error) {
      throw new FridaError("engine_unavailable", "no USB device with frida-server or a loaded Gadget", {
        detail: error instanceof Error ? error.message : String(error),
      });
    }
    const apps = await device.enumerateApplications();
    const app = apps.find((entry) => entry.identifier === name || entry.name === name);
    if (app === undefined) {
      const sample = apps.slice(0, 8).map((entry) => entry.identifier).join(", ");
      throw new FridaError("engine_unavailable", `package ${name} is not installed on the USB device`, {
        package: name,
        saw: sample,
      });
    }
    if (app.pid === 0) {
      throw new FridaError("engine_unavailable", `package ${name} is installed but not running`, { package: name });
    }
    try {
      const fridaSession = await device.attach(app.pid);
      const held = await this.inject(sessionId, app.pid, app.identifier, true, "running", null, fridaSession);
      return this.targetInfo(held);
    } catch (error) {
      await this.close(sessionId);
      throw error instanceof FridaError ? error : mapAgentError(error);
    }
  }

  private async inject(
    sessionId: string,
    pid: number,
    target: string,
    attached: boolean,
    phase: Phase,
    remoteAddress: string | null,
    existing?: Session,
  ): Promise<FridaSession> {
    const fridaSession = existing ?? (await attach(pid));
    const held: FridaSession = {
      pid,
      attached,
      target,
      arch: "x64",
      entryPoint: "",
      moduleBase: "",
      moduleEntry: "",
      openedAt: new Date().toISOString(),
      phase,
      pauseReason: phase === "suspended" ? "spawned" : null,
      lastHit: null,
      script: null as unknown as Script,
      session: fridaSession,
      waiter: null,
      closing: false,
      pushes: [],
      remoteAddress,
    };
    this.sessions.set(sessionId, held);
    fridaSession.detached.connect((reason) => {
      this.onDetached(held, reason);
    });
    const script = await fridaSession.createScript(agentSource(basename(target)));
    held.script = script;
    script.message.connect((message) => {
      this.onScriptMessage(held, message);
    });
    await script.load();
    let info: AgentInfo;
    try {
      info = await exportsOf(script).describe();
    } catch (error) {
      throw mapAgentError(error);
    }
    if (info.arch !== "x64" && info.arch !== "x86") {
      throw new FridaError("invalid_target", `frida reported unsupported arch ${info.arch}`, { arch: info.arch });
    }
    held.arch = info.arch;
    held.entryPoint = info.entry;
    held.moduleBase = info.moduleBase;
    held.moduleEntry = info.entry;
    if (info.path !== "") {
      held.target = info.path;
    }
    return held;
  }

  private targetInfo(session: FridaSession): DebugTargetInfo {
    return {
      pid: session.pid,
      architecture: session.arch,
      entryPoint: session.entryPoint,
      moduleBase: session.moduleBase,
      moduleEntry: session.moduleEntry,
      attached: session.attached,
    };
  }

  private expectStop(session: FridaSession, timeoutMs: number): Promise<ContinueResult> {
    if (session.waiter !== null) {
      return Promise.reject(new FridaError("engine_error", "a continue is already waiting"));
    }
    return new Promise<ContinueResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        session.waiter = null;
        reject(new FridaError("engine_timeout", `frida wait timed out after ${timeoutMs}ms`, { pid: session.pid }));
      }, timeoutMs);
      session.waiter = { resolve, reject, timer };
    });
  }

  private settleWaiter(session: FridaSession, result: ContinueResult): void {
    const waiter = session.waiter;
    if (waiter === null) {
      return;
    }
    session.waiter = null;
    clearTimeout(waiter.timer);
    waiter.resolve(result);
  }

  private failWaiter(session: FridaSession, error: Error): void {
    const waiter = session.waiter;
    if (waiter === null) {
      return;
    }
    session.waiter = null;
    clearTimeout(waiter.timer);
    waiter.reject(error);
  }

  private onScriptMessage(session: FridaSession, message: { type: string; payload?: unknown; description?: string }): void {
    if (message.type === "error") {
      this.failWaiter(session, new FridaError("engine_error", message.description ?? "frida script error"));
      return;
    }
    if (message.type !== "send" || !isHitMessage(message.payload)) {
      if (message.type === "send") {
        this.emit(session, "debugEvent", message.payload ?? null);
      }
      return;
    }
    const hit = message.payload;
    session.lastHit = hit;
    session.phase = "stopped";
    session.pauseReason = "breakpoint";
    this.emit(session, "debugEvent", hit);
    this.settleWaiter(session, { reason: "breakpoint", address: hit.address });
  }

  private onDetached(session: FridaSession, reason: SessionDetachReason): void {
    if (session.closing) {
      return;
    }
    if (reason === SessionDetachReason.ProcessTerminated) {
      session.phase = "exited";
      session.pauseReason = null;
      this.settleWaiter(session, { reason: "exited", address: "0x0" });
      return;
    }
    this.failWaiter(session, new FridaError("engine_error", `frida detached: ${reason}`, { reason }));
  }

  private emit(session: FridaSession, type: "stateChange" | "debugEvent", payload: unknown): void {
    for (const handler of session.pushes) {
      handler(type, payload);
    }
  }

  async callAgent<T>(sessionId: string, method: string, args: unknown[] = []): Promise<T> {
    const session = this.requireLive(sessionId);
    const table = exportsOf(session.script) as unknown as Record<string, ((...fnArgs: unknown[]) => Promise<T>) | undefined>;
    const fn = table[method];
    if (typeof fn !== "function") {
      throw new FridaError("capability_unsupported", `frida agent has no ${method}`);
    }
    try {
      return await fn(...args);
    } catch (error) {
      throw mapAgentError(error);
    }
  }

  private requireSession(sessionId: string): FridaSession {
    const session = this.sessions.get(sessionId);
    if (session === undefined) {
      throw new FridaError("target_not_open", `no target open for session ${sessionId}; call debug_open first`, {
        session_id: sessionId,
      });
    }
    return session;
  }

  private requireLive(sessionId: string): FridaSession {
    const session = this.requireSession(sessionId);
    if (session.phase === "exited") {
      throw new FridaError("engine_error", "debuggee has exited", { session_id: sessionId });
    }
    return session;
  }
}

export const fridaEngine = new FridaEngine();
