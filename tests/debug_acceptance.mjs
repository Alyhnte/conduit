#!/usr/bin/env node
/**
 * Debug acceptance for Conduit (fixture: plugin/x64dbg/test/mini_pe_x64.exe).
 *
 * What it checks (live hidden x64dbg, real ctypes bridge):
 *  1. determinism — gen_mini_pe.py regenerates both fixtures byte-for-byte
 *  2. engine      — PE arch auto-detect (x64 + x86), install resolution,
 *                   ELF rejection
 *  3. e2e stdio   — per arch (x64, then x86 when its runtime exists):
 *                   session_open(x64dbg) -> debug_open -> set bp at
 *                   module_entry+5 -> continue x2 (entry bp, then OUR bp) ->
 *                   registers (acc == 0x1234 proves real execution) ->
 *                   callstack -> step -> pause (idempotent) -> remove bp ->
 *                   continue to process exit -> events_pull chain ->
 *                   debug_state terminated -> debug_close -> session_close
 *  4. negatives   — debug tools on radare2/unknown sessions, missing address,
 *                   attach to bogus pid / own process
 *  5. attach e2e  — per arch (x64, then x86 when its runtime exists):
 *                   spawn sleeper -> debug_attach -> pid/arch match ->
 *                   registers readable -> debug_close detaches (sleeper
 *                   still alive) -> session_close, no debugger leftovers
 *
 * Usage:  node tests/debug_acceptance.mjs   (== npm run test:debug)
 * Prereqs: Windows, `npm run build`, portable x64dbg (X64DBG_DIR or
 * %USERPROFILE%/Tools/x64dbg), 64-bit Python 3.10+ with iced_x86 installed.
 * Env: X64DBG_DIR, PYTHON_HOME_X64 (same as the engine).
 */
import { spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_JS = join(ROOT, "dist", "server.js");
const X64_ENGINE_JS = join(ROOT, "dist", "engines", "x64dbg.js");
const TEST_DIR = join(ROOT, "plugin", "x64dbg", "test");
const GEN_SCRIPT = join(TEST_DIR, "gen_mini_pe.py");
const FIX_X64 = join(TEST_DIR, "mini_pe_x64.exe");
const FIX_X86 = join(TEST_DIR, "mini_pe_x86.exe");
const ELF = join(ROOT, "examples", "target", "mini_branch.elf");
const PROTOCOL = "2026-07-28";
// Fixtures link at fixed bases (no ASLR): entries are deterministic
// (x64: base 0x140000000 + 0x1000, x86: base 0x400000 + 0x1000).

let failures = 0;
let passes = 0;

function pass(name) {
  passes += 1;
  console.log(`ok   ${name}`);
}

function fail(name, detail) {
  failures += 1;
  console.log(`FAIL ${name}`);
  for (const line of String(detail).split("\n").slice(0, 12)) {
    console.log(`     ${line}`);
  }
}

function assertEqual(name, actual, expected) {
  const a = JSON.stringify(actual) ?? String(actual);
  const e = JSON.stringify(expected) ?? String(expected);
  if (a === e) {
    pass(name);
    return true;
  }
  fail(name, `expected: ${e.slice(0, 400)}\nactual:   ${a.slice(0, 400)}`);
  return false;
}

function checkPrereqs() {
  const problems = [];
  if (process.platform !== "win32") {
    problems.push(`Windows-only (platform: ${process.platform})`);
  }
  for (const [label, path] of [
    ["dist/server.js", SERVER_JS],
    ["dist/engines/x64dbg.js", X64_ENGINE_JS],
    ["fixture x64", FIX_X64],
    ["fixture x86", FIX_X86],
    ["generator", GEN_SCRIPT],
  ]) {
    try {
      readFileSync(path);
    } catch {
      problems.push(`${label} missing (${path})`);
    }
  }
  const py = spawnSync("python", ["--version"], { encoding: "utf8" });
  if (py.status !== 0) {
    problems.push("python not on PATH");
  } else {
    const iced = spawnSync("python", ["-c", "import iced_x86"], { encoding: "utf8" });
    if (iced.status !== 0) {
      problems.push("python package iced_x86 missing (python -m pip install iced_x86)");
    }
  }
  if (problems.length > 0) {
    console.log("prereq check FAILED:");
    for (const p of problems) console.log(`  - ${p}`);
    process.exit(2);
  }
  pass("prereqs (win32, dist built, fixtures, python+iced_x86)");
}

// ---------------------------------------------------------------------------
// 1. determinism
// ---------------------------------------------------------------------------

function checkDeterminism() {
  const dir = mkdtempSync(join(tmpdir(), "mini-pe-"));
  const res = spawnSync("python", [GEN_SCRIPT, dir], { encoding: "utf8" });
  if (res.status !== 0) {
    fail("determinism: generator runs", res.stderr || `exit ${res.status}`);
    return;
  }
  for (const name of ["mini_pe_x64.exe", "mini_pe_x86.exe"]) {
    const fresh = readFileSync(join(dir, name));
    const committed = readFileSync(join(TEST_DIR, name));
    if (Buffer.compare(fresh, committed) !== 0) {
      fail(`determinism: ${name} matches generator`, "re-run gen_mini_pe.py and commit the result");
    } else {
      pass(`determinism: ${name} (${committed.length} bytes)`);
    }
  }
}

// ---------------------------------------------------------------------------
// 2. engine-level resolution
// ---------------------------------------------------------------------------

async function checkEngine() {
  const eng = await import(pathToFileURL(X64_ENGINE_JS).href);
  try {
    const dir = await eng.resolveX64dbgDir();
    pass(`engine: resolveX64dbgDir (${dir})`);
    const exe64 = await eng.resolveDebuggerExe(dir, "x64");
    assertEqual("engine: resolveDebuggerExe x64", exe64.toLowerCase().endsWith("x64dbg.exe"), true);
    const exe32 = await eng.resolveDebuggerExe(dir, "x86");
    assertEqual("engine: resolveDebuggerExe x86", exe32.toLowerCase().endsWith("x32dbg.exe"), true);
  } catch (error) {
    fail("engine: install resolution", error instanceof Error ? error.message : String(error));
    return;
  }
  assertEqual("engine: detectPeArch x64", await eng.detectPeArch(FIX_X64), "x64");
  assertEqual("engine: detectPeArch x86", await eng.detectPeArch(FIX_X86), "x86");
  try {
    await eng.detectPeArch(ELF);
    fail("engine: ELF rejected", "expected invalid_target");
  } catch (error) {
    assertEqual("engine: ELF rejected", error?.code, "invalid_target");
  }
  try {
    await eng.detectPeArch(join(TEST_DIR, "does-not-exist.exe"));
    fail("engine: missing target rejected", "expected invalid_target");
  } catch (error) {
    assertEqual("engine: missing target rejected", error?.code, "invalid_target");
  }
  const probe = spawn(process.execPath, ["-e", "setTimeout(()=>{},15000)"], {
    stdio: "ignore",
    windowsHide: true,
  });
  try {
    const probePath = await eng.getProcessExePath(probe.pid);
    assertEqual("engine: getProcessExePath live pid", probePath.toLowerCase().endsWith("node.exe"), true);
  } finally {
    try {
      probe.kill();
    } catch {
      // already gone
    }
  }
  try {
    await eng.getProcessExePath(process.pid);
    fail("engine: own pid rejected", "expected invalid_argument");
  } catch (error) {
    assertEqual("engine: own pid rejected", error?.code, "invalid_argument");
  }
  try {
    await eng.getProcessExePath(2147483647);
    fail("engine: bogus pid rejected", "expected invalid_target");
  } catch (error) {
    assertEqual("engine: bogus pid rejected", error?.code, "invalid_target");
  }
}

// ---------------------------------------------------------------------------
// 3-4. MCP e2e over stdio
// ---------------------------------------------------------------------------

const META = {
  _meta: {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
    "io.modelcontextprotocol/clientCapabilities": {},
  },
};

function toolPayload(reply) {
  const text = reply?.result?.content?.[0]?.text ?? null;
  if (text === null) throw new Error(`tool reply has no text: ${JSON.stringify(reply).slice(0, 300)}`);
  return JSON.parse(text);
}

class StdioMcp {
  constructor() {
    this.id = 0;
    this.buf = "";
    this.waiters = new Map();
    this.child = null;
  }

  async start() {
    this.child = spawn(process.execPath, [SERVER_JS], { stdio: ["pipe", "pipe", "pipe"] });
    this.child.stderr.on("data", () => {});
    this.child.stdout.on("data", (chunk) => {
      this.buf += chunk.toString("utf8");
      let nl;
      while ((nl = this.buf.indexOf("\n")) !== -1) {
        const line = this.buf.slice(0, nl).trim();
        this.buf = this.buf.slice(nl + 1);
        if (!line) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        const waiter = this.waiters.get(msg.id);
        if (waiter !== undefined) {
          this.waiters.delete(msg.id);
          waiter(msg);
        }
      }
    });
    await new Promise((r) => setTimeout(r, 500));
  }

  request(method, params, timeoutMs = 180000) {
    const id = (this.id += 1);
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.waiters.delete(id);
        reject(new Error(`stdio ${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.waiters.set(id, (msg) => {
        clearTimeout(timer);
        resolvePromise(msg);
      });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  call(name, args, timeoutMs) {
    return this.request("tools/call", { ...META, name, arguments: args }, timeoutMs);
  }

  async stop() {
    try {
      this.child.kill();
    } catch {
      // already gone
    }
  }
}

const hexEq = (a, b) => parseInt(a, 16) === parseInt(b, 16);

/** Signal-0 liveness probe (mirrors the engine). */
function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== "ESRCH";
  }
}

/** PIDs currently running under an image name (tasklist CSV, header skipped). */
function pidsOf(imageName) {
  const out = spawnSync("tasklist", ["/fi", `imagename eq ${imageName}`, "/fo", "csv"], {
    encoding: "utf8",
  });
  const pids = new Set();
  for (const line of (out.stdout ?? "").split("\n").slice(1)) {
    const m = line.match(/^"[^"]+","(\d+)"/);
    if (m) pids.add(m[1]);
  }
  return pids;
}

/**
 * Full debug flow for one fixture/arch on its own session + debugger.
 * spec: { tag, fixture, arch, base, entry, acc, ip, module, dbgExe }
 * Returns the session id (closed) or throws; cleanup is best-effort.
 */
async function runArchFlow(mcp, spec) {
  const t = (name) => `e2e[${spec.tag}]: ${name}`;
  const opened = toolPayload(await mcp.call("session_open", { engine: "x64dbg" }));
  const sid = opened.session_id;
  assertEqual(t("session_open engine"), opened.engine, "x64dbg");
  // Pre-existing debuggers (other sessions, stale strays) are not ours.
  const debuggerPidsBefore = pidsOf(spec.dbgExe);
  try {
    const o = toolPayload(await mcp.call("debug_open", { session_id: sid, path: spec.fixture }));
    assertEqual(t("debug_open"), { opened: o.opened, engine: o.engine }, { opened: true, engine: "x64dbg" });
    assertEqual(t("debug_open arch"), o.architecture, spec.arch);
    assertEqual(t("module_base fixed"), hexEq(o.module_base, `0x${spec.base.toString(16)}`), true);
    assertEqual(t("module_entry fixed"), hexEq(o.module_entry, `0x${spec.entry.toString(16)}`), true);

    const bpAddr = `0x${(spec.entry + 5).toString(16)}`;
    const set = toolPayload(await mcp.call("debug_breakpoint", { session_id: sid, address: bpAddr }));
    assertEqual(t("bp set"), { action: set.action, resolved: set.resolved }, { action: "set", resolved: true });
    const listed = toolPayload(await mcp.call("debug_breakpoint", { session_id: sid, action: "list" }));
    const addrs = (listed.breakpoints ?? []).map((b) => b.address);
    assertEqual(
      t("bp list contains ours"),
      addrs.some((a) => hexEq(a, bpAddr)),
      true,
    );

    // First continue stops at x64dbg's own entry bp; second hits ours.
    let c = toolPayload(await mcp.call("debug_continue", { session_id: sid }));
    if (c.reason === "breakpoint" && hexEq(c.address, `0x${spec.entry.toString(16)}`)) {
      pass(t("continue#1 stopped at entry bp"));
      c = toolPayload(await mcp.call("debug_continue", { session_id: sid }));
    }
    assertEqual(
      t("OUR bp hit"),
      { reason: c.reason, at: hexEq(c.address, bpAddr) },
      { reason: "breakpoint", at: true },
    );

    const regs = toolPayload(await mcp.call("debug_registers", { session_id: sid }));
    assertEqual(t(`${spec.acc} == 0x1234 (real execution)`), hexEq(regs.general?.[spec.acc] ?? "0", "0x1234"), true);
    assertEqual(t(`${spec.ip} == bp`), hexEq(regs.general?.[spec.ip] ?? "0", bpAddr), true);

    const stack = toolPayload(await mcp.call("debug_callstack", { session_id: sid, max_frames: 6 }));
    assertEqual(t("callstack non-empty"), (stack.frames ?? []).length >= 1, true);
    assertEqual(t("callstack frame0 module"), (stack.frames ?? [])[0]?.module, spec.module);

    const step = toolPayload(await mcp.call("debug_step", { session_id: sid, kind: "into" }));
    assertEqual(t("step into"), hexEq(step.address, `0x${(spec.entry + 6).toString(16)}`), true);

    const paused = toolPayload(await mcp.call("debug_pause", { session_id: sid }));
    assertEqual(t("pause idempotent"), paused.reason, "paused");

    const removed = toolPayload(
      await mcp.call("debug_breakpoint", { session_id: sid, action: "remove", address: bpAddr }),
    );
    assertEqual(t("bp remove"), removed.status, "removed");

    const exit = toolPayload(await mcp.call("debug_continue", { session_id: sid }));
    assertEqual(t("continue to exit"), exit.reason, "exited");

    const events = toolPayload(await mcp.call("events_pull", { session_id: sid, limit: 100 }));
    const kinds = (events.events ?? []).map((e) => e.kind);
    const want = [
      "target.opened",
      "debug.loaded",
      "debug.breakpoint_set",
      "debug.breakpoint_hit",
      "debug.stepped",
      "debug.breakpoint_removed",
      "debug.exited",
    ];
    let cursor = -1;
    let ordered = true;
    for (const kind of want) {
      const next = kinds.indexOf(kind, cursor + 1);
      if (next === -1) {
        ordered = false;
        break;
      }
      cursor = next;
    }
    assertEqual(t("events_pull chain ordered"), ordered, true);

    const state = toolPayload(await mcp.call("debug_state", { session_id: sid }));
    assertEqual(
      t("debug_state terminated"),
      { state: state.state, termination_reason: state.termination_reason },
      { state: "terminated", termination_reason: "process_exit" },
    );

    const closed = toolPayload(await mcp.call("debug_close", { session_id: sid }));
    assertEqual(t("debug_close"), closed.closed, true);
    // No hidden debugger we spawned may survive teardown.
    await new Promise((r) => setTimeout(r, 2000));
    const after = pidsOf(spec.dbgExe);
    const leaked = [...after].filter((pid) => !debuggerPidsBefore.has(pid));
    assertEqual(t(`no new ${spec.dbgExe} survives debug_close`), leaked, []);

    const sessionClosed = toolPayload(await mcp.call("session_close", { session_id: sid }));
    assertEqual(t("session_close"), sessionClosed.closed, true);
  } catch (error) {
    try {
      await mcp.call("debug_close", { session_id: sid }, 30000);
    } catch {
      // best effort
    }
    throw error;
  }
}

async function x86RuntimeAvailable(eng) {
  try {
    const files = eng.bridgeFileSet("x86");
    readFileSync(files.loaderSource);
  } catch {
    return "prebuilt x64dbg_mcp_loader.dp32 missing (see plugin/x64dbg/THIRD_PARTY_NOTICES.md)";
  }
  try {
    await eng.resolvePythonHome("x86");
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  return null;
}

/**
 * Attach flow for one arch: spawn a hidden sleeper, attach, verify pid/arch,
 * read registers, then debug_close must DETACH (sleeper survives) and leave
 * no debugger behind. spec: { tag, arch, ip, dbgExe, spawn: () => ChildProcess }
 */
async function runAttachFlow(mcp, spec) {
  const t = (name) => `e2e[attach-${spec.tag}]: ${name}`;
  const sleeper = spec.spawn();
  const sleeperPid = sleeper.pid;
  assertEqual(t("sleeper spawned"), typeof sleeperPid === "number" && sleeperPid > 0, true);
  const opened = toolPayload(await mcp.call("session_open", { engine: "x64dbg" }));
  const sid = opened.session_id;
  const debuggerPidsBefore = pidsOf(spec.dbgExe);
  try {
    const a = toolPayload(await mcp.call("debug_attach", { session_id: sid, pid: sleeperPid }));
    assertEqual(
      t("debug_attach"),
      { attached: a.attached, pid: a.pid, architecture: a.architecture },
      { attached: true, pid: sleeperPid, architecture: spec.arch },
    );
    const regs = toolPayload(await mcp.call("debug_registers", { session_id: sid }));
    const ip = regs.general?.[spec.ip] ?? "0";
    assertEqual(t("registers readable, ip nonzero"), parseInt(ip, 16) > 0, true);
    const state = toolPayload(await mcp.call("debug_state", { session_id: sid }));
    assertEqual(
      t("debug_state attached"),
      { open: state.open, attached: state.attached, pid: state.pid, arch: state.arch },
      { open: true, attached: true, pid: sleeperPid, arch: spec.arch },
    );
    const events = toolPayload(await mcp.call("events_pull", { session_id: sid, limit: 50 }));
    const kinds = (events.events ?? []).map((e) => e.kind);
    assertEqual(t("events has debug.attached"), kinds.includes("debug.attached"), true);
    const closed = toolPayload(await mcp.call("debug_close", { session_id: sid }));
    assertEqual(t("debug_close"), closed.closed, true);
    await new Promise((r) => setTimeout(r, 1500));
    assertEqual(t("sleeper survives detach"), pidAlive(sleeperPid), true);
    const after = pidsOf(spec.dbgExe);
    const leaked = [...after].filter((pid) => !debuggerPidsBefore.has(pid));
    assertEqual(t(`no new ${spec.dbgExe} survives debug_close`), leaked, []);
    const sessionClosed = toolPayload(await mcp.call("session_close", { session_id: sid }));
    assertEqual(t("session_close"), sessionClosed.closed, true);
  } finally {
    try {
      sleeper.kill();
    } catch {
      // already gone
    }
  }
}

function spawnNodeSleeper() {
  return spawn(process.execPath, ["-e", "setTimeout(()=>{},90000)"], { stdio: "ignore", windowsHide: true });
}

async function runE2E() {
  const mcp = new StdioMcp();
  try {
    await mcp.start();

    // negatives (no debugger needed)
    const r2 = toolPayload(await mcp.call("session_open", { engine: "radare2" }));
    const dbgOnR2 = toolPayload(await mcp.call("debug_open", { session_id: r2.session_id, path: FIX_X64 }));
    assertEqual("e2e: debug_open on radare2 rejected", dbgOnR2.error, "capability_unsupported");
    const stOnR2 = toolPayload(await mcp.call("debug_state", { session_id: r2.session_id }));
    assertEqual("e2e: debug_state on radare2 rejected", stOnR2.error, "capability_unsupported");
    const stMissing = toolPayload(
      await mcp.call("debug_state", { session_id: "00000000-0000-4000-8000-000000000000" }),
    );
    assertEqual("e2e: debug_state unknown session", stMissing.error, "session_not_found");
    const tmp = toolPayload(await mcp.call("session_open", { engine: "x64dbg" }));
    const noAddr = toolPayload(await mcp.call("debug_breakpoint", { session_id: tmp.session_id, action: "set" }));
    assertEqual("e2e: breakpoint without address", noAddr.error, "invalid_argument");
    const attachOnR2 = toolPayload(await mcp.call("debug_attach", { session_id: r2.session_id, pid: 1234 }));
    assertEqual("e2e: debug_attach on radare2 rejected", attachOnR2.error, "capability_unsupported");
    const attachBogus = toolPayload(await mcp.call("debug_attach", { session_id: tmp.session_id, pid: 2147483647 }));
    assertEqual("e2e: debug_attach bogus pid", attachBogus.error, "invalid_target");
    await mcp.call("session_close", { session_id: r2.session_id });
    await mcp.call("session_close", { session_id: tmp.session_id });

    await runArchFlow(mcp, {
      tag: "x64",
      fixture: FIX_X64,
      arch: "x64",
      base: 0x140000000,
      entry: 0x140001000,
      acc: "rax",
      ip: "rip",
      module: "mini_pe_x64",
      dbgExe: "x64dbg.exe",
    });

    const eng = await import(pathToFileURL(X64_ENGINE_JS).href);
    const skip = await x86RuntimeAvailable(eng);
    if (skip !== null) {
      console.log(`skip   e2e[x86]: ${skip}`);
    } else {
      await runArchFlow(mcp, {
        tag: "x86",
        fixture: FIX_X86,
        arch: "x86",
        base: 0x400000,
        entry: 0x401000,
        acc: "eax",
        ip: "eip",
        module: "mini_pe_x86",
        dbgExe: "x32dbg.exe",
      });
    }

    await runAttachFlow(mcp, {
      tag: "x64",
      arch: "x64",
      ip: "rip",
      dbgExe: "x64dbg.exe",
      spawn: spawnNodeSleeper,
    });

    if (skip !== null) {
      console.log(`skip   e2e[attach-x86]: ${skip}`);
    } else {
      const py32 = join(await eng.resolvePythonHome("x86"), "python.exe");
      await runAttachFlow(mcp, {
        tag: "x86",
        arch: "x86",
        ip: "eip",
        dbgExe: "x32dbg.exe",
        spawn: () =>
          spawn(py32, ["-c", "import time;time.sleep(90)"], { stdio: "ignore", windowsHide: true }),
      });
    }
  } catch (error) {
    fail("e2e", error instanceof Error ? (error.stack ?? error.message) : String(error));
  } finally {
    await mcp.stop();
  }
}

async function main() {
  checkPrereqs();
  checkDeterminism();
  await checkEngine();
  await runE2E();
  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
