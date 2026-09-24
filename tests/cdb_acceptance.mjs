#!/usr/bin/env node
/**
 * cdb acceptance for Conduit (fixtures: plugin/x64dbg/test/mini_pe_*.exe).
 *
 * Mirrors tests/debug_acceptance.mjs on the cdb engine:
 *   bp at entry+5 → hit → accumulator == 0x1234 → events → callstack →
 *   step → pause → exit → no leftover cdb.
 * The first continue may stop on the entry breakpoint planted at open
 * (same shape as x64dbg's entry breakpoint); the next continue is ours.
 * Attach detaches: the target stays alive and cdb.exe does not.
 *
 * Usage:  node tests/cdb_acceptance.mjs   (== npm run test:cdb)
 * Prereqs: Windows, `npm run build`, Debugging Tools cdb.exe
 *   (CDB_DIR or Windows Kits\10\Debuggers). x86 attach needs a 32-bit
 *   python.exe (PYTHON_HOME_X86 or %USERPROFILE%\Tools\python-x86).
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_JS = join(ROOT, "dist", "server.js");
const CDB_ENGINE_JS = join(ROOT, "dist", "engines", "cdb.js");
const TEST_DIR = join(ROOT, "plugin", "x64dbg", "test");
const GEN_SCRIPT = join(TEST_DIR, "gen_mini_pe.py");
const FIX_X64 = join(TEST_DIR, "mini_pe_x64.exe");
const FIX_X86 = join(TEST_DIR, "mini_pe_x86.exe");
const ELF = join(ROOT, "examples", "target", "mini_branch.elf");
const PROTOCOL = "2026-07-28";

let failures = 0;
let passes = 0;

function pass(name) {
  passes += 1;
  console.log(`ok   ${name}`);
}

function fail(name, detail) {
  failures += 1;
  console.log(`FAIL ${name}`);
  for (const line of String(detail).split("\n").slice(0, 16)) {
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
  fail(name, `expected: ${e.slice(0, 500)}\nactual:   ${a.slice(0, 500)}`);
  return false;
}

function checkPrereqs() {
  const problems = [];
  if (process.platform !== "win32") {
    problems.push(`Windows-only (platform: ${process.platform})`);
  }
  for (const [label, path] of [
    ["dist/server.js", SERVER_JS],
    ["dist/engines/cdb.js", CDB_ENGINE_JS],
    ["mini_pe_x64.exe", FIX_X64],
    ["mini_pe_x86.exe", FIX_X86],
  ]) {
    try {
      readFileSync(path);
    } catch {
      problems.push(`${label} missing (${path})`);
    }
  }
  if (problems.length > 0) {
    console.log("prereq check FAILED:");
    for (const problem of problems) {
      console.log(`  - ${problem}`);
    }
    process.exit(2);
  }
  pass("prereqs (win32, dist built, fixtures)");
}

function checkDeterminism() {
  const dir = mkdtempSync(join(tmpdir(), "mini-pe-cdb-"));
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

function pidsOf(imageName) {
  const out = spawnSync("tasklist", ["/fi", `imagename eq ${imageName}`, "/fo", "csv"], { encoding: "utf8" });
  const pids = new Set();
  for (const line of (out.stdout ?? "").split("\n").slice(1)) {
    const match = line.match(/^"[^"]+","(\d+)"/);
    if (match?.[1] !== undefined) {
      pids.add(match[1]);
    }
  }
  return pids;
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== "ESRCH";
  }
}

function visibleCdb() {
  const script =
    "Get-Process cdb -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | " +
    "Select-Object -ExpandProperty Id";
  const result = spawnSync("powershell.exe", ["-NoProfile", "-Command", script], {
    windowsHide: true,
    encoding: "utf8",
  });
  return (result.stdout ?? "")
    .split(/\s+/)
    .map((part) => part.trim())
    .filter((part) => part !== "");
}

const hexEq = (a, b) => parseInt(a, 16) === parseInt(b, 16);

const META = {
  _meta: {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
    "io.modelcontextprotocol/clientCapabilities": {},
  },
};

function toolPayload(reply) {
  const text = reply?.result?.content?.[0]?.text ?? null;
  if (text === null) {
    throw new Error(`tool reply has no text: ${JSON.stringify(reply).slice(0, 400)}`);
  }
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
    this.child = spawn(process.execPath, [SERVER_JS], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    this.child.stderr.on("data", () => {});
    this.child.stdout.on("data", (chunk) => {
      this.buf += chunk.toString("utf8");
      let nl;
      while ((nl = this.buf.indexOf("\n")) !== -1) {
        const line = this.buf.slice(0, nl).trim();
        this.buf = this.buf.slice(nl + 1);
        if (line === "") {
          continue;
        }
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
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 300));
  }

  request(method, params, timeoutMs = 120000) {
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

async function runArchFlow(mcp, spec) {
  const t = (name) => `e2e[${spec.tag}]: ${name}`;
  const opened = toolPayload(await mcp.call("session_open", { engine: "cdb" }));
  const sid = opened.session_id;
  assertEqual(t("session_open engine"), opened.engine, "cdb");
  const before = pidsOf("cdb.exe");
  try {
    const info = toolPayload(await mcp.call("debug_open", { session_id: sid, path: spec.fixture }));
    assertEqual(t("debug_open"), { opened: info.opened, engine: info.engine }, { opened: true, engine: "cdb" });
    assertEqual(t("debug_open arch"), info.architecture, spec.arch);
    assertEqual(t("module_base fixed"), hexEq(info.module_base, `0x${spec.base.toString(16)}`), true);
    assertEqual(t("module_entry fixed"), hexEq(info.module_entry, `0x${spec.entry.toString(16)}`), true);
    assertEqual(t("no visible cdb window"), visibleCdb(), []);

    const bpAddr = `0x${(spec.entry + 5).toString(16)}`;
    const set = toolPayload(await mcp.call("debug_breakpoint", { session_id: sid, address: bpAddr }));
    assertEqual(t("bp set"), { action: set.action, resolved: set.resolved }, { action: "set", resolved: true });
    const listed = toolPayload(await mcp.call("debug_breakpoint", { session_id: sid, action: "list" }));
    const addrs = (listed.breakpoints ?? []).map((row) => row.address);
    assertEqual(t("bp list contains ours"), addrs.some((addr) => hexEq(addr, bpAddr)), true);

    let stopped = toolPayload(await mcp.call("debug_continue", { session_id: sid }));
    if (stopped.reason === "breakpoint" && hexEq(stopped.address, `0x${spec.entry.toString(16)}`)) {
      pass(t("continue#1 stopped at entry bp"));
      stopped = toolPayload(await mcp.call("debug_continue", { session_id: sid }));
    }
    assertEqual(
      t("OUR bp hit"),
      { reason: stopped.reason, at: hexEq(stopped.address, bpAddr) },
      { reason: "breakpoint", at: true },
    );

    const regs = toolPayload(await mcp.call("debug_registers", { session_id: sid }));
    assertEqual(t(`${spec.acc} == 0x1234 (real execution)`), hexEq(regs.general?.[spec.acc] ?? "0", "0x1234"), true);
    assertEqual(t(`${spec.ip} == bp`), hexEq(regs.general?.[spec.ip] ?? "0", bpAddr), true);

    const stack = toolPayload(await mcp.call("debug_callstack", { session_id: sid, max_frames: 6 }));
    assertEqual(t("callstack non-empty"), (stack.frames ?? []).length >= 1, true);
    assertEqual(t("callstack frame0 module"), (stack.frames ?? [])[0]?.module, spec.module);

    const stepped = toolPayload(await mcp.call("debug_step", { session_id: sid, kind: "into" }));
    assertEqual(t("step into"), hexEq(stepped.address, `0x${(spec.entry + 6).toString(16)}`), true);
    const over = toolPayload(await mcp.call("debug_step", { session_id: sid, kind: "over" }));
    assertEqual(t("step over"), hexEq(over.address, `0x${(spec.entry + 7).toString(16)}`), true);

    const paused = toolPayload(await mcp.call("debug_pause", { session_id: sid }));
    assertEqual(t("pause idempotent"), paused.reason, "paused");

    const removed = toolPayload(
      await mcp.call("debug_breakpoint", { session_id: sid, action: "remove", address: bpAddr }),
    );
    assertEqual(t("bp remove"), removed.status, "removed");

    const exit = toolPayload(await mcp.call("debug_continue", { session_id: sid }));
    assertEqual(t("continue to exit"), exit.reason, "exited");

    const events = toolPayload(await mcp.call("events_pull", { session_id: sid, limit: 100 }));
    const kinds = (events.events ?? []).map((event) => event.kind);
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
    if (!ordered) {
      fail(t("events_pull kinds"), kinds.join(","));
    }

    const state = toolPayload(await mcp.call("debug_state", { session_id: sid }));
    assertEqual(
      t("debug_state terminated"),
      { state: state.state, termination_reason: state.termination_reason },
      { state: "terminated", termination_reason: "process_exit" },
    );

    const closed = toolPayload(await mcp.call("debug_close", { session_id: sid }));
    assertEqual(t("debug_close"), closed.closed, true);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 800));
    const leaked = [...pidsOf("cdb.exe")].filter((pid) => !before.has(pid));
    assertEqual(t("no new cdb.exe survives debug_close"), leaked, []);
    const sessionClosed = toolPayload(await mcp.call("session_close", { session_id: sid }));
    assertEqual(t("session_close"), sessionClosed.closed, true);
  } catch (error) {
    try {
      await mcp.call("debug_close", { session_id: sid }, 15000);
    } catch {
      // best effort
    }
    try {
      await mcp.call("session_close", { session_id: sid }, 15000);
    } catch {
      // best effort
    }
    throw error;
  }
}

async function runAttachFlow(mcp, spec) {
  const t = (name) => `e2e[attach-${spec.tag}]: ${name}`;
  const sleeper = spec.spawn();
  const sleeperPid = sleeper.pid;
  assertEqual(t("sleeper spawned"), typeof sleeperPid === "number" && sleeperPid > 0, true);
  const opened = toolPayload(await mcp.call("session_open", { engine: "cdb" }));
  const sid = opened.session_id;
  const before = pidsOf("cdb.exe");
  try {
    const attached = toolPayload(await mcp.call("debug_attach", { session_id: sid, pid: sleeperPid }));
    assertEqual(
      t("debug_attach"),
      { attached: attached.attached, pid: attached.pid, architecture: attached.architecture },
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
    const kinds = (events.events ?? []).map((event) => event.kind);
    assertEqual(t("events has debug.attached"), kinds.includes("debug.attached"), true);
    assertEqual(t("no visible cdb window"), visibleCdb(), []);
    const closed = toolPayload(await mcp.call("debug_close", { session_id: sid }));
    assertEqual(t("debug_close"), closed.closed, true);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 800));
    assertEqual(t("sleeper survives detach"), pidAlive(sleeperPid), true);
    const leaked = [...pidsOf("cdb.exe")].filter((pid) => !before.has(pid));
    assertEqual(t("no new cdb.exe survives debug_close"), leaked, []);
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

function findPython32() {
  const candidates = [];
  if (process.env.PYTHON_HOME_X86 !== undefined && process.env.PYTHON_HOME_X86 !== "") {
    candidates.push(join(process.env.PYTHON_HOME_X86, "python.exe"));
  }
  candidates.push(join(homedir(), "Tools", "python-x86", "python.exe"));
  for (const candidate of candidates) {
    try {
      readFileSync(candidate);
      return candidate;
    } catch {
      // try the next one
    }
  }
  return null;
}

async function checkEngine(eng) {
  const exe64 = await eng.resolveCdbExe("x64");
  assertEqual("engine: cdb x64", exe64.toLowerCase().endsWith("\\x64\\cdb.exe"), true);
  const exe86 = await eng.resolveCdbExe("x86");
  assertEqual("engine: cdb x86", exe86.toLowerCase().endsWith("\\x86\\cdb.exe"), true);
  assertEqual("engine: detect x64", await eng.detectPeArch(FIX_X64), "x64");
  assertEqual("engine: detect x86", await eng.detectPeArch(FIX_X86), "x86");
  try {
    await eng.detectPeArch(ELF);
    fail("engine: ELF rejected", "expected invalid_target");
  } catch (error) {
    assertEqual("engine: ELF rejected", error?.code, "invalid_target");
  }
  const id = "hw-bp";
  try {
    await eng.cdbEngine.open(id, FIX_X64);
    // cdb refuses hardware breakpoints until the process breakpoint has been passed.
    const entryStop = await eng.cdbEngine.continue_(id);
    assertEqual(
      "engine: continue reaches entry before hardware bp",
      { reason: entryStop.reason, at: hexEq(entryStop.address, "0x140001000") },
      { reason: "breakpoint", at: true },
    );
    const set = await eng.cdbEngine.setBreakpoint(id, { address: "0x140001006", type: "hardware_execute" });
    assertEqual("engine: hardware bp resolved", set.resolved, true);
    const listed = await eng.cdbEngine.listBreakpoints(id);
    assertEqual(
      "engine: hardware bp listed",
      listed.breakpoints.some((row) => hexEq(row.address, "0x140001006") && row.type === "hardware_execute"),
      true,
    );
    const removed = await eng.cdbEngine.removeBreakpoint(id, "0x140001006");
    assertEqual("engine: hardware bp removed", removed.status, "removed");
    try {
      await eng.cdbEngine.setBreakpoint(id, { address: "0x140001006", type: "memory_access" });
      fail("engine: memory bp unsupported", "expected capability_unsupported");
    } catch (error) {
      assertEqual("engine: memory bp unsupported", error?.code, "capability_unsupported");
    }
  } finally {
    await eng.cdbEngine.close(id);
  }
}

async function checkRunningPause(eng) {
  const sleeper = spawn(process.execPath, ["-e", "setTimeout(()=>{},90000)"], { stdio: "ignore", windowsHide: true });
  const id = "pause-run";
  try {
    await eng.cdbEngine.attach(id, sleeper.pid);
    const pending = eng.cdbEngine.continue_(id);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 400));
    const paused = await eng.cdbEngine.pause(id);
    const continued = await pending;
    assertEqual("engine: pause while running", paused.reason, "paused");
    assertEqual(
      "engine: continue stopped for the pause",
      continued.reason === "paused" || continued.reason === "breakpoint",
      true,
    );
    await eng.cdbEngine.close(id);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 400));
    assertEqual("engine: sleeper survives running-pause detach", pidAlive(sleeper.pid), true);
  } finally {
    try {
      await eng.cdbEngine.close(id);
    } catch {
      // already closed
    }
    try {
      sleeper.kill();
    } catch {
      // already gone
    }
  }
}

async function main() {
  checkPrereqs();
  checkDeterminism();
  const eng = await import(pathToFileURL(CDB_ENGINE_JS).href);
  await checkEngine(eng);
  await checkRunningPause(eng);

  const mcp = new StdioMcp();
  try {
    await mcp.start();
    const r2 = toolPayload(await mcp.call("session_open", { engine: "radare2" }));
    const dbgOnR2 = toolPayload(await mcp.call("debug_open", { session_id: r2.session_id, path: FIX_X64 }));
    assertEqual("e2e: debug_open on radare2 rejected", dbgOnR2.error, "capability_unsupported");
    const missing = toolPayload(
      await mcp.call("debug_state", { session_id: "00000000-0000-4000-8000-000000000000" }),
    );
    assertEqual("e2e: debug_state unknown session", missing.error, "session_not_found");
    const tmp = toolPayload(await mcp.call("session_open", { engine: "cdb" }));
    const noAddr = toolPayload(await mcp.call("debug_breakpoint", { session_id: tmp.session_id, action: "set" }));
    assertEqual("e2e: breakpoint without address", noAddr.error, "invalid_argument");
    const bogus = toolPayload(await mcp.call("debug_attach", { session_id: tmp.session_id, pid: 2147483647 }));
    assertEqual("e2e: debug_attach bogus pid", bogus.error, "invalid_target");
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
    });
    await runArchFlow(mcp, {
      tag: "x86",
      fixture: FIX_X86,
      arch: "x86",
      base: 0x400000,
      entry: 0x401000,
      acc: "eax",
      ip: "eip",
      module: "mini_pe_x86",
    });

    await runAttachFlow(mcp, {
      tag: "x64",
      arch: "x64",
      ip: "rip",
      spawn: () => spawn(process.execPath, ["-e", "setTimeout(()=>{},90000)"], { stdio: "ignore", windowsHide: true }),
    });

    const py32 = findPython32();
    if (py32 === null) {
      console.log("skip   e2e[attach-x86]: no 32-bit python.exe");
    } else {
      const arch = await eng.detectPeArch(py32);
      if (arch !== "x86") {
        console.log(`skip   e2e[attach-x86]: ${py32} is ${arch}`);
      } else {
        await runAttachFlow(mcp, {
          tag: "x86",
          arch: "x86",
          ip: "eip",
          spawn: () => spawn(py32, ["-c", "import time; time.sleep(90)"], { stdio: "ignore", windowsHide: true }),
        });
      }
    }
  } catch (error) {
    fail("e2e", error instanceof Error ? (error.stack ?? error.message) : String(error));
  } finally {
    await mcp.stop();
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
