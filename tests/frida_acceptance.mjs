#!/usr/bin/env node
/**
 * Frida acceptance for Conduit (fixtures: plugin/x64dbg/test/mini_pe_*.exe).
 *
 * Adapted from the cdb/x64dbg loop. Frida has no entry breakpoint and no
 * step/pause:
 *   hardware_execute bp at entry+5 → one continue → accumulator == 0x1234
 *   → callstack frame0 is the fixture → step/pause are capability_unsupported
 *   → remove → continue exits → events stay ordered.
 * A fifth hardware breakpoint is no_breakpoint_slot. Attach detaches and
 * leaves the target running. Software breakpoints are rejected.
 *
 * Windowless proof (also printed at the end):
 *   Get-Process cdb,frida* -ErrorAction SilentlyContinue |
 *     Where-Object { $_.MainWindowHandle -ne 0 }
 * must be empty during a live session and after teardown.
 *
 * Usage:  node tests/frida_acceptance.mjs   (== npm run test:frida)
 * Prereqs: Windows, `npm run build`, the `frida` npm package (prebuild).
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import net from "node:net";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_JS = join(ROOT, "dist", "server.js");
const FRIDA_ENGINE_JS = join(ROOT, "dist", "engines", "frida.js");
const TEST_DIR = join(ROOT, "plugin", "x64dbg", "test");
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

const hexEq = (a, b) => parseInt(String(a), 16) === parseInt(String(b), 16);

function checkPrereqs() {
  const problems = [];
  if (process.platform !== "win32") {
    problems.push(`Windows-only (platform: ${process.platform})`);
  }
  for (const [label, path] of [
    ["dist/server.js", SERVER_JS],
    ["dist/engines/frida.js", FRIDA_ENGINE_JS],
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

/** Exact windowless probe from the phase plan. Empty stdout is the proof. */
function visibleDebuggerWindows() {
  const script = [
    "Get-Process cdb,frida* -ErrorAction SilentlyContinue |",
    "Where-Object { $_.MainWindowHandle -ne 0 } |",
    "ForEach-Object { \"$($_.ProcessName) $($_.Id) $($_.MainWindowHandle)\" }",
  ].join(" ");
  const result = spawnSync("powershell.exe", ["-NoProfile", "-Command", script], {
    windowsHide: true,
    encoding: "utf8",
  });
  return (result.stdout ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

function assertWindowless(name) {
  const rows = visibleDebuggerWindows();
  assertEqual(name, rows, []);
  return rows;
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== "ESRCH";
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
      // next candidate
    }
  }
  return null;
}

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

  request(method, params, timeoutMs = 60000) {
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

async function runArch(engine, spec) {
  const t = (name) => `e2e[${spec.tag}]: ${name}`;
  const id = `frida-${spec.tag}`;
  const base = spec.tag === "x64" ? 0x140000000 : 0x400000;
  const opened = await engine.open(id, spec.fixture);
  assertEqual(t("arch"), opened.architecture, spec.tag);
  assertEqual(t("module_base fixed"), hexEq(opened.moduleBase, `0x${base.toString(16)}`), true);
  assertEqual(t("module_entry fixed"), hexEq(opened.entryPoint, `0x${spec.entry.toString(16)}`), true);
  assertEqual(t("spawned paused"), (await engine.state(id)).state, "paused");
  assertWindowless(t("no visible cdb/frida window"));

  const bp = `0x${(spec.entry + 5).toString(16)}`;
  try {
    await engine.setBreakpoint(id, { address: bp, type: "software" });
    fail(t("software bp rejected"), "expected capability_unsupported");
  } catch (error) {
    assertEqual(t("software bp rejected"), error?.code, "capability_unsupported");
  }
  const set = await engine.setBreakpoint(id, { address: bp, type: "hardware_execute" });
  assertEqual(t("bp set"), hexEq(set.address, bp) && set.resolved, true);
  for (let extra = 1; extra <= 3; extra += 1) {
    await engine.setBreakpoint(id, {
      address: `0x${(spec.entry + 5 + extra).toString(16)}`,
      type: "hardware_execute",
    });
  }
  try {
    await engine.setBreakpoint(id, { address: `0x${(spec.entry + 20).toString(16)}`, type: "hardware_execute" });
    fail(t("fifth slot rejected"), "expected no_breakpoint_slot");
  } catch (error) {
    assertEqual(t("fifth slot rejected"), error?.code, "no_breakpoint_slot");
  }
  for (let extra = 1; extra <= 3; extra += 1) {
    await engine.removeBreakpoint(id, `0x${(spec.entry + 5 + extra).toString(16)}`);
  }

  const hit = await engine.continue_(id);
  assertEqual(
    t("OUR bp hit"),
    { reason: hit.reason, at: hexEq(hit.address, bp) },
    { reason: "breakpoint", at: true },
  );
  const regs = await engine.registers(id);
  assertEqual(t(`${spec.acc} == 0x1234`), hexEq(regs.general?.[spec.acc] ?? "0", "0x1234"), true);
  assertEqual(t(`${spec.ip} == bp`), hexEq(regs.general?.[spec.ip] ?? "0", bp), true);
  const stack = await engine.callStack(id, 6);
  assertEqual(t("callstack frame0 module"), stack.frames?.[0]?.module, spec.module);
  try {
    await engine.step(id, "into", 1);
    fail(t("step unsupported"), "expected capability_unsupported");
  } catch (error) {
    assertEqual(t("step unsupported"), error?.code, "capability_unsupported");
  }
  try {
    await engine.pause(id);
    fail(t("pause unsupported"), "expected capability_unsupported");
  } catch (error) {
    assertEqual(t("pause unsupported"), error?.code, "capability_unsupported");
  }
  assertEqual(t("bp remove"), (await engine.removeBreakpoint(id, bp)).status, "removed");
  assertEqual(t("continue to exit"), (await engine.continue_(id)).reason, "exited");
  assertEqual(t("debug_state terminated"), (await engine.state(id)).state, "terminated");
  await engine.close(id);
  assertWindowless(t("windowless after close"));
}

async function runAttach(engine, spec) {
  const t = (name) => `e2e[attach-${spec.tag}]: ${name}`;
  const sleeper = spec.spawn();
  const sleeperPid = sleeper.pid;
  assertEqual(t("sleeper spawned"), typeof sleeperPid === "number" && sleeperPid > 0, true);
  const id = `frida-attach-${spec.tag}`;
  try {
    const attached = await engine.attach(id, sleeperPid);
    assertEqual(
      t("debug_attach"),
      { attached: attached.attached, pid: attached.pid, architecture: attached.architecture },
      { attached: true, pid: sleeperPid, architecture: spec.arch },
    );
    assertWindowless(t("no visible cdb/frida window"));
    await engine.close(id);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 400));
    assertEqual(t("sleeper survives detach"), pidAlive(sleeperPid), true);
    assertWindowless(t("windowless after detach"));
  } finally {
    try {
      await engine.close(id);
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

async function runMcp(mcp) {
  const opened = toolPayload(await mcp.call("session_open", { engine: "frida" }));
  assertEqual("mcp: session_open engine", opened.engine, "frida");
  const sid = opened.session_id;
  const info = toolPayload(await mcp.call("debug_open", { session_id: sid, path: FIX_X64 }));
  assertEqual("mcp: debug_open", { opened: info.opened, engine: info.engine }, { opened: true, engine: "frida" });
  assertWindowless("mcp: no visible cdb/frida window");
  const bp = "0x140001005";
  const set = toolPayload(
    await mcp.call("debug_breakpoint", { session_id: sid, address: bp, type: "hardware_execute" }),
  );
  assertEqual("mcp: bp set", set.resolved, true);
  const hit = toolPayload(await mcp.call("debug_continue", { session_id: sid }));
  assertEqual("mcp: bp hit", { reason: hit.reason, at: hexEq(hit.address, bp) }, { reason: "breakpoint", at: true });
  const regs = toolPayload(await mcp.call("debug_registers", { session_id: sid }));
  assertEqual("mcp: rax == 0x1234", hexEq(regs.general?.rax ?? "0", "0x1234"), true);
  const step = toolPayload(await mcp.call("debug_step", { session_id: sid, kind: "into" }));
  assertEqual("mcp: step unsupported", step.error, "capability_unsupported");
  const pause = toolPayload(await mcp.call("debug_pause", { session_id: sid }));
  assertEqual("mcp: pause unsupported", pause.error, "capability_unsupported");
  const removed = toolPayload(await mcp.call("debug_breakpoint", { session_id: sid, action: "remove", address: bp }));
  assertEqual("mcp: bp remove", removed.status, "removed");
  const exit = toolPayload(await mcp.call("debug_continue", { session_id: sid }));
  assertEqual("mcp: continue to exit", exit.reason, "exited");
  const events = toolPayload(await mcp.call("events_pull", { session_id: sid, limit: 80 }));
  const kinds = (events.events ?? []).map((event) => event.kind);
  const want = [
    "target.opened",
    "debug.loaded",
    "debug.breakpoint_set",
    "debug.breakpoint_hit",
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
  assertEqual("mcp: events_pull chain ordered", ordered, true);
  if (!ordered) {
    fail("mcp: events_pull kinds", kinds.join(","));
  }
  await mcp.call("session_close", { session_id: sid });
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 400));
  assertWindowless("mcp: windowless after session_close");
}

const GADGET_PORT = 27111;

function waitForPort(port, timeoutMs) {
  const started = Date.now();
  return new Promise((resolvePromise, reject) => {
    const attempt = () => {
      const socket = net.connect(port, "127.0.0.1");
      socket.once("connect", () => {
        socket.end();
        resolvePromise();
      });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() - started > timeoutMs) {
          reject(new Error(`gadget port ${port} did not open`));
          return;
        }
        setTimeout(attempt, 200);
      });
    };
    attempt();
  });
}

async function ensureGadgetDll() {
  const dir = join(homedir(), "Tools", "frida-gadget");
  const dll = join(dir, "frida-gadget.dll");
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "frida-gadget.config"),
    JSON.stringify({
      interaction: {
        type: "listen",
        address: "127.0.0.1",
        port: GADGET_PORT,
        on_port_conflict: "fail",
        on_load: "resume",
      },
    }),
  );
  if (existsSync(dll)) {
    return dll;
  }
  const xz = join(dir, "frida-gadget.dll.xz");
  const response = await fetch(
    "https://github.com/frida/frida/releases/download/17.18.0/frida-gadget-17.18.0-windows-x86_64.dll.xz",
  );
  if (!response.ok) {
    throw new Error(`gadget download failed: HTTP ${response.status}`);
  }
  writeFileSync(xz, Buffer.from(await response.arrayBuffer()));
  const unpacked = spawnSync(
    "python",
    ["-c", "import lzma,pathlib,sys; pathlib.Path(sys.argv[2]).write_bytes(lzma.open(sys.argv[1]).read())", xz, dll],
    { encoding: "utf8" },
  );
  if (unpacked.status !== 0) {
    throw new Error(unpacked.stderr || "failed to unpack frida-gadget.dll.xz");
  }
  return dll;
}

function startGadgetHost(dll) {
  const script = `
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class GadgetHost {
  [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr LoadLibrary(string path);
}
'@
$handle = [GadgetHost]::LoadLibrary('${dll.replace(/'/g, "''")}')
if ($handle -eq [IntPtr]::Zero) {
  Write-Error ("LoadLibrary " + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
  exit 2
}
Start-Sleep -Seconds 120
`;
  return spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function runGadget(mcp) {
  const xdbg = toolPayload(await mcp.call("session_open", { engine: "x64dbg" }));
  const rejected = toolPayload(
    await mcp.call("debug_attach", { session_id: xdbg.session_id, gadget: "127.0.0.1:1" }),
  );
  assertEqual("gadget: x64dbg rejects listen attach", rejected.error, "capability_unsupported");
  await mcp.call("session_close", { session_id: xdbg.session_id });

  const opened = toolPayload(await mcp.call("session_open", { engine: "frida" }));
  const missing = toolPayload(await mcp.call("debug_attach", { session_id: opened.session_id }));
  assertEqual("gadget: pid required without gadget", missing.error, "invalid_argument");
  const usbMissing = toolPayload(await mcp.call("debug_attach", { session_id: opened.session_id, usb: true }));
  assertEqual("gadget: usb requires package", usbMissing.error, "invalid_argument");

  const dll = await ensureGadgetDll();
  const host = startGadgetHost(dll);
  let hostErr = "";
  host.stderr?.on("data", (chunk) => {
    hostErr += chunk.toString("utf8");
  });
  try {
    await waitForPort(GADGET_PORT, 20_000);
    const attached = toolPayload(
      await mcp.call("debug_attach", { session_id: opened.session_id, gadget: `127.0.0.1:${GADGET_PORT}` }),
    );
    assertEqual("gadget: attached", attached.attached, true);
    assertEqual("gadget: engine", attached.engine, "frida");
    const state = toolPayload(await mcp.call("debug_state", { session_id: opened.session_id }));
    assertEqual("gadget: state running", state.state, "running");
    assertEqual("gadget: marked attached", state.attached, true);
    assertWindowless("gadget: no visible cdb/frida window");
    const closed = toolPayload(await mcp.call("debug_close", { session_id: opened.session_id }));
    assertEqual("gadget: debug_close", closed.closed, true);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 400));
    assertEqual("gadget: host survives detach", pidAlive(host.pid), true);
  } catch (error) {
    fail("gadget", `${error instanceof Error ? error.message : String(error)}\n${hostErr}`);
  } finally {
    try {
      await mcp.call("session_close", { session_id: opened.session_id });
    } catch {
      // already closed
    }
    try {
      host.kill();
    } catch {
      // already gone
    }
  }
}

async function main() {
  checkPrereqs();
  const eng = await import(pathToFileURL(FRIDA_ENGINE_JS).href);
  try {
    await eng.detectPeArch(ELF);
    fail("engine: ELF rejected", "expected invalid_target");
  } catch (error) {
    assertEqual("engine: ELF rejected", error?.code, "invalid_target");
  }

  await runArch(eng.fridaEngine, {
    tag: "x64",
    fixture: FIX_X64,
    entry: 0x140001000,
    acc: "rax",
    ip: "rip",
    module: "mini_pe_x64",
  });
  await runArch(eng.fridaEngine, {
    tag: "x86",
    fixture: FIX_X86,
    entry: 0x401000,
    acc: "eax",
    ip: "eip",
    module: "mini_pe_x86",
  });

  await runAttach(eng.fridaEngine, {
    tag: "x64",
    arch: "x64",
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
      await runAttach(eng.fridaEngine, {
        tag: "x86",
        arch: "x86",
        spawn: () => spawn(py32, ["-c", "import time; time.sleep(90)"], { stdio: "ignore", windowsHide: true }),
      });
    }
  }

  const mcp = new StdioMcp();
  try {
    await mcp.start();
    const r2 = toolPayload(await mcp.call("session_open", { engine: "radare2" }));
    const rejected = toolPayload(await mcp.call("debug_open", { session_id: r2.session_id, path: FIX_X64 }));
    assertEqual("e2e: debug_open on radare2 rejected", rejected.error, "capability_unsupported");
    await mcp.call("session_close", { session_id: r2.session_id });
    await runMcp(mcp);
    await runGadget(mcp);
  } catch (error) {
    fail("e2e", error instanceof Error ? (error.stack ?? error.message) : String(error));
  } finally {
    await mcp.stop();
  }

  const proof = visibleDebuggerWindows();
  assertEqual("windowless: cdb,frida* MainWindowHandle -ne 0", proof, []);
  console.log("windowless proof: Get-Process cdb,frida* | Where-Object MainWindowHandle -ne 0 → (empty)");

  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
