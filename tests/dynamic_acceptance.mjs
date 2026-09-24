#!/usr/bin/env node
/**
 * Live memory / code / thread / checkpoint tools, plus the confirm gate.
 *
 * Every dynamic tool must return confirmation_required until confirm:true.
 * That first call must not start a debugger. Engines that cannot do a thing
 * return capability_unsupported. Scylla's GUI DLL is not launched.
 *
 * Usage: node tests/dynamic_acceptance.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_JS = join(ROOT, "dist", "server.js");
const FIX_X64 = join(ROOT, "plugin", "x64dbg", "test", "mini_pe_x64.exe");
const PROTOCOL = "2026-07-28";
const ENTRY = 0x140001000n;
const BASE = 0x140000000n;

let failures = 0;
let passes = 0;

function pass(name) {
  passes += 1;
  console.log(`ok   ${name}`);
}

function fail(name, detail) {
  failures += 1;
  console.log(`FAIL ${name}`);
  for (const line of String(detail).split("\n").slice(0, 24)) {
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
  fail(name, `expected: ${e.slice(0, 700)}\nactual:   ${a.slice(0, 700)}`);
  return false;
}

function hexEq(actual, expected) {
  try {
    return BigInt(actual) === BigInt(expected);
  } catch {
    return false;
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

function samePids(left, right) {
  if (left.size !== right.size) {
    return false;
  }
  for (const pid of left) {
    if (!right.has(pid)) {
      return false;
    }
  }
  return true;
}

function visibleWindows(image) {
  const script =
    `Get-Process ${image} -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | ` +
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

const META = {
  _meta: {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
    "io.modelcontextprotocol/clientCapabilities": {},
  },
};

function toolPayload(reply) {
  const text = reply?.result?.content?.[0]?.text ?? null;
  if (text === null) {
    throw new Error(`tool reply has no text: ${JSON.stringify(reply).slice(0, 500)}`);
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

async function openSession(mcp, engine) {
  const opened = toolPayload(await mcp.call("session_open", { engine }));
  assertEqual(`${engine} session`, opened.engine, engine);
  return opened.session_id;
}

async function closeSession(mcp, sid) {
  await mcp.call("debug_close", { session_id: sid }).catch(() => undefined);
  await mcp.call("session_close", { session_id: sid }).catch(() => undefined);
}

async function runConfirmGate(mcp) {
  const sid = await openSession(mcp, "cdb");
  const before = pidsOf("cdb.exe");
  const tools = [
    ["debug_memory", { action: "read", address: "0x140001000", size: 16 }],
    ["debug_code", { action: "disassemble", address: "0x140001000" }],
    ["debug_thread", { action: "list" }],
    ["debug_plugin", { action: "status" }],
    ["debug_time", { action: "snapshot" }],
  ];
  for (const [name, args] of tools) {
    const blocked = toolPayload(await mcp.call(name, { session_id: sid, ...args }));
    assertEqual(`${name} needs confirm`, blocked.error, "confirmation_required");
  }
  assertEqual("confirm gate starts no cdb", samePids(pidsOf("cdb.exe"), before), true);
  const denied = toolPayload(
    await mcp.call("debug_memory", { session_id: sid, confirm: true, action: "read", address: "0x140001000", size: 4 }),
  );
  assertEqual("confirm without a target", denied.error, "target_not_open");
  assertEqual("confirmed read starts no cdb before debug_open", samePids(pidsOf("cdb.exe"), before), true);
  const plugin = toolPayload(await mcp.call("debug_plugin", { session_id: sid, confirm: true, action: "status" }));
  assertEqual("cdb scylla unsupported", plugin.error, "capability_unsupported");
  await closeSession(mcp, sid);

  const r2 = await openSession(mcp, "radare2");
  const staticCall = toolPayload(
    await mcp.call("debug_memory", { session_id: r2, confirm: true, action: "read", address: "0x1000", size: 4 }),
  );
  assertEqual("static session rejected", staticCall.error, "capability_unsupported");
  await mcp.call("session_close", { session_id: r2 });
}

async function runCdb(mcp) {
  const sid = await openSession(mcp, "cdb");
  try {
    const info = toolPayload(await mcp.call("debug_open", { session_id: sid, path: FIX_X64 }));
    assertEqual("cdb open", info.engine, "cdb");
    assertEqual("cdb no window", visibleWindows("cdb"), []);
    const entry = `0x${ENTRY.toString(16)}`;
    const cont = toolPayload(await mcp.call("debug_continue", { session_id: sid }));
    assertEqual("cdb reached entry", hexEq(cont.address, entry), true);

    const read = toolPayload(
      await mcp.call("debug_memory", { session_id: sid, confirm: true, action: "read", address: entry, size: 16 }),
    );
    assertEqual("cdb read mov", read.hex?.startsWith("b834120000"), true);
    const dumped = toolPayload(
      await mcp.call("debug_memory", { session_id: sid, confirm: true, action: "dump", address: entry, size: 8 }),
    );
    assertEqual("cdb dump", dumped.action, "dump");
    assertEqual("cdb dump bytes", dumped.hex?.startsWith("b834120000"), true);
    const found = toolPayload(
      await mcp.call("debug_memory", {
        session_id: sid,
        confirm: true,
        action: "search",
        pattern: "b8 34 12 00",
        start_address: `0x${BASE.toString(16)}`,
        length: 0x2000,
      }),
    );
    const hit = (found.matches ?? []).some((row) => hexEq(row.address, entry));
    assertEqual("cdb search hits entry", hit, true);

    const dis = toolPayload(
      await mcp.call("debug_code", { session_id: sid, confirm: true, action: "disassemble", address: entry, count: 4 }),
    );
    assertEqual("cdb disasm mov", /mov/i.test(dis.instructions?.[0]?.mnemonic ?? ""), true);
    const asm = toolPayload(
      await mcp.call("debug_code", {
        session_id: sid,
        confirm: true,
        action: "assemble",
        address: entry,
        instruction: "nop",
      }),
    );
    assertEqual("cdb assemble unsupported", asm.error, "capability_unsupported");

    const threads = toolPayload(await mcp.call("debug_thread", { session_id: sid, confirm: true, action: "list" }));
    assertEqual("cdb has a thread", (threads.threads ?? []).length > 0, true);
    const tid = threads.threads?.[0]?.id;
    const ctx = toolPayload(
      await mcp.call("debug_thread", { session_id: sid, confirm: true, action: "context", thread_id: tid }),
    );
    assertEqual("cdb thread rip", hexEq(ctx.general?.rip, entry), true);
    const frozen = toolPayload(
      await mcp.call("debug_thread", { session_id: sid, confirm: true, action: "freeze", thread_id: tid }),
    );
    const froze = (frozen.threads ?? []).some((row) => row.id === tid && /frozen/i.test(row.state ?? ""));
    assertEqual("cdb freeze", froze, true);
    const thawed = toolPayload(
      await mcp.call("debug_thread", { session_id: sid, confirm: true, action: "thaw", thread_id: tid }),
    );
    const thaw = (thawed.threads ?? []).some((row) => row.id === tid && /unfrozen/i.test(row.state ?? ""));
    assertEqual("cdb thaw", thaw, true);

    const shot = toolPayload(
      await mcp.call("debug_time", { session_id: sid, confirm: true, action: "snapshot", memory_size: 16 }),
    );
    assertEqual("cdb snapshot address", hexEq(shot.checkpoint?.address, entry), true);
    const ran = toolPayload(
      await mcp.call("debug_code", { session_id: sid, confirm: true, action: "run_to", address: `0x${(ENTRY + 5n).toString(16)}` }),
    );
    assertEqual("cdb run_to", hexEq(ran.address, ENTRY + 5n), true);
    const regs = toolPayload(await mcp.call("debug_registers", { session_id: sid }));
    assertEqual("cdb eax after mov", hexEq(regs.general?.rax ?? regs.general?.eax, "0x1234"), true);
    const back = toolPayload(
      await mcp.call("debug_time", { session_id: sid, confirm: true, action: "rewind", checkpoint_id: shot.checkpoint.id }),
    );
    assertEqual("cdb rewind memory", back.memory_restored, true);
    assertEqual("cdb rewind registers", back.registers_restored, true);
    const after = toolPayload(await mcp.call("debug_registers", { session_id: sid }));
    assertEqual("cdb rip restored", hexEq(after.general?.rip, entry), true);
    const line = toolPayload(await mcp.call("debug_time", { session_id: sid, confirm: true, action: "timeline" }));
    assertEqual("cdb timeline", (line.checkpoints ?? []).length >= 1, true);
    assertEqual("cdb still windowless", visibleWindows("cdb"), []);
  } finally {
    await closeSession(mcp, sid);
  }
}

async function runFrida(mcp) {
  const sid = await openSession(mcp, "frida");
  try {
    const info = toolPayload(await mcp.call("debug_open", { session_id: sid, path: FIX_X64 }));
    assertEqual("frida open", info.engine, "frida");
    const entry = `0x${ENTRY.toString(16)}`;
    const read = toolPayload(
      await mcp.call("debug_memory", { session_id: sid, confirm: true, action: "read", address: entry, size: 16 }),
    );
    assertEqual("frida read mov", read.hex?.startsWith("b834120000"), true);
    const dis = toolPayload(
      await mcp.call("debug_code", { session_id: sid, confirm: true, action: "disassemble", address: entry, count: 4 }),
    );
    assertEqual("frida disasm mov", /mov/i.test(dis.instructions?.[0]?.mnemonic ?? ""), true);
    const found = toolPayload(
      await mcp.call("debug_memory", {
        session_id: sid,
        confirm: true,
        action: "search",
        pattern: "b8341200",
        start_address: entry,
        length: 32,
      }),
    );
    assertEqual("frida search", (found.matches ?? []).length >= 1, true);
    const threads = toolPayload(await mcp.call("debug_thread", { session_id: sid, confirm: true, action: "list" }));
    assertEqual("frida threads", (threads.threads ?? []).length > 0, true);
    const freeze = toolPayload(
      await mcp.call("debug_thread", { session_id: sid, confirm: true, action: "freeze", thread_id: threads.threads[0].id }),
    );
    assertEqual("frida freeze unsupported", freeze.error, "capability_unsupported");
    const asm = toolPayload(
      await mcp.call("debug_code", {
        session_id: sid,
        confirm: true,
        action: "assemble",
        address: entry,
        instruction: "nop",
      }),
    );
    assertEqual("frida assemble unsupported", asm.error, "capability_unsupported");
    const shot = toolPayload(await mcp.call("debug_time", { session_id: sid, confirm: true, action: "snapshot" }));
    assertEqual("frida snapshot", typeof shot.checkpoint?.id, "string");
    const ran = toolPayload(
      await mcp.call("debug_code", { session_id: sid, confirm: true, action: "run_to", address: `0x${(ENTRY + 5n).toString(16)}` }),
    );
    assertEqual("frida run_to", hexEq(ran.address, ENTRY + 5n), true);
    const back = toolPayload(
      await mcp.call("debug_time", { session_id: sid, confirm: true, action: "rewind", checkpoint_id: shot.checkpoint.id }),
    );
    assertEqual(
      "frida memory restored",
      { memory: back.memory_restored ?? null, error: back.error ?? null, detail: back.detail ?? null },
      { memory: true, error: null, detail: null },
    );
    const again = toolPayload(
      await mcp.call("debug_memory", { session_id: sid, confirm: true, action: "read", address: entry, size: 1 }),
    );
    assertEqual("frida entry byte intact", again.hex, "b8");
  } finally {
    await closeSession(mcp, sid);
  }
}

async function runX64dbg(mcp) {
  const sid = await openSession(mcp, "x64dbg");
  const before = pidsOf("x64dbg.exe");
  try {
    const blocked = toolPayload(await mcp.call("debug_plugin", { session_id: sid, action: "status" }));
    assertEqual("plugin needs confirm", blocked.error, "confirmation_required");
    const status = toolPayload(await mcp.call("debug_plugin", { session_id: sid, confirm: true, action: "status" }));
    const gui = (status.installs ?? []).some((row) => row.arch === "x64" && row.gui_dll_present === true);
    assertEqual("scylla gui dll present", gui, true);
    assertEqual("status opens no window", status.window_opened, false);
    assertEqual("status starts no debugger", samePids(pidsOf("x64dbg.exe"), before), true);
    const dump = toolPayload(await mcp.call("debug_plugin", { session_id: sid, confirm: true, action: "dump" }));
    assertEqual("scylla dump unavailable", dump.error, "engine_unavailable");
    assertEqual("scylla gui not launched", /will not be launched/i.test(dump.detail ?? ""), true);
    const hide = toolPayload(await mcp.call("debug_plugin", { session_id: sid, confirm: true, action: "hide" }));
    assertEqual("scyllahide missing", hide.error, "engine_unavailable");
    assertEqual("scyllahide path", /plugins/i.test(hide.detail ?? ""), true);
    assertEqual("plugin calls start no debugger", samePids(pidsOf("x64dbg.exe"), before), true);

    const info = toolPayload(await mcp.call("debug_open", { session_id: sid, path: FIX_X64, auto_analyze: false }));
    assertEqual("x64dbg open", info.engine, "x64dbg");
    const entry = info.module_entry;
    assertEqual("x64dbg entry", hexEq(entry, ENTRY), true);
    const read = toolPayload(
      await mcp.call("debug_memory", { session_id: sid, confirm: true, action: "read", address: entry, size: 16 }),
    );
    // The entry breakpoint shows up as CC in live memory. The mov immediate is still there.
    assertEqual("x64dbg read mov immediate", read.hex?.includes("34120000"), true);
    const dis = toolPayload(
      await mcp.call("debug_code", { session_id: sid, confirm: true, action: "disassemble", count: 4 }),
    );
    assertEqual("x64dbg disasm at stopped address", hexEq(dis.instructions?.[0]?.address, dis.address), true);
    assertEqual("x64dbg disasm mnemonic", (dis.instructions?.[0]?.mnemonic ?? "").length > 0, true);
    const atEntry = toolPayload(
      await mcp.call("debug_code", { session_id: sid, confirm: true, action: "disassemble", address: entry, count: 2 }),
    );
    assertEqual("x64dbg disasm at entry", hexEq(atEntry.instructions?.[0]?.address, entry), true);
    const threads = toolPayload(await mcp.call("debug_thread", { session_id: sid, confirm: true, action: "list" }));
    assertEqual("x64dbg threads", (threads.threads ?? []).length > 0, true);
    const ran = toolPayload(
      await mcp.call("debug_code", { session_id: sid, confirm: true, action: "run_to", address: `0x${(ENTRY + 5n).toString(16)}` }),
    );
    assertEqual("x64dbg run_to", ran.reached === true || hexEq(ran.address, ENTRY + 5n), true);
    const regs = toolPayload(await mcp.call("debug_registers", { session_id: sid }));
    assertEqual("x64dbg eax after mov", hexEq(regs.general?.rax ?? regs.general?.eax, "0x1234"), true);
    const shot = toolPayload(
      await mcp.call("debug_time", { session_id: sid, confirm: true, action: "snapshot", memory_size: 16 }),
    );
    const windowAddr = shot.checkpoint?.memoryAddress;
    const beforeByte = shot.checkpoint?.memoryHex?.slice(0, 2);
    const asm = toolPayload(
      await mcp.call("debug_code", {
        session_id: sid,
        confirm: true,
        action: "assemble",
        address: windowAddr,
        instruction: "nop",
      }),
    );
    assertEqual("x64dbg assemble nop", asm.bytes, "90");
    const nop = toolPayload(
      await mcp.call("debug_memory", { session_id: sid, confirm: true, action: "read", address: windowAddr, size: 1 }),
    );
    assertEqual("x64dbg wrote nop", nop.hex, "90");
    const back = toolPayload(
      await mcp.call("debug_time", { session_id: sid, confirm: true, action: "rewind", checkpoint_id: shot.checkpoint.id }),
    );
    assertEqual("x64dbg rewind registers", back.registers_restored, true);
    assertEqual("x64dbg rewind memory", back.memory_restored, true);
    const after = toolPayload(await mcp.call("debug_registers", { session_id: sid }));
    assertEqual("x64dbg rip restored", hexEq(after.general?.rip, shot.checkpoint.address), true);
    const original = toolPayload(
      await mcp.call("debug_memory", { session_id: sid, confirm: true, action: "read", address: windowAddr, size: 1 }),
    );
    assertEqual("x64dbg restored byte", original.hex, beforeByte);
    const tid = threads.threads[0].id;
    const frozen = toolPayload(
      await mcp.call("debug_thread", { session_id: sid, confirm: true, action: "freeze", thread_id: tid }),
    );
    assertEqual(
      "x64dbg freeze",
      { frozen: frozen.frozen ?? null, error: frozen.error ?? null, detail: frozen.detail ?? null },
      { frozen: true, error: null, detail: null },
    );
    const thawed = toolPayload(
      await mcp.call("debug_thread", { session_id: sid, confirm: true, action: "thaw", thread_id: tid }),
    );
    assertEqual("x64dbg thaw", thawed.frozen, false);
  } finally {
    await closeSession(mcp, sid);
  }
}

async function main() {
  for (const [label, path] of [
    ["dist/server.js", SERVER_JS],
    ["mini_pe_x64.exe", FIX_X64],
  ]) {
    try {
      readFileSync(path);
    } catch {
      console.log(`missing ${label} (${path})`);
      process.exit(2);
    }
  }
  const mcp = new StdioMcp();
  await mcp.start();
  try {
    await runConfirmGate(mcp);
    await runCdb(mcp);
    await runFrida(mcp);
    await runX64dbg(mcp);
  } catch (error) {
    fail("suite", error instanceof Error ? (error.stack ?? error.message) : String(error));
  } finally {
    await mcp.stop();
  }
  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
