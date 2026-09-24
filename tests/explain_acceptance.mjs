#!/usr/bin/env node
/**
 * Turkish assembly reading, and download hints for missing programs.
 * Does not launch a debugger.
 */
import { spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_JS = join(ROOT, "dist", "server.js");
const EXPLAIN_JS = join(ROOT, "dist", "explain.js");
const CATALOG_JS = join(ROOT, "dist", "catalog.js");
const GOLDEN = join(ROOT, "tests", "golden", "expected", "disassemble.entry0.json");
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

  request(method, params, timeoutMs = 30000) {
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

const { explainRegion } = await import(pathToFileURL(EXPLAIN_JS).href);
const { suggestDownload } = await import(pathToFileURL(CATALOG_JS).href);

const golden = JSON.parse(readFileSync(GOLDEN, "utf8"));
const reading = explainRegion(golden.ops);
assertEqual("dil", reading.dil, "tr");
assertEqual("atlama var", /atlar/.test(reading.ozet), true);
assertEqual("je hedefi", reading.atlamalar.some((row) => row.hedef === "0x40021b"), true);
const je = reading.satirlar.find((row) => row.kod.startsWith("je"));
assertEqual("je satırı", /0x40021b/.test(je?.anlam ?? "") && /atlar/.test(je?.anlam ?? ""), true);

const notice = explainRegion([
  { address: "0x401000", opcode: "call MessageBoxA" },
  { address: "0x401005", opcode: "ret" },
]);
assertEqual("bildirim adı", notice.bildirimler[0]?.ad?.toLowerCase(), "messageboxa");
assertEqual("bildirim özeti", /bildirim/i.test(notice.ozet), true);

const loop = explainRegion([{ address: "0x401010", opcode: "jmp 0x401000", jump: "0x401000" }]);
assertEqual("döngü", /döngü/.test(loop.ozet), true);

const hint = suggestDownload("cdb");
assertEqual("cdb indirme adresi", hint.includes("https://developer.microsoft.com/"), true);

const mcp = new StdioMcp();
await mcp.start();
try {
  const report = toolPayload(await mcp.call("prerequisites", {}));
  assertEqual("özet metni", typeof report.ozet, "string");
  const ids = (report.araclar ?? []).map((row) => row.id);
  assertEqual(
    "araç kimlikleri",
    ["radare2", "graphviz", "x64dbg", "python64", "python32", "cdb", "frida", "scyllahide"].every((id) => ids.includes(id)),
    true,
  );
  for (const row of report.araclar ?? []) {
    if (row.durum === "yok") {
      assertEqual(`${row.id} indir`, typeof row.indir === "string" && row.indir.startsWith("https://"), true);
      assertEqual(`${row.id} öneri`, typeof row.oneri === "string" && row.oneri.length > 0, true);
    } else {
      assertEqual(`${row.id} var`, row.durum, "var");
    }
  }

  const pasted = toolPayload(
    await mcp.call("explain", {
      instructions: [{ address: "0x401000", opcode: "call printf" }, { address: "0x401005", opcode: "ret" }],
    }),
  );
  assertEqual("yapıştırılan kaynak", pasted.kaynak, "verilen_komutlar");
  assertEqual("printf bildirim", pasted.bildirimler?.[0]?.ad, "printf");

  const before = pidsOf("x64dbg.exe");
  const opened = toolPayload(await mcp.call("session_open", { engine: "x64dbg" }));
  const blocked = toolPayload(await mcp.call("explain", { session_id: opened.session_id, address: "0x140001000" }));
  assertEqual("canlı açıklama onay ister", blocked.error, "confirmation_required");
  assertEqual("onaysız açıklama x64dbg başlatmaz", [...pidsOf("x64dbg.exe")].sort().join(","), [...before].sort().join(","));
  await mcp.call("session_close", { session_id: opened.session_id });
} catch (error) {
  fail("suite", error instanceof Error ? (error.stack ?? error.message) : String(error));
} finally {
  await mcp.stop();
}

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
