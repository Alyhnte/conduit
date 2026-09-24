#!/usr/bin/env node
/**
 * Golden-output tests for Conduit (fixture: examples/target/mini_branch.elf).
 *
 * What it checks:
 *  1. determinism — gen_mini_branch.py regenerates the committed .elf byte-for-byte
 *  2. goldens     — live engine output matches tests/golden/expected/*, after the
 *                   documented normalizations below (exact where stable, structural
 *                   where radare2 versions legitimately differ in formatting)
 *  3. cfg render  — the live CFG DOT parses with `dot -Tcanon`
 *  4. e2e stdio   — real MCP session over stdio: discover, session_open,
 *                   open_target, disassemble (compared to the same golden),
 *                   get_cfg, events_pull, plus both negative paths
 *  5. e2e http    — same over Streamable HTTP (/health + /mcp)
 *
 * Normalizations (goldens were captured with radare2 6.2.2; other 6.x/5.x
 * releases must still pass as long as the bytes/addresses/shape agree):
 *  - disasm/xrefs opcodes: collapse whitespace, fold `0x…` immediates and
 *    `str.NAME` flag spellings; addresses/sizes/bytes/types/jump/fail exact
 *  - cfg json: function header + per-block addr/size/jump/fail exact,
 *    per-op addr/size/bytes/type exact, opcode normalized; esil/disasm text,
 *    flags, comments, type_num and xref decorations ignored
 *  - cfg dot: node-address set + edge set exact, `dot -Tcanon` must parse;
 *    label prose ignored (r2 versions reword comments)
 *  - dump hex: ANSI color escapes stripped, then exact text match
 *    (the engine leaves r2 color codes in `px` output; stripping here keeps
 *    the golden readable without touching engine code)
 *  - strings / dump-bytes: exact match, no normalization
 *  - session ids, timestamps, absolute paths: never stored in goldens
 *
 * Usage:
 *   node tests/run_golden.mjs            # compare against goldens (== npm test)
 *   node tests/run_golden.mjs --update   # re-capture tests/golden/expected/*
 *
 * Prereqs: `npm run build` once, `r2` + `dot` + `python3` on PATH.
 * Env: DBG_BRIDGE_TEST_HTTP_PORT (default 3877; next free port up to +16 tried).
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_JS = join(ROOT, "dist", "server.js");
const R2_ENGINE_JS = join(ROOT, "dist", "engines", "radare2.js");
const TARGET_DIR = join(ROOT, "examples", "target");
const FIXTURE_ELF = join(TARGET_DIR, "mini_branch.elf");
const GEN_SCRIPT = join(TARGET_DIR, "gen_mini_branch.py");
const EXPECTED_DIR = join(ROOT, "tests", "golden", "expected");

const UPDATE = process.argv.includes("--update");
const PROTOCOL = "2026-07-28";
const ENTRY = "entry0";
const RODATA = "0x400300";
const TEXT_BASE = "0x400200";
const TEXT_LEN = 34; // len(.text): entry + unreachable pad + tail

let failures = 0;
let passes = 0;

function pass(name) {
  passes += 1;
  console.log(`ok   ${name}`);
}

function fail(name, detail) {
  failures += 1;
  console.log(`FAIL ${name}`);
  for (const line of String(detail).split("\n").slice(0, 25)) {
    console.log(`     ${line}`);
  }
}

function assertEqual(name, actual, expected) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) {
    pass(name);
    return true;
  }
  fail(name, `expected: ${e.slice(0, 600)}\nactual:   ${a.slice(0, 600)}`);
  return false;
}

function readGolden(name) {
  return readFileSync(join(EXPECTED_DIR, name), "utf8");
}

function readGoldenJson(name) {
  return JSON.parse(readGolden(name));
}

function writeGolden(name, text) {
  writeFileSync(join(EXPECTED_DIR, name), text.endsWith("\n") ? text : `${text}\n`, "utf8");
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// normalizers
// ---------------------------------------------------------------------------

/** Opcode text modulo r2-version formatting: spacing, immediates, str flags. */
function normOpcode(opcode) {
  return String(opcode)
    .replace(/\s+/g, " ")
    .replace(/0x[0-9a-fA-F]+/g, "0x…")
    .replace(/str\.[A-Za-z0-9_]+/g, "str.NAME")
    .replace(/\[rip\s*\+\s*0x…\]/g, "[rip+0x…]")
    .trim();
}

function normDisasmOp(op) {
  return {
    address: op.address,
    size: op.size,
    bytes: op.bytes,
    opcode: normOpcode(op.opcode),
    type: op.type,
    ...(op.jump !== undefined ? { jump: op.jump } : {}),
    ...(op.fail !== undefined ? { fail: op.fail } : {}),
  };
}

function normCfgOp(op) {
  return {
    addr: op.addr,
    size: op.size,
    bytes: op.bytes,
    type: op.type,
    opcode: normOpcode(op.opcode ?? op.disasm ?? ""),
  };
}

function normCfgBlock(block) {
  return {
    addr: block.addr,
    size: block.size,
    ...(block.jump !== undefined ? { jump: block.jump } : {}),
    ...(block.fail !== undefined ? { fail: block.fail } : {}),
    ops: (block.ops ?? []).map(normCfgOp),
  };
}

function normCfgJson(json) {
  return (json ?? []).map((fn) => ({
    name: fn.name,
    addr: fn.addr,
    size: fn.size,
    blocks: (fn.blocks ?? []).map(normCfgBlock),
  }));
}

/** Node-address set + edge set of a DOT graph (label prose ignored). */
function dotStructure(dot) {
  const nodes = new Set();
  for (const m of String(dot).matchAll(/"(0x[0-9a-fA-F]+)"\s*\[/g)) {
    nodes.add(m[1].toLowerCase());
  }
  const edges = new Set();
  for (const m of String(dot).matchAll(/"(0x[0-9a-fA-F]+)"\s*->\s*"(0x[0-9a-fA-F]+)"/g)) {
    edges.add(`${m[1].toLowerCase()}->${m[2].toLowerCase()}`);
  }
  return { nodes: [...nodes].sort(), edges: [...edges].sort() };
}

function stripAnsi(text) {
  // eslint-disable-next-line no-control-regex
  return String(text).replace(/\u001b\[[0-9;]*m/g, "");
}

function normHexdump(text) {
  return stripAnsi(text)
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n")
    .trim();
}

function normXref(op) {
  return {
    from: op.from,
    ...(op.to !== undefined ? { to: String(op.to).replace(/^str\..*$/, "str.NAME") } : {}),
    type: op.type,
    ...(op.opcode !== undefined ? { opcode: normOpcode(op.opcode) } : {}),
    ...(op.function !== undefined ? { function: op.function } : {}),
  };
}

// ---------------------------------------------------------------------------
// prereqs
// ---------------------------------------------------------------------------

function which(cmd) {
  const probe = process.platform === "win32" ? "where" : "which";
  const res = spawnSync(probe, [cmd], { encoding: "utf8" });
  return res.status === 0 ? res.stdout.split(/\r?\n/)[0].trim() : null;
}

function checkPrereqs() {
  const problems = [];
  for (const [label, path] of [
    ["dist/server.js", SERVER_JS],
    ["dist/engines/radare2.js", R2_ENGINE_JS],
    ["fixture", FIXTURE_ELF],
    ["generator", GEN_SCRIPT],
  ]) {
    try {
      readFileSync(path);
    } catch {
      problems.push(`${label} missing (${path})`);
    }
  }
  const r2 = which("radare2") ?? which("r2");
  if (r2 === null) problems.push("radare2 not on PATH (install a prebuilt r2 release)");
  const dot = which("dot");
  if (dot === null) problems.push("graphviz `dot` not on PATH");
  const python = which("python") ?? which("python3");
  if (python === null) problems.push("python not on PATH (needed to regenerate the fixture)");
  if (problems.length > 0) {
    console.log("prereq check FAILED:");
    for (const p of problems) console.log(`  - ${p}`);
    console.log("See README.md “Prerequisites”.");
    process.exit(2);
  }
  pass(`prereqs (r2: ${r2}, dot: ${dot}, python: ${python})`);
  return { r2, dot, python };
}

// ---------------------------------------------------------------------------
// 1. determinism: committed .elf == fresh generator output
// ---------------------------------------------------------------------------

function checkDeterminism(python) {
  const dir = mkdtempSync(join(tmpdir(), "mini-branch-"));
  const out = join(dir, "mini_branch.elf");
  const res = spawnSync(python, [GEN_SCRIPT, out], { encoding: "utf8" });
  if (res.status !== 0) {
    fail("determinism: generator runs", res.stderr || res.stdout || `exit ${res.status}`);
    return false;
  }
  const fresh = readFileSync(out);
  const committed = readFileSync(FIXTURE_ELF);
  const hex = (buf) => createHash("sha256").update(buf).digest("hex");
  if (Buffer.compare(fresh, committed) !== 0) {
    fail(
      "determinism: committed .elf matches generator",
      `committed sha256 ${hex(committed)}\nregenerated sha256 ${hex(fresh)}\n` +
        "re-run the generator and commit the result, or fix the drift.",
    );
    return false;
  }
  pass(`determinism: mini_branch.elf (${committed.length} bytes, sha256 ${hex(committed).slice(0, 16)}…)`);
  return true;
}

// ---------------------------------------------------------------------------
// 2. goldens via the engine (dist build, same code the MCP tools drive)
// ---------------------------------------------------------------------------

async function collectEngineOutputs() {
  const { radare2Engine } = await import(pathToFileURL(R2_ENGINE_JS).href);
  const sid = randomUUID();
  await radare2Engine.open(sid, FIXTURE_ELF);
  try {
    const dis = await radare2Engine.disassemble(sid, {});
    const cfg = await radare2Engine.getCfg(sid, { format: "both" });
    const strings = await radare2Engine.strings(sid, {});
    const dumpHex = await radare2Engine.dump(sid, { address: TEXT_BASE, length: TEXT_LEN, format: "hex" });
    const dumpJson = await radare2Engine.dump(sid, {
      address: TEXT_BASE,
      length: TEXT_LEN,
      format: "json",
    });
    const xrefs = await radare2Engine.xrefs(sid, { address: RODATA, direction: "both" });
    return { dis, cfg, strings, dumpHex, dumpJson, xrefs };
  } finally {
    await radare2Engine.close(sid);
  }
}

function updateGoldens(o) {
  mkdirSync(EXPECTED_DIR, { recursive: true });
  writeGolden("disassemble.entry0.json", stableJson(o.dis));
  writeGolden("cfg.entry0.fn.json", stableJson({ location: o.cfg.location, function: o.cfg.function }));
  writeGolden("cfg.entry0.json", stableJson(o.cfg.json));
  writeGolden("cfg.entry0.dot", `${String(o.cfg.dot).trim()}\n`);
  writeGolden("strings.json", stableJson(o.strings));
  writeGolden(
    "dump.hex.txt",
    `${normHexdump(o.dumpHex.text ?? "")}\n`,
  );
  writeGolden("dump.json.json", stableJson(o.dumpJson));
  writeGolden("xrefs.rodata.json", stableJson(o.xrefs));
  console.log("goldens re-captured in tests/golden/expected/ — inspect the diff before committing.");
}

function compareGoldens(o) {
  // disassembly: location + count exact, ops normalized
  const expDis = readGoldenJson("disassemble.entry0.json");
  assertEqual("golden disassemble.location", o.dis.location, expDis.location);
  assertEqual("golden disassemble.count", o.dis.count, expDis.count);
  assertEqual(
    "golden disassemble.ops",
    (o.dis.ops ?? []).map(normDisasmOp),
    (expDis.ops ?? []).map(normDisasmOp),
  );

  // cfg: function header exact, blocks structural
  const expFn = readGoldenJson("cfg.entry0.fn.json");
  assertEqual("golden cfg.location", o.cfg.location, expFn.location);
  assertEqual("golden cfg.function", o.cfg.function, expFn.function);
  assertEqual(
    "golden cfg.json",
    normCfgJson(o.cfg.json),
    normCfgJson(readGoldenJson("cfg.entry0.json")),
  );

  // dot: node/edge sets exact (label prose ignored)
  const expDot = readGolden("cfg.entry0.dot");
  if (!String(o.cfg.dot).trimStart().startsWith("digraph")) {
    fail("golden cfg.dot shape", `DOT does not start with "digraph": ${String(o.cfg.dot).slice(0, 120)}`);
  } else {
    pass("golden cfg.dot shape");
  }
  assertEqual("golden cfg.dot nodes+edges", dotStructure(o.cfg.dot), dotStructure(expDot));

  // strings: exact
  assertEqual("golden strings", o.strings, readGoldenJson("strings.json"));

  // dump: hex exact after ANSI strip, bytes exact
  assertEqual("golden dump.hex", normHexdump(o.dumpHex.text ?? ""), readGolden("dump.hex.txt").trim());
  assertEqual("golden dump.json", o.dumpJson, readGoldenJson("dump.json.json"));

  // xrefs to .rodata: normalized (flag spellings drift across r2 versions)
  const expXr = readGoldenJson("xrefs.rodata.json");
  assertEqual("golden xrefs.address", o.xrefs.address, expXr.address);
  assertEqual(
    "golden xrefs.to",
    (o.xrefs.to ?? []).map(normXref),
    (expXr.to ?? []).map(normXref),
  );
  assertEqual(
    "golden xrefs.from",
    (o.xrefs.from ?? []).map(normXref),
    (expXr.from ?? []).map(normXref),
  );
}

// ---------------------------------------------------------------------------
// 3. cfg renders with graphviz
// ---------------------------------------------------------------------------

function checkDotParses(dotBin, dotText) {
  const dir = mkdtempSync(join(tmpdir(), "cfg-dot-"));
  const dotFile = join(dir, "cfg.dot");
  writeFileSync(dotFile, dotText, "utf8");
  const canon = spawnSync(dotBin, ["-Tcanon", dotFile], { encoding: "utf8" });
  if (canon.status !== 0) {
    fail("graphviz: dot -Tcanon parses cfg.dot", canon.stderr?.slice(0, 400) ?? `exit ${canon.status}`);
    return;
  }
  const pngFile = join(dir, "cfg.png");
  const png = spawnSync(dotBin, ["-Tpng", dotFile, "-o", pngFile], { encoding: "utf8" });
  if (png.status !== 0) {
    fail("graphviz: dot -Tpng renders cfg.png", png.stderr?.slice(0, 400) ?? `exit ${png.status}`);
    return;
  }
  pass("graphviz: cfg.dot parses (-Tcanon) and renders (-Tpng)");
}

// ---------------------------------------------------------------------------
// 4-5. end-to-end over the real MCP transports (raw JSON-RPC, no test-only
// client: this is exactly what Cursor/Claude/Cline/OpenCode speak)
// ---------------------------------------------------------------------------

const META = {
  _meta: {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
    "io.modelcontextprotocol/clientCapabilities": {},
  },
};

function toolText(reply) {
  return reply?.result?.content?.[0]?.text ?? null;
}

function toolPayload(reply) {
  const text = toolText(reply);
  if (text === null) throw new Error(`tool reply has no text content: ${JSON.stringify(reply).slice(0, 300)}`);
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
    // The server speaks only after the first request; a bad spawn surfaces
    // as a timeout on discover, reported with stderr below.
    await new Promise((r) => setTimeout(r, 300));
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

  call(name, args) {
    return this.request("tools/call", { ...META, name, arguments: args });
  }

  async stop() {
    try {
      this.child.kill();
    } catch {
      // already gone
    }
  }
}

class HttpMcp {
  constructor(port) {
    this.port = port;
    this.id = 0;
  }

  async request(method, params, name) {
    const id = (this.id += 1);
    const res = await fetch(`http://127.0.0.1:${this.port}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-method": method,
        ...(name !== undefined ? { "mcp-name": name } : {}),
      },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`http ${method} -> ${res.status}: ${text.slice(0, 300)}`);
    return JSON.parse(text);
  }

  call(tool, args) {
    return this.request("tools/call", { ...META, name: tool, arguments: args }, tool);
  }
}

async function spawnHttpServer(preferredPort) {
  for (let port = preferredPort; port < preferredPort + 16; port += 1) {
    const child = spawn(process.execPath, [SERVER_JS, "--transport", "http", "--port", String(port)], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (c) => {
      stderr += c.toString("utf8");
    });
    const healthy = await waitForHealth(port, 10000);
    if (healthy) return { child, port };
    try {
      child.kill();
    } catch {
      // already gone
    }
    if (!/EADDRINUSE|listen/.test(stderr)) {
      throw new Error(`http server failed to boot on port ${port}: ${stderr.slice(0, 300)}`);
    }
  }
  throw new Error(`no free http port in ${preferredPort}..${preferredPort + 15}`);
}

async function waitForHealth(port, budgetMs) {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      if (res.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

/** Same E2E script against either transport; label is "stdio"/"http". */
async function runE2E(label, mcp) {
  const tag = (n) => `e2e ${label}: ${n}`;

  const discover = await mcp.request("server/discover", { ...META });
  assertEqual(`${tag("discover protocol")}`, discover?.result?.supportedVersions, [PROTOCOL]);

  const health = toolPayload(await mcp.call("health", {}));
  assertEqual(`${tag("health")}`, { status: health.status, name: health.name }, { status: "ok", name: "conduit" });

  const opened = toolPayload(await mcp.call("session_open", { engine: "radare2" }));
  const sid = opened.session_id;
  if (typeof sid !== "string" || sid.length < 8) {
    fail(tag("session_open"), JSON.stringify(opened).slice(0, 300));
    return;
  }
  pass(tag("session_open"));

  const target = toolPayload(await mcp.call("open_target", { session_id: sid, path: FIXTURE_ELF, mode: "static" }));
  assertEqual(`${tag("open_target")}`, { opened: target.opened, engine: target.engine }, { opened: true, engine: "radare2" });

  const dis = toolPayload(await mcp.call("disassemble", { session_id: sid }));
  const expDis = readGoldenJson("disassemble.entry0.json");
  assertEqual(
    tag("disassemble == golden"),
    (dis.ops ?? []).map(normDisasmOp),
    (expDis.ops ?? []).map(normDisasmOp),
  );

  const cfg = toolPayload(await mcp.call("get_cfg", { session_id: sid, format: "both" }));
  assertEqual(
    tag("get_cfg == golden"),
    dotStructure(cfg.dot),
    dotStructure(readGolden("cfg.entry0.dot")),
  );

  const events = toolPayload(await mcp.call("events_pull", { session_id: sid }));
  const kinds = (events.events ?? []).map((e) => e.kind);
  if (kinds.includes("target.opened")) {
    pass(tag("events_pull has target.opened"));
  } else {
    fail(tag("events_pull has target.opened"), JSON.stringify(kinds));
  }

  // negative paths: capability errors, never stubs or crashes
  const badMode = toolPayload(await mcp.call("open_target", { session_id: sid, path: FIXTURE_ELF, mode: "debug" }));
  assertEqual(`${tag("open_target mode=debug rejected")}`, badMode.error, "capability_unsupported");

  const xdbg = toolPayload(await mcp.call("session_open", { engine: "x64dbg" }));
  const xres = toolPayload(await mcp.call("disassemble", { session_id: xdbg.session_id }));
  assertEqual(`${tag("static tool on x64dbg rejected")}`, xres.error, "capability_unsupported");

  const closed = toolPayload(await mcp.call("session_close", { session_id: sid }));
  assertEqual(`${tag("session_close")}`, closed.closed, true);
  await mcp.call("session_close", { session_id: xdbg.session_id });
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  const { dot, python } = checkPrereqs();

  if (!checkDeterminism(python) && !UPDATE) {
    console.log(`\n${passes} passed, ${failures} failed`);
    process.exit(1);
  }

  let engine;
  try {
    engine = await collectEngineOutputs();
  } catch (error) {
    fail("engine: collect outputs", error instanceof Error ? error.stack ?? error.message : String(error));
    console.log(`\n${passes} passed, ${failures} failed`);
    process.exit(1);
  }

  if (UPDATE) {
    try {
      updateGoldens(engine);
    } catch (error) {
      console.log(`--update failed: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(2);
    }
    return;
  }

  try {
    compareGoldens(engine);
  } catch (error) {
    fail("goldens: compare", error instanceof Error ? error.message : String(error));
  }
  checkDotParses(dot, String(engine.cfg.dot));

  // E2E stdio
  const stdio = new StdioMcp();
  try {
    await stdio.start();
    await runE2E("stdio", stdio);
  } catch (error) {
    fail("e2e stdio", error instanceof Error ? error.message : String(error));
  } finally {
    await stdio.stop();
  }

  // E2E http
  const preferredPort = Number(process.env.DBG_BRIDGE_TEST_HTTP_PORT ?? 3877);
  let httpChild = null;
  try {
    const booted = await spawnHttpServer(Number.isInteger(preferredPort) ? preferredPort : 3877);
    httpChild = booted.child;
    const healthRes = await fetch(`http://127.0.0.1:${booted.port}/health`);
    const healthJson = await healthRes.json();
    assertEqual("e2e http: /health", healthJson.status, "ok");
    await runE2E("http", new HttpMcp(booted.port));
  } catch (error) {
    fail("e2e http", error instanceof Error ? error.message : String(error));
  } finally {
    try {
      httpChild?.kill();
    } catch {
      // already gone
    }
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
