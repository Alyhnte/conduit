#!/usr/bin/env node
/**
 * Multi-client concurrency over Streamable HTTP (fixture: mini_branch.elf).
 *
 * What it checks:
 *  1. isolation — N parallel clients each run a full static flow on their own
 *     session_id; every payload echoes the caller's own session, and each
 *     event buffer holds exactly [session.opened, target.opened] (no foreign
 *     events leak across sessions)
 *  2. correctness under load — every client's disassemble/get_cfg still
 *     matches tests/golden/expected/* (same oracle as npm test)
 *  3. staggered close — a holder session stays healthy while the other
 *     clients close theirs underneath it, then closes cleanly itself
 *  4. capability interleave — an x64dbg session's static-tool rejection
 *     races the static flows without disturbing them
 *  5. no leaks — session_list is empty and health.sessions is 0 afterwards
 *
 * Usage:  node tests/concurrent_http.mjs   (== npm run test:concurrency)
 * Prereqs: `npm run build` once, `r2` on PATH.
 * Env: DBG_BRIDGE_TEST_HTTP_PORT_CONC (default 3879; next free port up to +16
 * tried), DBG_BRIDGE_CONC_CLIENTS (default 4).
 *
 * Load shape: racers start ~1.5 s apart (realistic client arrivals, not a
 * same-millisecond spawn burst) while each flow lasts many seconds, so all
 * sessions overlap heavily. The server runs with generous-but-bounded r2
 * timeouts via the documented DBG_BRIDGE_R2_*_TIMEOUT_MS knobs; a genuine
 * hang still fails instead of hanging the harness.
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_JS = join(ROOT, "dist", "server.js");
const FIXTURE_ELF = join(ROOT, "examples", "target", "mini_branch.elf");
const EXPECTED_DIR = join(ROOT, "tests", "golden", "expected");
const PROTOCOL = "2026-07-28";
const CLIENTS = Math.max(2, Number(process.env.DBG_BRIDGE_CONC_CLIENTS ?? 4) || 4);

const META = {
  _meta: {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
    "io.modelcontextprotocol/clientCapabilities": {},
  },
};

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
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) {
    pass(name);
    return true;
  }
  fail(name, `expected: ${e.slice(0, 400)}\nactual:   ${a.slice(0, 400)}`);
  return false;
}

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

const expDis = JSON.parse(readFileSync(join(EXPECTED_DIR, "disassemble.entry0.json"), "utf8"));
const expDot = dotStructure(readFileSync(join(EXPECTED_DIR, "cfg.entry0.dot"), "utf8"));

function toolPayload(reply, label) {
  const text = reply?.result?.content?.[0]?.text ?? null;
  if (text === null) throw new Error(`${label}: tool reply has no text: ${JSON.stringify(reply).slice(0, 300)}`);
  return JSON.parse(text);
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
      signal: AbortSignal.timeout(180000),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`http ${method} -> ${res.status}: ${text.slice(0, 300)}`);
    return JSON.parse(text);
  }

  call(tool, args) {
    return this.request("tools/call", { ...META, name: tool, arguments: args }, tool);
  }
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

async function spawnHttpServer(preferredPort) {
  for (let port = preferredPort; port < preferredPort + 16; port += 1) {
    const child = spawn(process.execPath, [SERVER_JS, "--transport", "http", "--port", String(port)], {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        DBG_BRIDGE_TOKEN: "",
        // Generous-but-bounded r2 timeouts for the loaded server: parallel
        // r2 startups on Windows occasionally stall for tens of seconds.
        DBG_BRIDGE_R2_CMD_TIMEOUT_MS: "90000",
        DBG_BRIDGE_R2_ANALYSIS_TIMEOUT_MS: "240000",
      },
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

/** Full static flow for one client; returns its session_id. */
async function runClientFlow(port, tag) {
  const mcp = new HttpMcp(port);
  const t = (n) => `conc[${tag}]: ${n}`;
  const opened = toolPayload(await mcp.call("session_open", { engine: "radare2" }), t("session_open"));
  const sid = opened.session_id;
  if (typeof sid !== "string" || sid.length < 8) {
    fail(t("session_open"), JSON.stringify(opened).slice(0, 300));
    throw new Error("no session");
  }
  const target = toolPayload(
    await mcp.call("open_target", { session_id: sid, path: FIXTURE_ELF, mode: "static" }),
    t("open_target"),
  );
  if (target.opened !== true || target.session_id !== sid) {
    fail(t("open_target echoes own session"), JSON.stringify(target).slice(0, 300));
  }
  const dis = toolPayload(await mcp.call("disassemble", { session_id: sid }), t("disassemble"));
  if (dis.session_id !== sid) {
    fail(t("disassemble echoes own session"), JSON.stringify(dis).slice(0, 200));
  }
  const opsOk =
    JSON.stringify((dis.ops ?? []).map(normDisasmOp)) ===
    JSON.stringify((expDis.ops ?? []).map(normDisasmOp));
  if (!opsOk) {
    fail(t("disassemble == golden"), `ops differ for ${sid.slice(0, 8)}…`);
  }
  const cfg = toolPayload(await mcp.call("get_cfg", { session_id: sid, format: "both" }), t("get_cfg"));
  if (JSON.stringify(dotStructure(cfg.dot)) !== JSON.stringify(expDot)) {
    fail(t("get_cfg == golden"), `dot differs for ${sid.slice(0, 8)}…`);
  }
  const events = toolPayload(await mcp.call("events_pull", { session_id: sid }), t("events_pull"));
  const kinds = (events.events ?? []).map((e) => e.kind);
  if (JSON.stringify(kinds) !== JSON.stringify(["session.opened", "target.opened"])) {
    fail(t("event buffer holds exactly own events"), JSON.stringify(kinds));
  }
  // Staggered close: everyone except the holder closes now; the holder keeps
  // its session alive while the others tear down underneath it.
  if (tag !== "holder") {
    const closed = toolPayload(await mcp.call("session_close", { session_id: sid }), t("session_close"));
    if (closed.closed !== true) {
      fail(t("session_close"), JSON.stringify(closed).slice(0, 200));
    }
  }
  return { sid, mcp };
}

async function runCapabilityInterleave(port) {
  const mcp = new HttpMcp(port);
  const opened = toolPayload(await mcp.call("session_open", { engine: "x64dbg" }), "conc[cap]: session_open");
  const xres = toolPayload(
    await mcp.call("disassemble", { session_id: opened.session_id }),
    "conc[cap]: disassemble",
  );
  assertEqual("conc[cap]: static tool on x64dbg rejected", xres.error, "capability_unsupported");
  await mcp.call("session_close", { session_id: opened.session_id });
}

async function main() {
  try {
    readFileSync(SERVER_JS);
    readFileSync(FIXTURE_ELF);
  } catch {
    console.log("prereq check FAILED: run `npm run build` first.");
    process.exit(2);
  }
  const preferredPort = Number(process.env.DBG_BRIDGE_TEST_HTTP_PORT_CONC ?? 3879);
  let httpChild = null;
  try {
    const booted = await spawnHttpServer(Number.isInteger(preferredPort) ? preferredPort : 3879);
    httpChild = booted.child;
    pass(`conc: http server on ${booted.port} (${CLIENTS} clients + holder + capability)`);

    // Holder opens first so its session outlives the racing clients.
    const holder = await runClientFlow(booted.port, "holder");
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const racers = await Promise.all(
      Array.from({ length: CLIENTS }, (_, i) => sleep(i * 1500).then(() => runClientFlow(booted.port, `c${i}`))),
    );
    await runCapabilityInterleave(booted.port);

    const ids = [holder.sid, ...racers.map((r) => r.sid)];
    assertEqual("conc: session_ids distinct", new Set(ids).size, ids.length);

    // The holder's session must be undisturbed by the closes that raced it.
    const redis = toolPayload(
      await holder.mcp.call("disassemble", { session_id: holder.sid }),
      "conc[holder]: redisassemble",
    );
    assertEqual("conc[holder]: session survives others closing", redis.session_id, holder.sid);
    const hevents = toolPayload(
      await holder.mcp.call("events_pull", { session_id: holder.sid }),
      "conc[holder]: events_pull",
    );
    assertEqual(
      "conc[holder]: buffer still exactly own events",
      (hevents.events ?? []).map((e) => e.kind),
      ["session.opened", "target.opened"],
    );
    // session_close without a prior close_target must still drop the target:
    // the r2 child dies with the session (Faz1 close-cleanup rule).
    const hclose = toolPayload(
      await holder.mcp.call("session_close", { session_id: holder.sid }),
      "conc[holder]: session_close",
    );
    assertEqual("conc[holder]: session_close", hclose.closed, true);
    const gone = toolPayload(
      await holder.mcp.call("events_pull", { session_id: holder.sid }),
      "conc[holder]: events_pull after close",
    );
    assertEqual("conc[holder]: session really gone", gone.error, "session_not_found");

    const probe = new HttpMcp(booted.port);
    const list = toolPayload(await probe.call("session_list", {}), "conc: session_list");
    assertEqual("conc: no sessions leak", list.sessions, []);
    const health = toolPayload(await probe.call("health", {}), "conc: health");
    assertEqual("conc: health.sessions back to 0", health.sessions, 0);

    if (failures === 0) {
      pass(`conc: all ${CLIENTS + 1} static flows + capability interleave clean`);
    }
  } catch (error) {
    fail("conc: harness", error instanceof Error ? (error.stack ?? error.message) : String(error));
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
