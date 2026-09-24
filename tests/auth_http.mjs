#!/usr/bin/env node
/**
 * Optional localhost token gate over Streamable HTTP.
 *
 * What it checks:
 *  1. gated   — with DBG_BRIDGE_TOKEN set, /health and /mcp answer 401
 *     {error:"unauthorized"} without (or with a wrong) `Authorization:
 *     Bearer <token>` header, and serve normally with the right one
 *     (discover + a session_open/open_target/disassemble/session_close flow)
 *  2. open     — without DBG_BRIDGE_TOKEN the server behaves exactly as
 *     before (no header needed anywhere)
 *
 * Usage:  node tests/auth_http.mjs   (== npm run test:auth)
 * Prereqs: `npm run build` once, `r2` on PATH.
 * Env: DBG_BRIDGE_TEST_HTTP_PORT_AUTH (default 3887; next free port up to +8
 * tried per phase).
 */
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_JS = join(ROOT, "dist", "server.js");
const FIXTURE_ELF = join(ROOT, "examples", "target", "mini_branch.elf");
const PROTOCOL = "2026-07-28";

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

async function waitFor(port, budgetMs, headers = {}) {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`, { headers });
      if (res.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

async function spawnHttpServer(preferredPort, token) {
  for (let port = preferredPort; port < preferredPort + 8; port += 1) {
    const child = spawn(process.execPath, [SERVER_JS, "--transport", "http", "--port", String(port)], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, DBG_BRIDGE_TOKEN: token ?? "" },
    });
    let stderr = "";
    child.stderr.on("data", (c) => {
      stderr += c.toString("utf8");
    });
    const healthy = await waitFor(port, 10000, token ? { authorization: `Bearer ${token}` } : {});
    if (healthy) return { child, port, stderr: () => stderr };
    try {
      child.kill();
    } catch {
      // already gone
    }
    if (!/EADDRINUSE|listen/.test(stderr)) {
      throw new Error(`http server failed to boot on port ${port}: ${stderr.slice(0, 300)}`);
    }
  }
  throw new Error(`no free http port in ${preferredPort}..${preferredPort + 7}`);
}

async function stop(child) {
  try {
    child?.kill();
  } catch {
    // already gone
  }
  await new Promise((r) => setTimeout(r, 300));
}

function toolPayload(reply, label) {
  const text = reply?.result?.content?.[0]?.text ?? null;
  if (text === null) throw new Error(`${label}: tool reply has no text: ${JSON.stringify(reply).slice(0, 300)}`);
  return JSON.parse(text);
}

async function mcpCall(port, tool, args, headers = {}) {
  const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "mcp-method": "tools/call",
      "mcp-name": tool,
      ...headers,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { ...META, name: tool, arguments: args } }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function main() {
  try {
    readFileSync(SERVER_JS);
    readFileSync(FIXTURE_ELF);
  } catch {
    console.log("prereq check FAILED: run `npm run build` first.");
    process.exit(2);
  }
  const basePort = Number(process.env.DBG_BRIDGE_TEST_HTTP_PORT_AUTH ?? 3887);
  const startPort = Number.isInteger(basePort) ? basePort : 3887;

  // Phase 1: gated server.
  const token = `t-${randomUUID()}`;
  const auth = { authorization: `Bearer ${token}` };
  let gated = null;
  try {
    gated = await spawnHttpServer(startPort, token);
    pass(`auth[gated]: http server on ${gated.port}`);

    const hNone = await fetch(`http://127.0.0.1:${gated.port}/health`);
    assertEqual("auth[gated]: /health without token -> 401", hNone.status, 401);
    assertEqual("auth[gated]: /health 401 shape", (await hNone.json()).error, "unauthorized");

    const hWrong = await fetch(`http://127.0.0.1:${gated.port}/health`, {
      headers: { authorization: "Bearer wrong-token" },
    });
    assertEqual("auth[gated]: /health wrong token -> 401", hWrong.status, 401);

    const hOk = await fetch(`http://127.0.0.1:${gated.port}/health`, { headers: auth });
    assertEqual("auth[gated]: /health right token -> 200", hOk.status, 200);
    assertEqual("auth[gated]: /health payload unchanged", (await hOk.json()).status, "ok");

    const mNone = await mcpCall(gated.port, "health", {});
    assertEqual("auth[gated]: /mcp without token -> 401", mNone.status, 401);
    assertEqual("auth[gated]: /mcp 401 shape", mNone.body?.error, "unauthorized");

    const mWrong = await mcpCall(gated.port, "health", {}, { authorization: "Bearer wrong-token" });
    assertEqual("auth[gated]: /mcp wrong token -> 401", mWrong.status, 401);

    // Full flow with the token: session_open -> open_target -> disassemble -> session_close.
    const opened = toolPayload((await mcpCall(gated.port, "session_open", { engine: "radare2" }, auth)).body, "open");
    const target = toolPayload(
      (await mcpCall(gated.port, "open_target", { session_id: opened.session_id, path: FIXTURE_ELF, mode: "static" }, auth)).body,
      "target",
    );
    assertEqual("auth[gated]: authed flow opens target", target.opened, true);
    const dis = toolPayload(
      (await mcpCall(gated.port, "disassemble", { session_id: opened.session_id }, auth)).body,
      "dis",
    );
    assertEqual("auth[gated]: authed flow disassembles", dis.count > 0, true);
    const closed = toolPayload(
      (await mcpCall(gated.port, "session_close", { session_id: opened.session_id }, auth)).body,
      "close",
    );
    assertEqual("auth[gated]: authed flow closes", closed.closed, true);
  } catch (error) {
    fail("auth[gated]", error instanceof Error ? (error.stack ?? error.message) : String(error));
  } finally {
    await stop(gated?.child);
  }

  // Phase 2: open server (default) — no header needed anywhere.
  let open = null;
  try {
    open = await spawnHttpServer(startPort, undefined);
    const h = await fetch(`http://127.0.0.1:${open.port}/health`);
    assertEqual("auth[open]: /health without token -> 200", h.status, 200);
    const m = await mcpCall(open.port, "health", {});
    assertEqual("auth[open]: /mcp without token -> 200", m.status, 200);
    assertEqual("auth[open]: health payload", toolPayload(m.body, "health").status, "ok");
  } catch (error) {
    fail("auth[open]", error instanceof Error ? (error.stack ?? error.message) : String(error));
  } finally {
    await stop(open?.child);
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
