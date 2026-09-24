#!/usr/bin/env node
import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { localhostHostValidation, localhostOriginValidation, toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";

import { registerTools } from "./tools.js";

export const SERVER_NAME = "conduit";
export const SERVER_VERSION = "0.1.0";
export const PROTOCOL_VERSION = "2026-07-28";

export function createBridgeServer(): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );
  registerTools(server);
  return server;
}

interface ServeOptions {
  transport: "stdio" | "http";
  host: string;
  port: number;
  /** Optional HTTP bearer token (DBG_BRIDGE_TOKEN). Absent means open localhost. */
  token?: string;
}

function readFlag(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) {
    return undefined;
  }
  return argv[index + 1];
}

export function parseServeOptions(argv: string[], env: NodeJS.ProcessEnv = process.env): ServeOptions {
  const flagged = readFlag(argv, "--transport") ?? (argv.includes("--http") ? "http" : undefined);
  const fromEnv = env.DBG_BRIDGE_TRANSPORT;
  const transport = flagged ?? fromEnv ?? "stdio";
  if (transport !== "stdio" && transport !== "http") {
    throw new Error(`unsupported transport: ${transport}`);
  }
  const portText = readFlag(argv, "--port") ?? env.DBG_BRIDGE_PORT ?? "3847";
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid port: ${portText}`);
  }
  const host = readFlag(argv, "--host") ?? env.DBG_BRIDGE_HOST ?? "127.0.0.1";
  const rawToken = env.DBG_BRIDGE_TOKEN ?? "";
  const token = rawToken === "" ? undefined : rawToken;
  return { transport, host, port, ...(token === undefined ? {} : { token }) };
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
  });
  res.end(payload);
}

/**
 * Optional localhost token gate. When DBG_BRIDGE_TOKEN is set, every HTTP
 * route (including /health) requires `Authorization: Bearer <token>` and
 * anything else is answered 401. stdio is unaffected: spawning the process
 * locally is the authentication there. Both digests are hashed before the
 * constant-time compare so token length does not leak via early rejection.
 */
function isAuthorized(req: IncomingMessage, wantToken: string): boolean {
  const header = req.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    return false;
  }
  const digest = (value: string): Buffer => createHash("sha256").update(value, "utf8").digest();
  return timingSafeEqual(digest(header.slice("Bearer ".length)), digest(wantToken));
}

/**
 * Streamable HTTP: modern 2026-07-28 path plus a stateless 2025-era fallback.
 * No HTTP+SSE endpoint, no Mcp-Session-Id, JSON responses (no push stream).
 */
export function startHttp(options: ServeOptions): void {
  const handler = createMcpHandler(() => createBridgeServer(), {
    legacy: "stateless",
    responseMode: "json",
  });
  const nodeHandler = toNodeHandler(handler);
  const validateHost = localhostHostValidation();
  const validateOrigin = localhostOriginValidation();
  // Test-only escape hatch (e.g. public-tunnel runs): allow listed Host
  // values past localhost validation. Empty by default = no behavior change.
  const extraHosts = (process.env.DBG_BRIDGE_EXTRA_HOSTS ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h !== "");
  const hostAllowed = (req: { headers: { host?: string } }): boolean => {
    const host = ((req.headers.host ?? "").split(":")[0] ?? "").trim().toLowerCase();
    return host !== "" && extraHosts.includes(host);
  };

  const wantToken = options.token;
  const http = createServer((req, res) => {
    if (wantToken !== undefined && !isAuthorized(req, wantToken)) {
      writeJson(res, 401, { error: "unauthorized" });
      return;
    }
    const path = req.url?.split("?")[0] ?? "/";
    if (req.method === "GET" && path === "/health") {
      writeJson(res, 200, {
        status: "ok",
        name: SERVER_NAME,
        version: SERVER_VERSION,
        protocol: PROTOCOL_VERSION,
        transport: "streamable-http",
      });
      return;
    }
    if (path !== "/mcp") {
      writeJson(res, 404, { error: "not_found" });
      return;
    }
    if (!hostAllowed(req) && (!validateHost(req, res) || !validateOrigin(req, res))) {
      return;
    }
    void nodeHandler(req, res);
  });

  if (extraHosts.length > 0) {
    console.error(`${SERVER_NAME} WARNING: extra allowed hosts: ${extraHosts.join(",")}`);
  }
  http.listen(options.port, options.host, () => {
    console.error(
      `${SERVER_NAME} streamable-http ${PROTOCOL_VERSION} http://${options.host}:${options.port}/mcp auth=${wantToken === undefined ? "open" : "token"}`,
    );
  });

  const shutdown = (): void => {
    void handler.close().finally(() => {
      http.close(() => process.exit(0));
    });
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

export function startStdio(): void {
  serveStdio(() => createBridgeServer(), { legacy: "serve" });
}

function main(): void {
  let options: ServeOptions;
  try {
    options = parseServeOptions(process.argv.slice(2));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exit(1);
  }
  if (options.transport === "http") {
    startHttp(options);
    return;
  }
  startStdio();
}

const invokedDirectly = process.argv[1]?.replace(/\\/g, "/").endsWith("/src/server.ts")
  || process.argv[1]?.replace(/\\/g, "/").endsWith("/dist/server.js");

if (invokedDirectly) {
  main();
}
