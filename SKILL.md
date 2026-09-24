---
name: conduit
description: Drive radare2, x64dbg, cdb, and Frida from an MCP client. Use for disassembly, control-flow graphs, cross-references, strings, and live debugging.
---

# Conduit

Conduit is an MCP server, not a subcommand CLI. Start it, then call tools.

## Install

```sh
npm install -g github:Alyhnte/conduit
```

Node.js 20 or newer. Static tools need `radare2` on PATH. Live tools need x64dbg, cdb, or the bundled Frida package.

## Run

```sh
conduit
conduit --transport http --port 3847
```

Cursor, Claude Desktop, Cline, and OpenCode configs are in `configs/`.

## Tool order

1. `health` — expect `status: ok` and `name: conduit`.
2. `session_open` with `engine` set to `radare2`, `x64dbg`, `cdb`, or `frida`.
3. Static session: `open_target` with `mode: "static"`, then `disassemble`, `get_cfg`, `xrefs`, `strings`, `dump`.
4. Live session: `debug_open` or `debug_attach`, then `debug_breakpoint`, `debug_continue`, `debug_registers`, `debug_callstack`.
5. Live memory, code, threads, plugins, and snapshots need `confirm: true`.
6. `explain` reads an assembly window. A live session still needs `confirm: true`.
7. `close_target` and `session_close` when finished.

A tool the engine does not implement returns `capability_unsupported`. Frida hardware execute breakpoints use four slots; a fifth returns `no_breakpoint_slot`.
