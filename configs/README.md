# configs — client setup for Conduit

Copy the file for your client, replace the placeholder, install it at the
path below, then restart the client.

## Placeholder

`<DBG_BRIDGE_DIR>` — absolute path of the `conduit/` folder, with
**forward slashes** (they work on Windows too):

- Windows: `C:/Users/you/conduit`
- macOS/Linux: `/home/you/conduit`

`node` must be on PATH (Node ≥ 20). If it is not, replace `node` with the
absolute path of your Node binary.

## Files

| Client         | stdio (client spawns the server)                          | HTTP (you run the server first)                           |
|----------------|-----------------------------------------------------------|-----------------------------------------------------------|
| Cursor         | `cursor/mcp.stdio.json`                                   | `cursor/mcp.http.json`                                    |
| Claude Desktop | `claude-desktop/claude_desktop_config.stdio.json`         | `claude-desktop/claude_desktop_config.http.json`          |
| Cline          | `cline/cline_mcp_settings.stdio.json`                     | `cline/cline_mcp_settings.http.json`                      |
| OpenCode       | `opencode/opencode.stdio.json`                            | `opencode/opencode.http.json`                             |

## Install paths

- **Cursor**: `~/.cursor/mcp.json` (global) or `<project>/.cursor/mcp.json`
  (project-only). Merge the `mcpServers` entry into the existing file.
- **Claude Desktop**: `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
  or `~/Library/Application Support/Claude/claude_desktop_config.json`
  (macOS). Merge the `mcpServers` entry. Very old Claude Desktop builds only
  support stdio entries — use the `.stdio` file there.
- **Cline**: the MCP settings file Cline manages (`cline_mcp_settings.json`,
  opened via the Cline extension's “MCP Servers” panel). Paste the
  `mcpServers` entry.
- **OpenCode**: `opencode.json` in the project root (or `~/.config/opencode/opencode.json`
  for global). Merge the `mcp` entry.

## HTTP variant

The `.http` files point at `http://127.0.0.1:3847/mcp`. Start the server
yourself before (or after) configuring the client:

```sh
node <DBG_BRIDGE_DIR>/dist/server.js --transport http --port 3847
```

It prints `conduit streamable-http 2026-07-28 http://127.0.0.1:3847/mcp`
and stays in the foreground. Any port works — just keep the config URL and
the `--port` value in sync.

## Engine

These files do not select a debugger. The same stdio or HTTP entry serves
every engine. The client chooses one with `session_open`:

- `radare2` — static tools (`open_target`, `disassemble`, …)
- `x64dbg`, `cdb`, `frida` — live `debug_*` tools

No config key was added for that. Install paths below are unchanged.

## Verify inside the client

Ask the client to call the `health` tool (or run any prompt that lists the
`conduit` tools). You should see `status: ok`, `name: conduit`.
Then follow the end-to-end check in `../README.md` (“End-to-end check”).

Note: 2025-era clients (e.g. opencode 1.x on protocol `2025-11-25`) work
with the same files — the server answers them via its legacy fallback.
No `protocolVersion` setting is needed on the client side.
