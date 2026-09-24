# x64dbg live-debug engine (ouonet pattern)

One hidden x64dbg process per application session. A prebuilt C loader
plugin embeds Python 3 inside the debugger and auto-starts a TCP bridge
that calls `x64bridge.dll` / `x32bridge.dll` directly via `ctypes`; the
TypeScript engine (`src/engines/x64dbg.ts`) speaks the bridge's
newline-delimited JSON protocol over `127.0.0.1`. No compiler, installer,
or `PATH` edit is needed at runtime: the debugger, the loader binaries,
and the 32-bit Python are all portable directories.

## Layout

- `x64dbg_bridge_sdk.py`, `x64dbg_mcp_bridge.py` — vendored bridge
  (MIT, ouonet/x64dbg-mcp, commit `52b8842`); see
  `THIRD_PARTY_NOTICES.md` for the license and the marked Conduit
  deviations (exit-aware waits, 60 s `InitDebug` wait, phantom session
  handling, synchronous command dispatch, dual-flag session polls).
- `loader/` — vendored loader C source (+ upstream CMakeLists for
  reference). Rebuild notes in `THIRD_PARTY_NOTICES.md`.
- `prebuilt/` — loader binaries built from that exact source:
  `x64dbg_mcp_loader.dp64` (x86_64 MinGW) and
  `x64dbg_mcp_loader.dp32` (i686 MinGW). The engine copies the matching
  loader + the two `.py` files into the debugger's `plugins/` directory
  on first use; x64dbg auto-loads `*.dp32|*.dp64` at startup.
- `test/` — `gen_mini_pe.py` generates the hand-packed fixtures
  `mini_pe_x64.exe` / `mini_pe_x86.exe` (1024 bytes each, no compiler):
  entry runs `mov acc,0x1234; nop; nop`, then `ExitProcess(0)` via a
  one-import kernel32 table. Fixed base (no ASLR), deterministic entry.

## Runtime prerequisites

| Need | Default resolution | Override |
|---|---|---|
| Portable x64dbg snapshot | `%USERPROFILE%\Tools\x64dbg` (also `%ProgramFiles%\x64dbg`, `C:\x64dbg`) | `X64DBG_DIR` |
| 64-bit Python 3.10+ with `iced_x86` | `python`/`py -3` on `PATH` | `PYTHON_HOME_X64` |
| 32-bit Python 3.10+ with `iced_x86` (x86 targets only) | `%USERPROFILE%\Tools\python-x86` | `PYTHON_HOME_X86` |

`iced_x86` is required, not optional: without it the bridge disassembles
via debugger calls from its worker thread, which crashes x64dbg on step.
Install with `python -m pip install iced_x86` (and the `win32` wheel into
the portable 32-bit tree). The acceptance test fails its prereq check
without it.

Target arch comes from the PE `Machine` field (`0x14c` → `x32dbg`,
`0x8664` → `x64dbg`, ARM/other → `invalid_target`).

## MCP tools (all require an `x64dbg` session)

`debug_open` (`path`, `break_on_entry=true`, `auto_analyze=false`,
`command_line_args?`) · `debug_close` · `debug_state` ·
`debug_attach` (`pid`; arch auto-detected from the live process, target
survives `debug_close` via detach) ·
`debug_breakpoint` (`set|remove|list`, hex/number/x64dbg expression,
software/hardware/memory types) · `debug_continue` (blocks until the
next stop; posts `debug.breakpoint_hit` / `debug.exited` / `debug.paused`)
· `debug_step` (`into|over`, `count`) · `debug_pause` (idempotent) ·
`debug_registers` (`include_segment?`, `include_debug?`) ·
`debug_callstack` (`max_frames?`). Async debugger activity lands in the
session ring buffer; `events_pull` with its `after` cursor is the poll
API. `debug_open` also reports `module_base`/`module_entry` (the true
main-module entry — `debug.load`'s `entry_point` is the system entry).

Environment knobs: `DBG_BRIDGE_X64DBG_CMD_TIMEOUT_MS` (30 s),
`DBG_BRIDGE_X64DBG_START_TIMEOUT_MS` (bridge ready, 60 s),
`DBG_BRIDGE_X64DBG_LOAD_TIMEOUT_MS` (150 s),
`DBG_BRIDGE_X64DBG_CONTINUE_TIMEOUT_MS` (125 s),
`DBG_BRIDGE_PYTHON` (interpreter for auto-detection),
`KEEP_DEBUGGER=1` (leave the debugger alive on close, for debugging).

## Verify

```powershell
npm run build
npm test                 # static goldens, must stay 38/38
npm run test:debug       # live dual-arch acceptance (58 checks)
```

`test:debug` needs Windows + the prerequisites above and takes ~2–4 min
(two hidden debuggers, real breakpoints/steps/exits). The x86 leg skips
with a note when the 32-bit runtime is absent.

## Troubleshooting

- `engine_unavailable` with a path: set `X64DBG_DIR` / `PYTHON_HOME_X*_`.
- `InitDebug did not start ... within 60s`: cold symbol fetch can be
  slow on first runs; retry once. Persistent failure → read
  `<debugger>\plugins\mcp_loader_debug.log` (loader/Python issues) and
  `mcp_dispatch_trace.log` (last bridge method).
- A previous crashed run can orphan a hidden debugger; `debug_close`
  tree-kills on the normal path, otherwise stop `x64dbg.exe`/`x32dbg.exe`
  in Task Manager. (`session_close` also tears the engine down.)
- x64dbg localizes some names (e.g. breakpoint names); the protocol
  itself is locale-independent.
