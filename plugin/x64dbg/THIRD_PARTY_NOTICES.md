# Third-party notices — plugin/x64dbg

The files in this directory are vendored from
[ouonet/x64dbg-mcp](https://github.com/ouonet/x64dbg-mcp) at commit
`52b8842de0ca81b091944e9f3a35b7f30410828f` (MIT License, (c) 2026
x64dbg-mcp contributors):

- `x64dbg_bridge_sdk.py` — ctypes bindings to x64bridge.dll / x32bridge.dll
- `x64dbg_mcp_bridge.py` — in-process TCP bridge (newline-delimited JSON)
- `loader/x64dbg_mcp_loader.c` + `loader/CMakeLists.txt` — C plugin that
  embeds Python 3.10+ inside x64dbg and auto-starts the bridge
- `prebuilt/` — loader binaries built from that exact source so end users
  never need a compiler (no VS Build Tools, no MinGW required at runtime)

Upstream license (MIT):

> Permission is hereby granted, free of charge, to any person obtaining a
> copy of this software and associated documentation files (the "Software"),
> to deal in the Software without restriction, including without limitation
> the rights to use, copy, modify, merge, publish, distribute, sublicense,
> and/or sell copies of the Software, and to permit persons to whom the
> Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
> OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
> MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
> NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
> DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
> USE OR OTHER DEALINGS IN THE SOFTWARE.

## Rebuilding the loader

x64 (MinGW-w64, already available on the build machine — MSVC not needed):

```powershell
gcc -shared -O2 -s -o prebuilt/x64dbg_mcp_loader.dp64 loader/x64dbg_mcp_loader.c `
  -D_WIN32_WINNT=0x0A00 -D_CRT_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN
```

x86 (needs an i686-w64-mingw32 toolchain):

```powershell
i686-w64-mingw32-gcc -shared -O2 -s -o prebuilt/x64dbg_mcp_loader.dp32 loader/x64dbg_mcp_loader.c `
  -D_WIN32_WINNT=0x0A00 -D_CRT_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN
```

Verify exports: `pluginit`, `plugsetup`, `plugstop`.

## Conduit deviations from upstream

`x64dbg_mcp_bridge.py` carries marked deviations (wire protocol unchanged):

1. `_wait_for_stop` also stops waiting when `DbgIsDebugging()` is false.
   Without it, a continue/step that ends in process exit spins to the
   120 s timeout, because this x64dbg snapshot leaves `DbgIsRunning()`
   set after exit (observed: bridge reports `idle` while the wait
   still spins).
2. `handle_debug_load` waits 60 s (not 15 s) for `InitDebug` to start
   the session: cold starts legitimately exceed 15 s, and giving up
   early wedges the debugger.
3. `handle_debug_load` and `handle_debug_attach` skip the `StopDebug`
   dance when no live pid exists (fresh-startup phantom / stale
   half-state): there is nothing real to stop. Genuine live sessions
   on another target still go through `StopDebug`.
4. Session-control commands (`InitDebug`, `erun`/`run`, `pause`,
   `StopDebug`, `stop`, `AttachDebugger`, `DetachDebugger`) use
   synchronous `DbgCmdExecDirect` instead of async `DbgCmdExec`: on
   x32dbg the async queue is not drained (observed: `InitDebug` never
   starts and only flushes minutes later when a Direct call lands),
   while Direct executes inline and works on both archs. Handlers stay
   serialized by `_dispatch_lock`.
5. The post-`InitDebug`/`AttachDebugger` waits poll BOTH
   `DbgIsDebugging()` and `DbgIsRunning()`. An `IsDebugging`-only poll
   never observes the new x32 session (False for 60 s+ while a parallel
   `getState` — which reads both flags — sees it instantly).
