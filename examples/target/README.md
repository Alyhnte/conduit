# examples/target — minimal static-analysis fixture

`mini_branch.elf`: hand-packed 64-bit ELF (1536 bytes, no compiler needed).
Entry `0x400200` runs a branching function (`lea` + `cmp`/`je` if/else);
`.rodata` holds `HELLO-FIXTURE` and `mini-branch`.

Sources:

- `mini_branch.c` — semantic source (behavior the bytes implement)
- `mini_branch.asm` — annotated bytes, 1:1 with the generator output
- `gen_mini_branch.py` — the actual generator (no compiler needed)

Regenerate deterministically:

```sh
python conduit/examples/target/gen_mini_branch.py conduit/examples/target/mini_branch.elf
```

The committed `.elf` must stay byte-identical to the generator output;
`npm test` (golden suite) verifies this and compares live tool output
against `tests/golden/expected/*`.

## Manual end-to-end check

Prereqs: `r2` (`radare2`) and `dot` (Graphviz) on PATH, `npm run build`
once in `conduit/`.

1. Start the bridge (stdio): `node conduit/dist/server.js`
2. `server/discover` with `_meta {"io.modelcontextprotocol/protocolVersion":
   "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}`
   (every request needs that envelope on protocol 2026-07-28).
3. `session_open {"engine": "radare2"}` → `session_id`
4. `open_target {"session_id", "path": "<abs path>/mini_branch.elf",
   "mode": "static"}`
5. `disassemble {"session_id"}` → 10 ops at `entry0` (`lea rax, ...`,
   `cmp edi, 0`, `je`, `mov eax, 1/2`, `ret`)
6. `get_cfg {"session_id", "format": "both"}` → 4 blocks JSON + DOT
7. Save `dot` to `cfg.dot`, then:
   `dot -Tcanon cfg.dot` (must parse) and `dot -Tpng cfg.dot -o cfg.png`
   (must render, ~16 KB)
8. Negative paths: `open_target` with `mode "debug"` and any static tool
   on an `x64dbg` session return `capability_unsupported`.
