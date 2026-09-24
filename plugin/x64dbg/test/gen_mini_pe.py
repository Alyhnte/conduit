#!/usr/bin/env python3
"""Generate minimal branching-free PE fixtures for x64dbg bridge tests.

Produces two tiny console executables (no compiler needed):

  mini_pe_x64.exe  64-bit: entry runs `mov eax,0x1234; nop; nop`,
                   then ExitProcess(0) via kernel32 import.
  mini_pe_x86.exe  32-bit: same semantics, x86 encoding.

The two NOPs after the MOV are deterministic breakpoint slots: the
acceptance flow breaks on entry, sets a software BP on entry+5, continues,
asserts the hit, reads EAX/RAX == 0x1234 (proof of real execution), then
continues to process exit.

Layout (both): DOS header + PE32/PE32+ headers + one RWX `.text` section
holding code first, then the import directory (one descriptor + ILT/IAT +
hint/name + "kernel32.dll"). FileAlignment 0x200, total 1024 bytes.

Usage:  python gen_mini_pe.py [outdir]
"""
import struct
import sys
from pathlib import Path

FA = 0x200  # FileAlignment
SA = 0x1000  # SectionAlignment
TEXT_RVA = 0x1000
TEXT_RAW = 0x200


def align_up(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def build_import_block(code_len: int, bits: int):
    """Return (block_bytes, iat_rva_offset, code_patch_info).

    Block layout (relative to block start):
      +0x00  Import Directory Table (20 bytes, 1 entry + terminator follows)
      +0x28  zero terminator (20 bytes)
      +0x40  ILT (3 entries: hintptr, 0, pad)  [x64: +0x40, x86: +0x40]
      ILT_end: IAT (same shape)
      then Hint/Name "ExitProcess", then "kernel32.dll".
    """
    is64 = bits == 64
    pe = "<Q" if is64 else "<I"
    pes = 8 if is64 else 4

    idt_off = 0x00
    ilt_off = 0x40
    iat_off = ilt_off + 3 * pes
    hn_off = iat_off + 3 * pes
    dll_off = hn_off + 2 + len(b"ExitProcess") + 1
    block_len = align_up(dll_off + len(b"kernel32.dll") + 1, 16)

    block_rva = TEXT_RVA + code_len
    rva = lambda o: block_rva + o  # noqa: E731

    buf = bytearray(block_len)
    # Import Directory Table entry: ILT, TimeDate, Forwarder, Name, IAT.
    struct.pack_into("<IIIII", buf, idt_off, rva(ilt_off), 0, 0, rva(dll_off), rva(iat_off))
    # ILT + IAT point at the Hint/Name entry.
    struct.pack_into(pe, buf, ilt_off, rva(hn_off))
    struct.pack_into(pe, buf, iat_off, rva(hn_off))
    # Hint/Name + DLL name.
    struct.pack_into("<H", buf, hn_off, 0)
    buf[hn_off + 2:hn_off + 2 + len(b"ExitProcess") + 1] = b"ExitProcess\x00"
    buf[dll_off:dll_off + len(b"kernel32.dll") + 1] = b"kernel32.dll\x00"
    return bytes(buf), rva(iat_off), rva(idt_off)


def build_pe(bits: int) -> bytes:
    is64 = bits == 64
    image_base = 0x140000000 if is64 else 0x400000
    entry_rva = TEXT_RVA

    # --- code ---
    #   mov eax, 0x1234   ; B8 34 12 00 00
    #   nop               ; 90            <- bp slot 1 (entry+5)
    #   nop               ; 90            <- bp slot 2 (entry+6)
    #   zero exit code    ; x64: xor ecx,ecx (31 C9)  x86: push 0 (6A 00)
    #   x64 prologue      ; sub rsp,0x28 (48 83 EC 28): shadow space +
    #                       16-byte stack alignment for the API call
    #   call ExitProcess  ; x64: FF 15 <disp32>  x86: FF 15 <m32>
    code = bytearray(b"\xB8\x34\x12\x00\x00\x90\x90" + (b"\x31\xC9\x48\x83\xEC\x28" if is64 else b"\x6A\x00"))
    call_off = len(code)  # offset of the call within .text
    if is64:
        code += b"\xFF\x15\x00\x00\x00\x00"
    else:
        code += b"\xFF\x15\x00\x00\x00\x00"
    code_len = len(code)

    block, iat_rva, idt_rva = build_import_block(code_len, bits)
    text = bytes(code) + block
    text_vsize = len(text)

    if is64:
        # disp32 = iat_va - address_of_next_instruction
        next_ip = image_base + TEXT_RVA + call_off + 6
        disp = (image_base + iat_rva) - next_ip
        text = bytearray(text)
        struct.pack_into("<i", text, call_off + 2, disp)
        text = bytes(text)
    else:
        text = bytearray(text)
        struct.pack_into("<I", text, call_off + 2, image_base + iat_rva)
        text = bytes(text)

    # --- DOS header ---
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    dos[0x40:0x44] = b"ZM\x90\x00"  # harmless stub marker

    # --- COFF header ---
    machine = 0x8664 if is64 else 0x14C
    nsec = 1
    opt_size = 0xF0 if is64 else 0xE0
    coff = struct.pack("<HHIIIHH", machine, nsec, 0, 0, 0, opt_size, 0x010F)
    # characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE? no: use
    # EXECUTABLE(2)|LARGE_ADDRESS_AWARE(20)|... keep 0x010F? For x64 use 0x002F.
    chars = 0x002F if is64 else 0x010F
    coff = struct.pack("<HHIIIHH", machine, nsec, 0, 0, 0, opt_size, chars)

    # --- Optional header ---
    size_of_headers = FA
    size_of_image = align_up(TEXT_RVA + align_up(text_vsize, SA), SA)
    ndata = 16
    if is64:
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B, 14, 0, FA, 0, 0,
            entry_rva, TEXT_RVA, image_base, SA, FA,
            6, 0, 0, 0, 6, 0, 0,
            size_of_image, size_of_headers, 0, 3, 0,
            0x100000, 0x1000, 0x100000, 0x1000, 0, ndata,
        )
    else:
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B, 14, 0, FA, 0, 0,
            entry_rva, TEXT_RVA, 0, image_base, SA, FA,
            6, 0, 0, 0, 6, 0, 0,
            size_of_image, size_of_headers, 0, 3, 0,
            0x100000, 0x1000, 0x100000, 0x1000, 0, ndata,
        )
    # Data directories: [0]=export ... [1]=import.
    dirs = bytearray(8 * ndata)
    struct.pack_into("<II", dirs, 8 * 1, idt_rva, 0x28)

    # --- Section header (.text) ---
    sec = struct.pack(
        "<8sIIIIIIHHI", b".text\x00\x00\x00",
        align_up(text_vsize, SA), TEXT_RVA, FA, TEXT_RAW,
        0, 0, 0, 0, 0xE0000020,  # CODE|EXECUTE|READ|WRITE
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + opt + bytes(dirs) + sec
    assert len(headers) <= FA, len(headers)
    headers = headers + b"\x00" * (FA - len(headers))
    image = headers + text
    image = image + b"\x00" * (align_up(len(image), FA) - len(image))
    return image


def main() -> None:
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent
    for bits in (64, 32):
        name = f"mini_pe_x{'64' if bits == 64 else '86'}.exe"
        data = build_pe(bits)
        (outdir / name).write_bytes(data)
        print(f"wrote {name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
