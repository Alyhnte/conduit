"""Generate a minimal 64-bit ELF fixture with a branching function.

Layout (x86-64, base 0x400000):
  .text   @ 0x400200 : entry function with an if/else branch + LEA referencing .rodata
  .rodata @ 0x400300 : "HELLO-FIXTURE" and "mini-branch" strings

No compiler needed: pure struct packing. Output is deterministic.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

BASE = 0x400000
TEXT_OFF = 0x200
TEXT_VADDR = 0x400200
RODATA_OFF = 0x300
RODATA_VADDR = 0x400300
SHSTR_OFF = 0x400
SHDR_OFF = 0x500
ENTRY = TEXT_VADDR

# entry(+0x00): lea rax,[rip+disp] -> RODATA_VADDR ; rip after insn = TEXT+7
_disp = RODATA_VADDR - (TEXT_VADDR + 7)
CODE = bytes(
    [
        0x48, 0x8D, 0x05,  # lea rax, [rip+disp32]
        _disp & 0xFF,
        (_disp >> 8) & 0xFF,
        (_disp >> 16) & 0xFF,
        (_disp >> 24) & 0xFF,
        0x55,  # +0x07 push rbp
        0x48, 0x89, 0xE5,  # +0x08 mov rbp, rsp
        0x83, 0xFF, 0x00,  # +0x0b cmp edi, 0
        0x74, 0x0B,  # +0x0e je +0x0b -> +0x1b
        0xB8, 0x01, 0x00, 0x00, 0x00,  # +0x10 mov eax, 1
        0xEB, 0x09,  # +0x15 jmp +0x09 -> +0x20
        0x90, 0x90, 0x90, 0x90,  # +0x17 pad (unreachable)
        0xB8, 0x02, 0x00, 0x00, 0x00,  # +0x1b mov eax, 2
        0x5D,  # +0x20 pop rbp
        0xC3,  # +0x21 ret
    ]
)
assert len(CODE) == 0x22, len(CODE)

RODATA = b"HELLO-FIXTURE\x00mini-branch\x00"
SHSTRTAB = b"\x00.text\x00.rodata\x00.shstrtab\x00"


def build() -> bytes:
    eh = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + bytes(8),  # e_ident (64-bit LE v1 SysV)
        2,  # e_type = EXEC
        62,  # e_machine = x86-64
        1,  # e_version
        ENTRY,  # e_entry
        0x40,  # e_phoff
        SHDR_OFF,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        2,  # e_phnum
        64,  # e_shentsize
        4,  # e_shnum
        3,  # e_shstrndx
    )

    def phdr(p_type: int, p_flags: int, p_offset: int, p_vaddr: int, size: int) -> bytes:
        return struct.pack("<IIQQQQQQ", p_type, p_flags, p_offset, p_vaddr, p_vaddr, size, size, 0x1000)

    file_size = SHDR_OFF + 4 * 64
    phdrs = (
        phdr(1, 5, TEXT_OFF, TEXT_VADDR, len(CODE))  # PT_LOAD R+X .text
        + phdr(1, 4, RODATA_OFF, RODATA_VADDR, len(RODATA))  # PT_LOAD R .rodata
    )

    def shdr(name: int, stype: int, flags: int, addr: int, offset: int, size: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name, stype, flags, addr, offset, size, 0, 0, 1, 0)

    shdrs = (
        shdr(0, 0, 0, 0, 0, 0)  # null
        + shdr(1, 1, 0x6, TEXT_VADDR, TEXT_OFF, len(CODE))  # .text PROGBITS AX
        + shdr(7, 1, 0x2, RODATA_VADDR, RODATA_OFF, len(RODATA))  # .rodata PROGBITS A
        + shdr(15, 3, 0, 0, SHSTR_OFF, len(SHSTRTAB))  # .shstrtab STRTAB
    )

    buf = bytearray(file_size)
    buf[0:64] = eh
    buf[0x40 : 0x40 + len(phdrs)] = phdrs
    buf[TEXT_OFF : TEXT_OFF + len(CODE)] = CODE
    buf[RODATA_OFF : RODATA_OFF + len(RODATA)] = RODATA
    buf[SHSTR_OFF : SHSTR_OFF + len(SHSTRTAB)] = SHSTRTAB
    buf[SHDR_OFF : SHDR_OFF + len(shdrs)] = shdrs
    return bytes(buf)


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("mini_branch.elf")
    out.write_bytes(build())
    print(f"wrote {out} ({out.stat().st_size} bytes, entry=0x{ENTRY:x})")


if __name__ == "__main__":
    main()
