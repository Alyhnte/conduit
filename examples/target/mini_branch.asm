; mini_branch.asm — annotated source of the .text bytes in mini_branch.elf.
; Assemble mentally (or with nasm -f bin) at vaddr 0x400200; every line below
; maps 1:1 to the bytes emitted by gen_mini_branch.py.
;
;   nasm -f bin mini_branch.asm -o /tmp/text.bin   ; optional cross-check only,
;                                                 ; the committed .elf stays canonical.

BITS 64
ORG 0x400200

entry0:
    lea rax, [rel rodata_hello]  ; 48 8D 05 F9 00 00 00  (7 bytes) -> 0x400300
    push rbp                     ; 55                   (1 byte)
    mov rbp, rsp                 ; 48 89 E5             (3 bytes)
    cmp edi, 0                   ; 83 FF 00             (3 bytes)  ; arg == 0?
    je .is_zero                  ; 74 0B                (2 bytes)  ; -> 0x40021b
    mov eax, 1                   ; B8 01 00 00 00       (5 bytes)  ; else-branch
    jmp .join                    ; EB 09                (2 bytes)  ; -> 0x400220
    ; unreachable padding (never disassembled as part of entry0):
    times 4 nop                  ; 90 90 90 90          ; 0x400217..0x40021a
.is_zero:                        ; 0x40021b
    mov eax, 2                   ; B8 02 00 00 00       (5 bytes)  ; then-branch
.join:                           ; 0x400220
    pop rbp                      ; 5D                   (1 byte)
    ret                          ; C3                   (1 byte)

; --- .rodata @ 0x400300 (22 bytes) ---
; rodata_hello: db "HELLO-FIXTURE", 0    ; 0x400300, len 13
;               db "mini-branch", 0      ; 0x40030e, len 11
