# Nothing is True

## Overview

We are given a service containing a Python script which accepts an ELF
file, performs the following validations on it:

```py
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
...
def check_bytes(data, b):
    p = -1
    while True:
        p = data.find(b, p+1)
        if p == -1:
            return True
        elif p & 0xfff == 0 or p & 0xfff == 0xfff:
            return False

def check_segments(elf):
    for seg in elf.iter_segments():
        if seg.header.p_filesz > 0x10000 or seg.header.p_memsz > 0x10000:
            print('Segment too large')
            return False
        elif seg.header.p_type == 'PT_INTERP' or seg.header.p_type == 'PT_DYNAMIC':
            print('No dynamic link')
            return False
        elif seg.header.p_type == 'PT_LOAD' and seg.header.p_flags & P_FLAGS.PF_W and seg.header.p_flags & P_FLAGS.PF_X:
            print('W^X')
            return False
        elif seg.header.p_type == 'PT_GNU_STACK' and seg.header.p_flags & P_FLAGS.PF_X:
            print('No executable stack')
            return False

    return True

def check_elf(data):
    if len(data) < 0x40:
        print('Incomplete ELF Header')
        return False

    if not data.startswith(b'\x7fELF\x02\x01\x01' + b'\x00'*9):
        print('Invalid ELF Magic')
        return False

    if b'\xcd\x80' in data or b'\x0f\x05' in data:
        print('Bad Instruction')
        return False

    if not check_bytes(data, b'\xcd') or not check_bytes(data, b'\x80') or not check_bytes(data, b'\x0f') or not check_bytes(data, b'\x05'):
        print('Bad Instruction')
        return False

    elf = ELFFile(BytesIO(data))
    if ((elf.header.e_type != 'ET_EXEC' and elf.header.e_type != 'ET_DYN')
        or elf.header.e_version != 'EV_CURRENT'
        or elf.header.e_ehsize != 0x40
        or elf.header.e_phoff != 0x40
        or elf.header.e_phnum <= 0
        or elf.header.e_phnum >= 100):
        print('Bad ELF Header')
        return False

    return check_segments(elf)
```

then executes it under a binary which first chroots into a directory
containing a flag file and installs the following seccomp policy:
```
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x1b 0xc000003e  if (A != ARCH_X86_64) goto 0029
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x22 0xffffffff  if (A != 0xffffffff) goto KILL

 0005: 0x15 0x20 0x00 0x00000003  if (A == close) goto ALLOW
 0006: 0x15 0x1f 0x00 0x0000000b  if (A == munmap) goto ALLOW
 0007: 0x15 0x1e 0x00 0x0000000c  if (A == brk) goto ALLOW
 0008: 0x15 0x1d 0x00 0x0000003c  if (A == exit) goto ALLOW
 0009: 0x15 0x1c 0x00 0x000000e7  if (A == exit_group) goto ALLOW

 0010: 0x15 0x00 0x04 0x00000009  if (A != mmap) goto 0015
 0011: 0x20 0x00 0x00 0x00000024  A = prot >> 32 # mmap(addr, len, prot, flags, fd, pgoff)
 0012: 0x15 0x00 0x1a 0x00000000  if (A != 0x0) goto KILL
 0013: 0x20 0x00 0x00 0x00000020  A = prot # mmap(addr, len, prot, flags, fd, pgoff)
 0014: 0x15 0x17 0x18 0x00000002  if (A == 0x2) goto ALLOW else goto KILL

 0015: 0x15 0x00 0x04 0x0000003b  if (A != execve) goto 0020
 0016: 0x20 0x00 0x00 0x00000014  A = filename >> 32 # execve(filename, argv, envp)
 0017: 0x15 0x00 0x15 0x00007ffd  if (A != 0x7ffd) goto KILL
 0018: 0x20 0x00 0x00 0x00000010  A = filename # execve(filename, argv, envp)
 0019: 0x15 0x12 0x13 0xc81d787e  if (A == 0xc81d787e) goto ALLOW else goto KILL

 0020: 0x15 0x00 0x12 0x00000002  if (A != open) goto KILL
 0021: 0x20 0x00 0x00 0x00000014  A = filename >> 32 # open(filename, flags, mode)
 0022: 0x15 0x00 0x10 0x00000000  if (A != 0x0) goto KILL
 0023: 0x20 0x00 0x00 0x00000010  A = filename # open(filename, flags, mode)
 0024: 0x15 0x00 0x0e 0x00031337  if (A != 0x31337) goto KILL
 0025: 0x20 0x00 0x00 0x0000001c  A = flags >> 32 # open(filename, flags, mode)
 0026: 0x15 0x00 0x0c 0x00000000  if (A != 0x0) goto KILL
 0027: 0x20 0x00 0x00 0x00000018  A = flags # open(filename, flags, mode)
 0028: 0x15 0x09 0x0a 0x00000000  if (A == 0x0) goto ALLOW else goto KILL

 0029: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto KILL
 0030: 0x20 0x00 0x00 0x00000000  A = sys_number
 0031: 0x15 0x06 0x00 0x00000001  if (A == i386.exit) goto ALLOW
 0032: 0x15 0x05 0x00 0x00000003  if (A == i386.read) goto ALLOW
 0033: 0x15 0x04 0x00 0x00000004  if (A == i386.write) goto ALLOW
 0034: 0x15 0x03 0x00 0x0000002d  if (A == i386.brk) goto ALLOW
 0035: 0x15 0x02 0x00 0x0000005a  if (A == i386.mmap) goto ALLOW
 0036: 0x15 0x01 0x00 0x0000005b  if (A == i386.munmap) goto ALLOW

 0037: 0x15 0x00 0x01 0x000000fc  if (A != i386.exit_group) goto KILL
 ALLOW: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 KILL: 0x06 0x00 0x00 0x00000000  return KILL
```

If the program's exit status is 137, then the output of the program is
returned to the user. The seccomp policy allows opening, reading and
printing the flag as long as:
 - The flag filename is at addess 0x31337
 - The program can execue both 32 bit and 64 bit syscalls

The ELF validation attempts to block RWX memory, as well as `int 0x80`
and `syscall` instructions that appear in the binary. The validator also
prevents the bytes comprising these instructions (0xcd, 0x80, 0xf, and
0x5) to appear at page boundaries in order to prevent players from
straddling these instructions across pages that are contiguous when
loaded, but not in the ELF file.

## Bug

The binary validator parses the provided ELF using the
[pyelftools](https://github.com/eliben/pyelftools) library. If we can
find a difference in how this library parses ELF files vs. how Linux
parses ELF files, then we may be able to construct a binary which passes
the Python validation but allows us to execute unrestricted code when
executed.

The difference we exploited was:

pyelftools uses the `e_ident[EI_CLASS]` from the ELF header to determine
whether an ELF is in 64 bit or 32 bit format:
https://github.com/eliben/pyelftools/blob/47eea5562c8fb304969a24f5e28221f7fab9afbe/elftools/elf/elffile.py#L573-L576

However, the Linux kernel uses the `e_machine` field in the ELF header:
https://github.com/torvalds/linux/blob/2cf4f94d8e8646803f8fb0facf134b0cd7fb691a/fs/binfmt_elf.c#L848-L849

## Exploit

We construct an ELF with `e_ident[EI_CLASS] = 2` (64-bit) and
`e_machine = 3` (x86). pyelftools will treat this as an 64 bit ELF,
while Linux will load and execute it as a 32 bit ELF.

By taking advantage of the different lengths of 32 bit vs. 64 bit ELF
header structures, we are able to construct an ELF containing a RWX
segment when interpreted as a 32 bit ELF, but only contains a single 0
byte `PT_NULL` segment when interpreted as a 64 bit ELF.

We are then able to use self-modifying code to gain access to 32 bit and
64 bit syscall instructions, which allow us to read and print the flag
in the manner required by the seccomp policy.

[nothing_is_true.asm](nothing_is_true.asm)
