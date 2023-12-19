# Everything is Permitted

## Overview

This challenge is a follow-up to [Nothing is True](../nothing_is_true/README.md).
The problem is essentially the same, with the following differences:
 - The Python checker expects a 32-bit ELF (as determined by
   `e_ident[EI_CLASS]`.
 - There are some minor changes to addresses and allowed syscalls in the
   seccomp policy. These changes aren't very interesting - they still
   allow the program to read and output the flag given the ability to
   run 32 bit and 64 bit syscalls.

## Exploit

We exploit the same pyelftools vs. Linux ELF parsing difference, except
in the reverse direction.

This time, we construct an ELF with `e_ident[EI_CLASS] = 1` (32 bit) and
`e_machine = 0x3e` (x86-64).

Once again, we use differences in field lengths in 64 bit vs 32 bit ELFs
to contain an RWX segment when the ELF is treated as 64 bit, while
containing a fake non-loaded segment when treated as 32 bit.

This allows us to execute arbitrary 32 bit and 64 bit syscalls, and
obtain the flag.

[nothing_is_true.asm](nothing_is_true.asm)
