## blackout - Pwn Problem - Writeup by Robert Xiao (@nneonneo)

blackout was a misc challenge solved by 7 teams, worth 322 points.

Description:

> Letter to the Black World
> 
> nc blackout.seccon.games 9999
> 
> blackout.tar.gz b54c89b6e2629898acea225798043c9f5b359d33

We're given an x86-64 Linux binary. A later version of the handout included a Dockerfile and C source code, but we did not use these.

## Reversing

The binary is a simple "memo" service providing three operations on an array of 8 "letters":

1. Write: allocate a letter of any length up to 65536 to a selected index. The letter is filled with zeros, and then the user can write one line of text up to the letter size (minus one) into the region. Write does not check to see if a letter is already allocated before overwriting it.
2. Blackout: specify a target letter index and a "word" (one line of at most 31 characters). `memmem` is used to repeatedly locate the word, which is then replaced with `*` characters. The redacted letter is printed out at the end.
3. Delete: free a letter, setting the pointer to NULL.

The bug in the binary is that the return value from `memmem`, which is a pointer, is truncated down to an `int`, as can be seen in Ghidra:

```c
pvVar2 = memmem(cur,(size_t)(letter[idx] + (letter_len - (long)cur)),word,word_len);
pvVar2 = (void *)(long)(int)pvVar2;
```

This bug can be caused by e.g. failing to `#include <string.h>`, as C will default to an `int` return type (as it turns out, this is exactly the bug in the C source file which was provided later).

The binary is compiled without PIE, so it will be loaded at address 0x400000. The heap will consequently be allocated at a small random offset past the binary, up to a maximum address of around 0x2000000. Thus, the heap pointers will usually fit inside the 32-bit range.

## Exploitation

We can allocate 0x100000000 (4GB) of memory by repeatedly leaking max-size letters, pushing our heap pointers past the 32-bit range. When `memmem` is applied to these pointers, the pointers will be truncated down to the 32-bit range, allowing us to overwrite other heap structures.

The bug allows us to write any number of `*` (0x2a) bytes to `heap_addr & 0xffffffff` where `heap_addr` is within a letter allocation. Because of ASLR, we cannot initially write to the binary, only other heap structures.

The basic flow of the exploit is as follows:

- Allocate and free two small chunks at the start of the heap.
- Allocate 8 smallbin-sized chunks, then free them to get a libc pointer into the heap
- Allocate the first small chunk again, which will be used for leaking.
- Allocate ~65534 chunks of size 65519, which gets us to approximately `0x100000000 + heap_base`.
- Use the bug to overwrite the null terminators of the first small chunk, then "blackout" that chunk with a dummy word to leak heap and libc pointers
- Do some allocations to control the second-lowest-byte of the top address, then allocate some chunks near 0x1....2a00
- Use the bug to overwrite a next pointer in tcache to point inside a controlled chunk, then allocate the fake chunk to control the tcache next pointer
- At this point, we can allocate anywhere we want; I chose to allocate near `&letters`, overwrite the array to leak a stack address, then do a second fake allocation into the stack and ROP to win.
- Get the flag from a shell: `SECCON{D0n't_f0Rg3T_fuNcT10n_d3cL4r4T10n}`

See the full exploit in [`exploit.py`](exploit.py).
