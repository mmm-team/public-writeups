from pwn import *
import subprocess
from multiprocessing import cpu_count
import sys

s = remote("chal-collision.chal.hitconctf.com", 33333)

def h2b(x):
    return (x & ((1<<56) - 1)).to_bytes(7, "little")

for i in range(8):
    log.info("=== ROUND %d/8 ===", i + 1)
    s.recvuntil(b'salt: ')
    salt = s.recvline().strip().decode()

    s.sendlineafter(b'm1: ', b'ABCD'.hex().encode())
    s.sendlineafter(b'm2: ', b'abcd'.hex().encode())
    target = s.recvuntil(b"!=", drop=True).strip().decode()

    log.info("salt=%s target=%s", salt, target)

    seed = subprocess.check_output(["./findseed", salt, target]).strip().decode()
    log.info("seed=%s", seed)

    collision = subprocess.check_output(["./brute", str(cpu_count()), seed, salt], stderr=sys.stderr).strip().decode()
    log.info("collision=%s", collision)

    a, b = collision.split()
    s.sendlineafter(b'm1: ', h2b(int(a, 16)).hex().encode())
    s.sendlineafter(b'm2: ', h2b(int(b, 16)).hex().encode())

s.interactive()

# hitcon{PYTHONHASHSEED_has_less_entropy_than_it_should_be}
# run on a 96-core machine in ~2 minutes
