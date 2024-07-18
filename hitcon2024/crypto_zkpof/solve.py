from pwn import remote, context
import random

# context.log_level = "debug"

#s = remote("jammy", 11111)
s = remote("zkpof.chal.hitconctf.com", 11111)

s.recvuntil(b"n = ")
n = int(s.recvline())

rand = random.Random(1337)

limit = 10**4300
A = 2**1000

# 2^511 <= p, q < 2^512
lo = 1 << 512
hi = 1 << 514
for i in range(0x137):
    z = rand.randrange(2, n)

    mid = (lo + hi) // 2
    s.recvuntil(b"e = ")
    s.sendline(str(-limit // mid).encode())
    s.recvuntil(b"Error: ")
    err = s.recvline().strip()
    print(i, err)
    if err == b"":
        hi = mid
    else:
        lo = mid + 1

print(lo)
print(hi)
import subprocess
p = int(subprocess.check_output(["sage", "solve_pq.sage", str(lo), str(hi), str(n)]))
print(p)
assert n % p == 0
q = n // p

phi = (p - 1) * (q - 1)
for i in range(13):
    z = rand.randrange(2, n)

    r = random.randrange(A)
    s.recvuntil(b"x = ")
    s.sendline(str(pow(z, r, n)).encode())
    s.recvuntil(b"e = ")
    e = int(s.recvline())
    s.recvuntil(b"y = ")
    s.sendline(str(r + (n - phi) * e).encode())

s.interactive()

# hitcon{the_error_is_leaking_some_knowledge}
