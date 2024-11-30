# dual_summon - Crypto

By: Lyndon

> You are a beginner summoner. It's finally time to learn dual summon
>
> `nc dual-summon.seccon.games 2222`
> 
> [`dual_summon.tar.gz`]([https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/brokenshare/brokenshare-4af73c97cbac939d9eade6a32503050a7403ba47.tar.gz](https://score.quals.seccon.jp/api/download?key=quals202413%2Fdual_summon.tar.gz))
>
- Author: kurenaif
- Solves: 63

## Challenge

In `server.py`:

```py
from Crypto.Cipher import AES
import secrets
import os
import signal

signal.alarm(300)

flag = os.getenv('flag', "SECCON{sample}")

keys = [secrets.token_bytes(16) for _ in range(2)]
nonce = secrets.token_bytes(16)

def summon(number, plaintext):
    assert len(plaintext) == 16
    aes = AES.new(key=keys[number-1], mode=AES.MODE_GCM, nonce=nonce)
    ct, tag = aes.encrypt_and_digest(plaintext)
    return ct, tag

# When you can exec dual_summon, you will win
def dual_summon(plaintext):
    assert len(plaintext) == 16
    aes1 = AES.new(key=keys[0], mode=AES.MODE_GCM, nonce=nonce)
    aes2 = AES.new(key=keys[1], mode=AES.MODE_GCM, nonce=nonce)
    ct1, tag1 = aes1.encrypt_and_digest(plaintext)
    ct2, tag2 = aes2.encrypt_and_digest(plaintext)
    # When using dual_summon you have to match tags
    assert tag1 == tag2

print("Welcome to summoning circle. Can you dual summon?")
for _ in range(10):
    mode = int(input("[1] summon, [2] dual summon >"))
    if mode == 1:
        number = int(input("summon number (1 or 2) >"))
        name   = bytes.fromhex(input("name of sacrifice (hex) >"))
        ct, tag = summon(number, name)
        print(f"monster name = [---filtered---]")
        print(f"tag(hex) = {tag.hex()}")

    if mode == 2:
        name   = bytes.fromhex(input("name of sacrifice (hex) >"))
        dual_summon(name)
        print("Wow! you could exec dual_summon! you are master of summoner!")
        print(flag)
```

## Solution

This challenge was about exploiting a nonce reuse in AES-GCM to control an authentication tag. The server keeps track of two authentication keys `K_1,K_2`
and a common nonce `IV` for all encryptions. The protocol itself supports two operations:
- **`summon(n, pt)`**: Accepts an integer `n` (either `1` or `2`) and a plaintext `pt`, and outputs the authentication tag from computing `AES-GCM(K_n, pt)`.
- **`dual_summon(pt)`**: Accepts a plaintext `pt` and computes `tag1 = AES-GCM(K_1, pt)` and `tag2 = AES-GCM(K_2, pt)`. If `tag1 == tag2`, then it outputs the flag.

In addition, the length of the provided plaintexts must be 16 bytes long.

The rough formula for computing the authentication tag is `tag = (P + E_K(nonce))*H^2 + L*H + E_K(nonce || 1)`, where `H = E_K(0)`.
Note that all the math is done over a `GF(2^128)` polynomial. If we add two tags from two different plaintexts, a lot of canellations occur and we just end up with
`tag0 + tag1 = (P0 + P1)*H^2`, where `P0` and `P1` are the two plaintexts. Now it is easy to recover `H` by root finding.

It turns out that once we have `H`, it becomes eays to forge two tags to be identical. Suppose we know that some plaintext `P` encrypts to a tag `T`. Then the plaintext
`P' = P + x` will necessarily have a tag of `T' = T + x*H^2` (refer to the tag formula above).

To pass `dual_summon()`, we just need to find `x` such that the two tags are equal. In other words,
```
tag0 + x*H0^2 = tag1 + x*H1^2
tag0 - tag1 = x*(H1^2 - H0^2)
x = (tag0 - tag1) / (H1^2 - H0^2)
```

Here is a high level overview of the solution:
- Call `summon(1, pt0)` and `summon(1, pt1)` for any two plaintexts `pt0,pt1`, and use the linearity to recover `H_0`.
- Do the same for the second key to recover `H_1`.
- Generate two tags `tag0` and `tag1` for each key, for some fixed plaintext that we know.
- Compute the delta `x` that needs to be added to the plaintext to pass `dual_summon()`, i.e. `x = (tag0 - tag1) / (H1^2 - H0^2)`.
- Get the flag!

## Solve

```py
from sage.all import *
from pwn import *
from Crypto.Util.number import *

X = GF(2)['X'].gen()
P = GF(2**128, modulus=X**128 + X**7 + X**2 + X + 1, names='Y')

def bytes_to_gf(x):
    x = int.from_bytes(x, 'big')
    x = int(f'{x:0128b}'[::-1], 2)
    return P.fetch_int(x)

def gf_to_bytes(x):
    x = x.integer_representation()
    x = int(f'{x:0128b}'[::-1], 2)
    return x.to_bytes(16, 'big')

def summon(n, pt):
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'>', b'%d' % n)
    io.sendlineafter(b'>', pt.hex().encode())
    io.recvuntil(b'tag(hex) = ')
    return bytes.fromhex(io.recvline().decode())

def dual_summon(pt):
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'>', pt.hex().encode())

def recover_h(n):
    P0, P1 = b'A' * 16, b'B' * 16
    tag0, tag1 = summon(n, P0), summon(n, P1)
    T = bytes_to_gf(tag0) + bytes_to_gf(tag1)
    return (T / (bytes_to_gf(P0) + bytes_to_gf(P1))).sqrt()

# tag = (P + E_K(nonce))*H^2 + L*H + E_K(nonce || 1) where H = E_K(0)
# tag0 + tag1 = (P0 + P1)*H^2

# io = process(['python', 'server.py'])
io = remote('dual-summon.seccon.games', 2222)

L = bytes_to_gf(long_to_bytes(16 * 8))

H0 = recover_h(0)
H1 = recover_h(1)

Pnull = b'\x00' * 16
tag0 = summon(0, Pnull)
tag1 = summon(1, Pnull)

# tag0 + x*H0^2 = tag1 + x*H1^2
# tag0 - tag1 = x*(H1^2 - H0^2)
x = (bytes_to_gf(tag0) - bytes_to_gf(tag1)) / (H1**2 - H0**2)
dual_summon(gf_to_bytes(x))
io.interactive()
```
