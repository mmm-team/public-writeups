from pwn import *
import ast
from Crypto.Util.number import inverse

import sys; sys.path.append("../../utils/math")
from dlog import pohlig_hellman
from solve_crt import solve_crt
from solvemod import solve_quadratic_mod_pk
import itertools

from params import *
from drsa0 import *

lcg = LCG()
alice = RSA(lcg)
bob = RSA(lcg)

s = remote("127.0.0.1", 32226); local = True
#s = remote("eu.chall.ctf.0ops.sjtu.cn", 32226); local = False

if not local:
    import subprocess

    pow_bits = s.recvline().split()
    x = pow_bits[2].rstrip(b")")
    target = pow_bits[4].decode()
    res = subprocess.check_output([sys.executable, "fast_chalsolve.py", x, target]).strip()
    s.sendline(res)

s.recvuntil(b"Give me your RSA key plz.\n")
s.sendline(b'%x' % p)
s.sendline(b'%x' % q)
alice.e = int(s.recvline())
orig_ae = alice.e
alice.n = int(s.recvline())
del alice.p
del alice.q
del alice.phi
del alice.d
lcg.p = int(s.recvline())
lcg.a = ast.literal_eval(s.recvline().decode())
lcg.b = int(s.recvline())
lcg.s = ast.literal_eval(s.recvline().decode())
alice.l = lcg

del bob.e
bob.n = n
bob.p = p
bob.q = q
bob.phi = (p - 1) * (q - 1)
del bob.d
bob.l = lcg

# phi, but minus the confounding factors of 2
phi = (p - 1) * (q - 1) // 4

def dlog_n(g, y):
    ep = pohlig_hellman(g, y, p, pf)
    eq = pohlig_hellman(g, y, q, qf)
    res, _ = solve_crt([ep, eq], [(p-1) // 2, (q-1) // 2])
    return res

def bob_decrypt(ct, be):
    poss = []
    for pp in [p, q]:
        bd = inverse(be, pp - 1)
        pt = pow(ct, bd, pp)
        if (be * bd) % (pp - 1) == 2:
            poss.append(list(solve_quadratic_mod_pk(1, 0, -pt, pp, 1)))
        else:
            poss.append([pt])

    for ptp, ptq in itertools.product(*poss):
        pt, _ = solve_crt([ptp, ptq], [p, q])
        yield pt

## Phase 1: recover bob.e
alice.refresh()
next_ae = alice.e ^ lcg.next()
b_refresh = lcg.next()
next_be_noise = lcg.next()
addend = next_be_noise // phi

pt = 2
act = pow(pt, next_ae, alice.n)

s.recvuntil(b"pt: ")
s.sendline(b"%x" % pt)
s.recvuntil(b"ct: ")
bct = int(s.recvline(), 16)

bob.e = (dlog_n(act, bct) + addend * phi) ^ next_be_noise
assert bob.e < 2 ** E_BITS
log.info("recovered bob.e = %d", bob.e)

## Receive phase 2 parameters
s.recvuntil(b"pt:")
s.sendline(b"0")
s.recvuntil(b"secrets_ct:")
secrets_ct = int(s.recvline(), 16)

bob.refresh()
secrets_be = bob.e ^ lcg.next()

lcg.p = int(s.recvline())
lcg.a = ast.literal_eval(s.recvline().decode())
lcg.b = int(s.recvline())
lcg.s = ast.literal_eval(s.recvline().decode())
bob.l = lcg

del bob.e

## Phase 2: recover bob.e, again
b_refresh = lcg.next()
next_be_noise = lcg.next()
addend = next_be_noise // phi

pt = random.getrandbits(P_BITS)
act = pow(pt, orig_ae, alice.n)

s.recvuntil(b"ct: ")
s.sendline(b"%x" % act)
s.recvuntil(b"pt: ")
bct = int(s.recvline(), 16)

bob.e = (dlog_n(pt, bct) + addend * phi) ^ next_be_noise
assert bob.e < 2 ** E_BITS
log.info("recovered bob.e = %d", bob.e)

## Finally, decrypt secrets_ct
for candidate_secrets_ct in bob_decrypt(secrets_ct, secrets_be):
    s.recvuntil(b"ct:")
    s.sendline(b"%x" % candidate_secrets_ct)
    s.recvuntil(b"pt:")
    final_ct = int(s.recvline(), 16)

    bob.refresh()
    next_be = bob.e ^ lcg.next()
    for secrets in bob_decrypt(final_ct, next_be):
        if secrets < (1 << (P_BITS // 8)):
            break
    else:
        log.warn("wrong candidate secrets_ct, try again")
        continue

    break

s.recvuntil(b"ct:")
s.sendline(b"0" * (P_BITS // 2))

log.info("secrets=%d", secrets)
s.clean(0.1)
s.sendline(b"%x" % secrets)

s.interactive()

# flag{All_Crypto_challenges_in_0CTF/TCTF2023_are_solvable_on_laptop_good_luck_and_have_fun}
