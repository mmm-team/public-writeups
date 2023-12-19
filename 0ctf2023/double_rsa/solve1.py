from pwn import *
import ast
from math import gcd
import itertools
from Crypto.Util.number import inverse
from sage.all import Zmod, ZZ, var

import sys; sys.path.append("../../utils/math")
from dlog import pohlig_hellman
from solve_crt import solve_crt
from solvemod import solve_quadratic_mod_pk
from solvelinmod import solve_linear_mod

from params import *
from drsa1 import *

lcg = LCG()
alice = RSA(lcg)
bob = RSA(lcg, p, q)

s = remote("127.0.0.1", 32225); local = True
#s = remote("eu.chall.ctf.0ops.sjtu.cn", 32225); local = False

if not local:
    import subprocess

    pow_bits = s.recvline().split()
    x = pow_bits[2].rstrip(b")")
    target = pow_bits[4].decode()
    res = subprocess.check_output([sys.executable, "fast_chalsolve.py", x, target]).strip()
    s.sendline(res)

def inverse(u, v):
    """The inverse of :data:`u` *mod* :data:`v`."""
    
    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = u3 // v3
        u1, v1 = v1, u1 - v1*q
        u3, v3 = v3, u3 - v3*q
    while u1<0:
        u1 = u1 + v
    return u1

log.info("starting")
s.recvuntil(b"Give me your RSA key plz.\n")
s.sendline(b'%x' % p)
s.sendline(b'%x' % q)
del alice.e
del alice.n
del alice.p
del alice.q
del alice.phi
del alice.d
lcg.p = int(s.recvline())
lcg.a = ast.literal_eval(s.recvline().decode())
lcg.b = int(s.recvline())
del lcg.s
alice.l = lcg

del bob.e
del bob.d
bob.l = lcg

phi = (p - 1) * (q - 1) // 2
gs = [
    (g, p-1, q-1),
    (solve_crt([g, g**2], [p, q])[0], p-1, (q-1)//2),
    (solve_crt([g**2, g], [p, q])[0], (p-1)//2, q-1)
]

def dlog_n(y, g=None):
    if g is None:
        my_gs = gs
    else:
        my_gs = [gg for gg in gs if gg[0] == g]
        assert my_gs, "can't use arbitrary gs, sorry"

    for g, pphi, qphi in my_gs:
        try:
            ep = pohlig_hellman(g, y, p, pf)
            eq = pohlig_hellman(g, y, q, qf)
            res, _phi = solve_crt([ep, eq], [pphi, qphi])
            assert _phi == phi
            return (res, g)
        except Exception:
            continue
    raise Exception(f"unlucky: dlog_n({y}) is not defined over any of the {len(my_gs)} gs")

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

## Phase 1: recover alice.n, lcg.s, bob.e
ls = Zmod(lcg.p)["s0", "s1", "s2", "s3", "s4", "s5"].gens()
lcg.s = list(ls)
for i in range(40):
    lcg.next()

results = []
while len(results) < 18:
    a_refresh = lcg.next()
    ae_noise = lcg.next()
    b_refresh = lcg.next()
    be_noise = lcg.next()

    # send -1 to get either +1 or bob.noise_enc(n-1)
    s.recvuntil(b"pt: ")
    s.sendline(b"-1")
    s.recvuntil(b"ct: ")
    bct = int(s.recvline(), 16)

    if bct == 1:
        continue

    results.append(dict(be_noise=be_noise.change_ring(ZZ), bct=bct))

# figure out which g generates an-1
bes = []
chosen_g = g
for i in range(len(results)):
    be, bg = dlog_n(results[i]["bct"])
    if bg != g:
        assert chosen_g in [g, bg]
        chosen_g = bg
    bes.append((be, bg))

for i in range(len(results)):
    be, bg = bes[i]
    if bg != chosen_g:
        bes[i] = dlog_n(results[i]["bct"], chosen_g)

assert all(bg == chosen_g for be, bg in bes)
log.info(f"{chosen_g=}")

gg = gcd(*[be for be, bg in bes])
bes = [(be//gg, bg) for be, bg in bes]
mphi = phi // gg
log.info(f"{gg=}")

equations = []
variables = {s.change_ring(ZZ): lcg.p for s in ls}
# alice.n - 1 == g ^ (anei ^ -1 mod phi)
anei = var('anei')
variables[anei] = mphi
for i in range(len(results)):
    bs = var('bs%d' % i)
    variables[bs] = lcg.p
    be = var('be%d' % i)
    variables[be] = [-(1 << (E_BITS - 1)), (1 << (E_BITS - 1))]
    equations.append((bs == results[i]["be_noise"], lcg.p))
    equations.append((bs + be == bes[i][0] * anei, mphi))

values = solve_linear_mod(equations, variables)
values = {v: int(i) for v, i in values.items()}

alice.n = pow(chosen_g, inverse(values[anei], mphi) * gg, n) + 1
log.info(f"{alice.n=}")
lcg.s = [int(sx([values[s] for s in ls])) for sx in lcg.s]
bob.e = (values[bs] + values[be]) ^ values[bs]

## Receive phase 2 parameters
s.recvuntil(b"pt:")
s.sendline(b"0")
s.recvuntil(b"secrets_ct:")
secrets_ct = int(s.recvline(), 16)

bob.refresh()
secrets_be = bob.e ^ lcg.next()
log.info(f"{secrets_be=}")

del lcg.p
del lcg.a
del lcg.b
del lcg.s

del bob.e

## Phase 2: recover secrets
for candidate_secrets_ct in bob_decrypt(secrets_ct, secrets_be):
    results = []
    for i in range(12):
        s.recvuntil(b"ct:")
        s.sendline(b"%x" % pow(candidate_secrets_ct, i + 1, alice.n))
        s.recvuntil(b"pt:")
        bct = int(s.recvline(), 16)
        results.append(bct)

    # With any luck, we just encrypted secrets^(i+1) with random es.
    try:
        # figure out which g generates secrets
        bes = []
        chosen_g = g
        for i in range(len(results)):
            be, bg = dlog_n(results[i])
            if bg != g:
                assert chosen_g in [g, bg], "mismatched bg"
                chosen_g = bg
            bes.append((be, bg))

        for i in range(len(results)):
            be, bg = bes[i]
            if bg != chosen_g:
                bes[i] = dlog_n(results[i], chosen_g)

        assert all(bg == chosen_g for be, bg in bes), "mismatched bg"
        log.info(f"{chosen_g=}")

        gg = gcd(*[be for be, bg in bes])
        bes = [(be//gg, bg) for be, bg in bes]
        mphi = phi // gg
        log.info(f"{gg=}")

        equations = []
        # variable bounds will be centered on 0 in order to avoid
        # the all-zeros solution
        variables = {}
        # secret == g ^ (sei ^ -1 mod phi)
        sei = var('sei')
        variables[sei] = (-(mphi // len(results)), mphi // len(results))
        for i in range(len(results)):
            bs = var('bs%d' % i)
            vlm = 1 << (P_BITS - 1)
            variables[bs] = (-vlm, vlm)
            equations.append((bs * (i + 1) == bes[i][0] * sei, mphi))

        values = solve_linear_mod(equations, variables)
        values = {v: int(i) for v, i in values.items()}
        log.info(f"{values=}")
        secrets = pow(chosen_g, inverse(values[sei], mphi) * gg, n)
        log.info(f"{secrets=}")
        break

    except Exception as e:
        log.warn("wrong candidate secrets_ct, try again: %s", e)

s.recvuntil(b"ct:")
s.sendline(b"0" * (P_BITS // 2))

log.info("secrets=%d", secrets)
s.clean(0.1)
s.sendline(b"%x" % secrets)

s.interactive()

# flag{DLP_and_HNP_s0_345y}
