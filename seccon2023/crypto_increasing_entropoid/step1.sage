import sys
sys.path.append("dist")
from problem import *

p = 18446744073709550147
F = GF(p)
a3, a8, b2, b7 = F(1), F(3), F(3), F(7)
g = (F(13), F(37))

load("grouplaw.sage")

## adapted from entropoid-attack/attack.sage, https://yx7.cc/files/entropoid-attack.tar.gz
# proj = iota
proj = lambda x: ev1(gfmap,x)

gen = GF(p).multiplicative_generator()
famap = lambda tup: tuple(t.log(gen) for t in tup)      # (Fp*)^2 -> (Z/(p-1),+)^2
afmap = lambda vec: tuple(gen**v for v in vec)          # (Z/(p-1),+)^2 -> (Fp*)^2

conjpair = lambda el: (proj(el), proj(ev1(sigma, el)))
pow2 = lambda gs,es: ev(fmul, *(tuple(t**e for t in g) for g,e in zip(gs,es)))

gs = conjpair(g)
mat = matrix(map(famap, gs))

def do_dlog(Ka):
    if isinstance(Ka, EntropoidElement):
        Ka = (Ka.x1, Ka.x2)
    Ka = tuple(F(x) for x in Ka)

    vec = vector(famap(proj(Ka)))
    sol = mat.solve_left(vec)
    sol = (sol % (p-1)).change_ring(ZZ)
    return sol

## dlog every number in the output to leak the a values
params = EntropoidParams(
    p=18446744073709550147,  # safe prime
    a3=1,
    a8=3,
    b2=3,
    b7=7,
)
E = Entropoid(params)
Eg = E(13, 37)

import re
for i, row in zip(range(256), open("dist/output.txt")):
    ax, ay, bx, by = map(int, re.findall("\d+", row))
    ae = do_dlog((ax, ay))
    be = do_dlog((bx, by))
    print(sum(ae), sum(be))
