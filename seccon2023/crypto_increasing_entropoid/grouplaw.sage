#!/usr/bin/env sage
# from https://yx7.cc/files/entropoid-attack.tar.gz

if all(v in globals() for v in 'p a3 a8 b2 b7'.split()):
    R = GF(p)
else:
    R.<a3,a8,b2,b7> = QQ[]
S.<x1,x2,y1,y2> = R.fraction_field()[]
T.<u1,u2,v1,v2,w1,w2> = R.fraction_field()[]

xx,yy = (x1,x2), (y1,y2)
uu,vv,ww = (u1,u2), (v1,v2), (w1,w2)

# formulas from ePrint 2021/469
emul = (a3*(a8*b2-b7)/(a8*b7)+a3*x2+a8*b2*y1/b7+a8*x2*y1, -b2*(a8-a3*b7)/(a8*b7)+a3*b7*y2/a8+b2*x1+b7*x1*y2)
lunit = (1/b7-a3/a8, 1/a8-b2/b7)
linv = ((1-a3*b2-a3*b7*x2)/(a8*(b2+b7*x2)), (1-a3*b2-a8*b2*x1)/(b7*(a3+a8*x1)))

ev = lambda ff,x,y: tuple(f(*x,*y) for f in ff)
ev1 = lambda ff,x: tuple(f(*x,None,None) for f in ff)

def invmap(eqs):
    assert len(eqs) == 2 and not any(set(yy) & set(eq.variables()) for eq in eqs)
    sol = [None] * len(xx)
    for eq in Ideal([y-eq for y,eq in zip(yy,eqs)]).groebner_basis(algorithm='toy:buchberger'):
        v, = set(xx) & set(eq.variables())
        sol[xx.index(v)] = (v - eq / eq.monomial_coefficient(v)).subs({y1:x1, y2:x2})
    return tuple(sol)

################################################################

# Murdoch: Quasi-Groups Which Satisfy Certain Generalized Associative Laws, §5

sigma = ev(emul, xx, lunit)
print('automorphism:', sigma)
assert ev1(sigma, emul) == ev(emul, ev1(sigma,xx), ev1(sigma,yy))               # homomorphism
assert ev1(sigma, sigma) == xx                                                  # self-inverse

gmul = ev(emul, sigma, yy)
print('group multiplication:', gmul)
assert ev(gmul, uu, ev(gmul, vv, ww)) == ev(gmul, ev(gmul, uu, vv), ww)         # associative

gunit = lunit
print('group unit:', gunit)
assert ev(gmul, gunit, xx) == ev(gmul, xx, gunit) == xx                         # two-sided unit

ginv = ev1(sigma, linv)
print('group inverse:', ginv)
assert ev(gmul, ginv, xx) == ev(gmul, xx, ginv) == gunit                        # two-sided inverse

# entropoid multiplication is just group multiplication tweaked by sigma
assert emul == ev(gmul, sigma, yy)

# sigma is indeed a group automorphism
assert ev(gmul, sigma, ev1(sigma, yy)) == ev1(sigma, gmul)

################

# maps to the underlying finite fields

fgmap = (x1/b7 - a3/a8, x2/a8 - b2/b7)  # (Fp*)^2 -> E*
print('map from (Fp*)^2:', fgmap)
gfmap = invmap(fgmap)                   # E* -> (Fp*)^2
print('map to (Fp*)^2:  ', gfmap)

# our map is a group isomorphism
fmul = (x1*y1, x2*y2)   # multiplication in (Fp*)^2
assert ev1(fgmap, fmul) == ev(gmul, fgmap, ev1(fgmap,yy))
assert ev1(gfmap, gmul) == ev(fmul, gfmap, ev1(gfmap,yy))

