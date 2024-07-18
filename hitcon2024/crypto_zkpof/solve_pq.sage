import sys
from math import isqrt

left, right, n = map(int, sys.argv[1:])

m = left // 2; 
pleft = m + isqrt(m * m - n)
m = right // 2; 
pright = m + isqrt(m * m - n)

P.<x> = PolynomialRing(Zmod(n))
soln = (pleft + x).small_roots(X=pright - pleft, beta=0.50)
print(pleft + soln[0])
