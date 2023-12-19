""" make smooth p/q for easy recovery of e """
import numpy as np
import random
import math
from Crypto.Util.number import isPrime

primes = []
maxbits = 15

sieve = np.ones((1 << maxbits,), dtype=bool)
sieve[1] = False
for i in range(2, len(sieve)):
    if sieve[i]:
        primes.append(i)
        sieve[::i] = False

def factor(x):
    res = []
    for p in primes:
        count = 0
        while x % p == 0:
            x //= p
            count += 1
        if count:
            res.append((p, count))
        if x == 1:
            return res
    raise Exception("couldn't factorize %d with small primes" % x)

def getSmoothPrime(bits):
    good_primes = [p for p in primes if p.bit_length() == maxbits]
    while 1:
        n = 1
        while n.bit_length() < bits - maxbits:
            n *= random.choice(good_primes)
        n *= 2
        if n.bit_length() >= bits - 6:
            continue
        rr = range(((3 << (bits - 2)) + n - 1) // n, ((1 << bits) - 1) // n + 1)
        n *= random.choice([pp for pp in primes if pp in rr])
        if isPrime(n + 1):
            return n + 1

if __name__ == "__main__":
    from collections import Counter

    p = getSmoothPrime(512)
    pf = factor(p - 1)

    while 1:
        q = getSmoothPrime(512)
        qf = factor(q - 1)
        if [f for (f, _) in qf if (f, 1) in pf and f != 2]:
            continue
        break

    n = p * q
    nf = factor((p - 1) * (q - 1))

    g = 2
    while 1:
        if all(pow(g, (p - 1) // f, p) != 1 for f, _ in pf) and \
           all(pow(g, (q - 1) // f, q) != 1 for f, _ in qf):
            break
        g += 1

    with open("params.py.new", "w") as outf:
        print(f"{p = }", file=outf)
        print(f"{pf = }", file=outf)
        print(f"{q = }", file=outf)
        print(f"{qf = }", file=outf)
        print(f"{n = }", file=outf)
        print(f"{nf = }", file=outf)
        print(f"{g = }", file=outf)
