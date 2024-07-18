# [HITCON 2024] Crypto/ZKPOF 

We are given [`server.py`](./src/server.py), and associated [Dockerfiles](./src/)
## Preliminaries

The challenge required a zero knowledge proof of the factorization of a composite number `n`. Reading the paper attached
outlines the way in which this proof works. 

Let's see how the challenge implements this proof of knowledge. 

## The Proof Of Knowledge 

There are two roles: the prover and verifier. For the ZKP to work, both parties need to have knowledge of factorization
of a public modulus `n`. In this challenge, `n = p*q` for primes `p`, `q`.

- **Step 0**: A random value `z` between `[0, 2**80]` is generated and is publicly known.
- **Step 1**: The *prover* generates a random `r` between `0` and `2*1000`.
    We define `x` to be `z^r (mod n)`. 
- **Step 2**: The *verifier* now chooses an arbitrary value `e` that should be less than `2**80`. 
- **Step 3**: The *prover* computes a value `y` based on this input, where `y = r + (n - phi)*e`. `phi` here refers to
    the Euler's totient of `n` (`tot(n) = (p-1)*(q-1)`). 
        - This is where the "knowledge" comes in because it is very difficult to compute the totient of a composite
            number without knowledge of its factorization.
- **step 4**: The *verifier* now verifies this result of `y` by asserting the truth of `x == z^(y - n*e) (mod n)`. A
    simple exercise in substitutions from the known information is enough to prove that the assertion should hold true
    if `y` is correctly computed.
- **step 5**: Repeat until parties are satisfied with posession of shared knowledge.


## The challenge setup 

In the challenge, we start by playing the *verifier* while the server tries to *prove* its knowledge. That is, we
provide values of `e`, while the server shows us the values of `x`, and `y`. This will continue for about `0x137`
rounds or until we, the verifier, are satisfied.

After this, the roles flip and we become the *prover* while the server *verifies*. We must now provide values for `x`
and `y` given the server's choice for `e`. 

This seems impossible without knowledge of the totient of `n` right? It turns out, there might be a leak of knowledge
here.

## The Unfortunate Leak

It turns out there is an oversight with step 2 of our proof implementation. We allow negative values of `e`. Normally,
this wouldn't be a huge problem. However, because we can make our number arbitrarily small (ie a negative number with a
very large magnitude), we trigger python's max digit error that is shown to us by the program.

If the value of y is negative then `zkpof_verify()` will return false since it checks that y is between 0 and 2*1000.
This also returns an error. This time it has a blank message

This is enough to leak knowledge.

## The Idea behind the Exploit

For the sake of convenience, let `u = n - phi`. if we expand the definition of `u` we get `u = p + q - 1` which is
appproximately `p + q`. Our attack will focus on recovering `u` since `phi = n - u`. 

Using this, we express `y` as `y = r + eu`. if `e` is a negative number with a large magnitude (10**4300) and `r` has 
a magnitude of `2**1000`, then `|eu| >>>>> |r|`. So, we can mostly ignore `r` for the rest of this exploit and simply
consider that `y ≈ eu`. using a highly negative value of `e`, we can trigger one of two errors. 

The first occurs when `json.dumps(transcript)` is called which converts `y` to a string. If we get this error about the
max digit size, we have that y or `eu < -10**4300` or rather `u > -10**4300/e` (recall `e` is negative so we flip the
sign).

The second error would occur in the case that `y` is negative but is not negative enough to trigger error 1. That is,
`0 > eu > -10**4300`. Rather, `u < -10**4300/e`. 

Great! we now have a binary search that narrows down a value of `u`. Since we only have 0x137 rounds of verification
with the server, we can't recover all the bits of `u`. Instead, we are left with a lower and upper bound for the value
of `u` (call it `lo` and `hi`).

However, with some Lattice and Coppersmith small roots magic we are able recover `p`. 

Recall that our `y` is not exactly equal to `eu`. There is some deviation from this in the lower bits of `u` since we
add `r`. However, with some clever square roots, we eliminate this error out of our approximation of `y` and hence `u`. 
since `p + q` is much much larger than `r`. The integer square root of `p + q` is more or less the same as the integer
square root of `u`. We use this logic to craft a highly accurate approximation of `p` as follows:

`p ==  u//2 + isqrt(u^2//4 - n)`

Using the lower bound of `u`, we can create a lower bound for `p` and call it `pleft`. Similarly, we use the upper bound
to create an upper bound for `p` called `pright`. 

From our lower bound of `p`, we can create a polynomial `p = pleft + x`. where `x` is an unknown. We can determine that
since the maximum value of `p` is `pright`, we deduce that `x` has to be less than `pright - pleft`. So, we end up with
a polynomial `pleft + x` and a bound `X = pright - pleft`. We can use to Coppersmith's small roots to recover `p`. We
can then trivially calculate `phi` and use that to complete the rest of challenge from the server.


## Exploit Script

[`solve_pq.sage`](./solve_pq.sage)
```py
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
```

[`solve.py`](./solve.py)
```py
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
```

## Credits
@b2xiao
