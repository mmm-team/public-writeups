# BrokenShare - Crypto

By: Lyndon

> I implemented another secret sharing this year, but it doesn’t recover the flag correctly. Can you help me fix it and recover the flag?
>
> [`brokenshare.tar.gz`](https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/brokenshare/brokenshare-4af73c97cbac939d9eade6a32503050a7403ba47.tar.gz)
>
- Author: maple3142
- Solves: 26

## Challenge

In `chall.py`:

```py
import numpy as np
from Crypto.Cipher import AES
from hashlib import sha256
from random import SystemRandom
import sys

p = 65537
rand = SystemRandom()


def share(secret: bytes, n: int, t: int):
    # (t, n) secret sharing
    poly = np.array([rand.randrange(0, p) for _ in range(t)])
    f = lambda x: int(np.polyval(poly, x) % p)

    xs = rand.sample(range(t, p), n)
    ys = [f(x) for x in xs]
    shares = [(int(x), int(y)) for x, y in zip(xs, ys)]

    ks = [f(x) for x in range(t)]
    key = sha256(repr(ks).encode()).digest()
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.nonce + cipher.encrypt(secret)
    return ct, shares


def interpolate(xs: list[int], ys: list[int], x: int):
    n = len(xs)
    assert n == len(ys)
    res = 0
    for i in range(n):
        numer, denom = 1, 1
        for j in range(n):
            if i == j:
                continue
            numer *= x - xs[j]
            denom *= xs[i] - xs[j]
        res += ys[i] * numer * pow(denom, -1, p)
    return res % p


def recover(ct: bytes, shares: list, t: int):
    xs, ys = zip(*shares[:t])
    ks = [interpolate(xs, ys, x) for x in range(t)]
    key = sha256(repr(ks).encode()).digest()
    cipher = AES.new(key, AES.MODE_CTR, nonce=ct[:8])
    return cipher.decrypt(ct[8:])


def sanity_check():
    message = b"hello world"
    ct, shares = share(message, 16, 4)
    assert recover(ct, shares, 4) == message


if __name__ == "__main__":
    sanity_check()
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
    ct, shares = share(flag, 48, 24)
    print(f"{ct = }")
    print(f"{shares = }")

    if recover(ct, shares, 24) != flag:
        print("Failed to recover flag ???", file=sys.stderr)
```

## Overview

The challenge implements a secret sharing algorithm known as SSS (Shamir's secret sharing). `share()` first generates a secret polynomial $f(x)$ in $GF(p)$ of degree $t=24$,
where $p=65537$. It then generates $n=48$ random values of $x$ and evaluates the polynomial at those points. We are given these points, but to get the flag we essentially
need to recover the polynomial (a.k.a. its coefficients).

This is actually a famous problem known as polynomial interpolation, which says that given $n+1$ points on a polynomial, we can efficiently recover any $n$-degree polynomial.
We are even given $48$ points for a $24$-degree polynomial, so it should be easy, right?

The twist is that the program uses `int(np.polyval(poly, x) % p)` to evaluate the polynomial. However, by default, NumPy can only handle up to 64-bit integers. The code will
therefore overflow upon evaluating such a large polynomial, resulting in something like $f(x) \bmod 2^{64} \bmod p$ being computed instead (this is *slightly* inaccurate
due to integer truncation, but more on that later). This is why the `sanity_check()` passes (which uses a lesser degree polynomial).

All that being said, the normal algorithm for polynomial interpolation will not work here because the $y$ values we get are completely different than what they are supposed
to be.

## Solution

Let's present the problem more concretely. We are given $(x_i,y_i)$ for $i=0 \dotsc 47$, and wish to solve for all $24$ coefficients $c_i$ in the following $48$ equations:

$$
\begin{matrix}
c_0 + c_1 x_0 + c_2 x_0^2 + \dotsc + c_{21} x_0^{21} + c_{22} x_0^{22} + c_{23} x_0^{23} = y_0 \bmod 2^{64} \bmod 65537 \\
c_0 + c_1 x_1 + c_2 x_1^2 + \dotsc + c_{21} x_1^{21} + c_{22} x_1^{22} + c_{23} x_1^{23} = y_1 \bmod 2^{64} \bmod 65537 \\
c_0 + c_1 x_2 + c_2 x_2^2 + \dotsc + c_{21} x_2^{21} + c_{22} x_2^{22} + c_{23} x_2^{23} = y_2 \bmod 2^{64} \bmod 65537 \\
\vdots \\
c_0 + c_1 x_{47} + c_2 x_{47}^2 + \dotsc + c_{21} x_{47}^{21} + c_{22} x_{47}^{22} + c_{23} x_{47}^{23} = y_{47} \bmod 2^{64} \bmod 65537
\end{matrix}
$$

Notice that (ignoring the mod) this is a linear system of diophantine equations, meaning we can solve this using [LLL](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm).
One problem as mentioned earlier is that `np.polyval()` doesn't actually cause the result to be $(\bmod 2^{64})$, as values above $2^{63}-1$ overflow as per two's complement.
This causes the result to be off-by-one from $f(x) \bmod 2^{64} \bmod p$ around half of the time.

However, this "problem" conveniently does not actually pose a problem, because LLL only looks for small basis so $\pm 1$ off is not a big deal.

The other problem is that the equation uses two mods, which LLL cannot directly handle. We can remove a mod by replacing $a=b \pmod{p}$ with $a-kp=b$ and introducing a
new unknown, $k$, for each equation. However, this means that we will need another $2n$ unknowns.

At some point `@nneonneo` realized that because $2^{64} \bmod 65537=1$, the expression $x(2^{64}-1) \bmod (65537*2^{64}) / 2^{64}$ is approximately equal to
$x \bmod 2^{64} \bmod 65537$, with an error of $\sim 0.5$. Using this observation, we can cut down the number of unknowns from $2n$ to $n$. This should make the
solution a bit faster and easier to find.

Our system of equations now looks something like this, where $P=65537 \cdot 2^{64}$ and $Q=2^{64}-1$:

$$
\begin{matrix}
c_0 Q + c_1 x_0 Q + c_2 x_0^2 Q + \dotsc + c_{23} x_0^{23} Q + c_{22} x_0^{22} Q + c_{21} x_0^{21} Q + P k_0 - 2^{64} y_0 = 0 \\
c_0 Q + c_1 x_1 Q + c_2 x_1^2 Q + \dotsc + c_{23} x_1^{23} Q + c_{22} x_1^{22} Q + c_{21} x_1^{21} Q + P k_1 - 2^{64} y_1 = 0 \\
c_0 Q + c_1 x_2 Q + c_2 x_2^2 Q + \dotsc + c_{21} x_2^{21} Q + c_{22} x_2^{22} Q + c_{23} x_2^{23} Q + P k_2 - 2^{64} y_2 = 0 \\
\vdots \\
c_0 Q + c_1 x_{47} Q + c_2 x_{47}^2 Q + c_{21} x_{47}^{21} Q + c_{22} x_{47}^{22} Q + c_{23} x_{47}^{23} Q + P k_{47} - 2^{64} y_{47} = 0
\end{matrix}
$$

Or in LLL-matrix form,

$$
\begin{bmatrix}
\begin{array}{ccccc|ccccc|ccccc|c}
Q           & Q           & Q           & \dots  & Q              & 1      & 0      & 0      & \dots  & 0      & 0      & 0      &0       & \dots  & 0      & 0      \\
Q x_0       & Q x_1       & Q x_2       & \dots  & Q x_{47}       & 0      & 1      & 0      & \dots  & 0      & 0      & 0      & 0      & \dots  & 0      & 0      \\
Q x_0^2     & Q x_1^2     & Q x_2^2     & \dots  & Q x_{47}^2     & 0      & 0      & 1      & \dots  & 0      & 0      & 0      & 0      & \dots  & 0      & 0      \\
\vdots      & \vdots      & \vdots      & \ddots & \vdots         & \vdots & \vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots & \ddots & \vdots & \vdots \\
Q x_0^{23}  & Q x_1^{23}  & Q x_2^{23}  & \dots  & Q x_{47}^{23}  & 0      & 0      & 0      & \dots  & 1      & 0      & 0      & 0      & \dots  & 0      & 0      \\
\hline
P           & 0           & 0           & \dots  & 0              & 0      & 0      & 0      & \dots  & 0      & 1      & 0      & 0      & \dots  & 0      & 0      \\
0           & P           & 0           & \dots  & 0              & 0      & 0      & 0      & \dots  & 0      & 0      & 1      & 0      & \dots  & 0      & 0      \\
0           & 0           & P           & \dots  & 0              & 0      & 0      & 0      & \dots  & 0      & 0      & 0      & 1      & \dots  & 0      & 0      \\
\vdots      & \vdots      & \vdots      & \ddots & \vdots         & \vdots & \vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots & \ddots & \vdots & \vdots \\
0           & 0           & 0           & \dots  & P              & 0      & 0      & 0      & \dots  & 0      & 0      & 0      & 0      & \dots  & 1      & 0      \\
\hline
-y_0 2^{64} & -y_1 2^{64} & -y_2 2^{64} & \dots  & -y_{47} 2^{64} & 0      & 0      & 0      & \dots  & 0      & 0      & 0      & 0      & \dots  & 0      & 1      \\
\end{array}
\end{bmatrix}
$$

with the rows associated to the values $(c_0,c_1,c_2,\dotsc,c_{23},k_0,k_1,k_2,k_{47},\dotsc,1)$.

The first $48$ columns represent the $48$ polynomial equations. The rest of the columns are there to extract the rest of the unknowns (columns $49-72$
correspond to $c_i$). In practice, we also need to apply a *weight* to certain columns because their product is more important to minimize than others.
For example, columns $1-48$ must be within $[0,1]$, while columns $49-72$ can be within $[0,65537)$. Whichever columns have a wider range should accept a proportionally
larger weight.

Once we have the coefficients, we can easily reconstruct the key and crack the flag. My full solve is inside `solve.py`.
