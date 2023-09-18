## RSA 4.0 - Crypto Problem - Writeup by Robert Xiao (@nneonneo)

RSA 4.0 was a crypto challenge solved by 33 teams, worth 164 points.

Description:

> A new era has come, RSA 4.0!
> 
> dist.tar.gz fac97cdaf64588a1e3189a5f20c09291b99026cb

This problem implements an RSA-like cryptosystem over the quaternions mod $n$, i.e. the numbers $a + bi + cj + dk$ where $a, b, c, d \in \mathbb{Z}_n$ and $i, j, k$ are square roots of -1 such that $i^2 = j^2 = k^2 = -1$ and $ij=k$, $jk=i$, $ki=j$, $ji=-k$, $kj=-i$, $ik=-j$. $n$ is the product of two 1024-bit primes $p$ and $q$, the exponent is $e = 65537$, and $m \in \mathbb{Z}_n$ is the message. The encryption process computes the quaternion message $M = m + (3m + p + 337q)i + (3m + 13p + 37q)j + (7m + 133p + 7q)k$, then outputs $n$, $e$ and $C = M^e$.

## Solution

Quaternion exponentiation actually occurs within a sub-algebra of the quaternions: the powers of $a + bi + cj + dk$ are of the form $e + f(ai + cj + dk)$, where $a, b, c, d, e, f \in \mathbb{Z}_n$, a fact which can be readily verified by induction. Thus, since our initial $b, c, d$ have a linear relationship, we can solve for $m$, $p$ and/or $q$ by solving a system of linear equations mod $n$.

This is quite straightforward to do, and there are many possible approaches; I used [`solvelinmod`](https://github.com/nneonneo/pwn-stuff/blob/master/math/solvelinmod.py), and immediately obtained $p$, which thus yields $q$. The order of the quaternion algebra is $q^4$, so I inferred that the multiplicative order divides $p^4 - 1$; thus, we can obtain the decryption exponent $d$ via $ed = 1 \bmod (p^4 - 1) (q^4 - 1)$. Computing $C^d$ yields the message: `SECCON{pr0m153_m3!d0_n07_3ncryp7_p_0r_q_3v3n_w17h_r54_4.0}`.

Full solution script in [`solve.sage`](solve.sage).
