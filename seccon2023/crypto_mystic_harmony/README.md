## mystic_harmony - Crypto Problem - Writeup by Robert Xiao (@nneonneo)

mystic_harmony was a crypto challenge solved by 10 teams, worth 278 points.

Description:

> The spirit world and the human world are two sides of the same coin. A misalignment in the two worlds would be apocalypse. You have been assigned by a witch to investigate the misalignment of the worlds. Report its location and quantity to the witch and bring the world into harmony!
> 
> nc mystic-harmony.seccon.games 8080
> 
> problem.sage 8eb07c2c37071c9f7515cbfee3c8a737ace703cf

We're given a server that generates a random problem instance which consists of a 32x32 "map" and an encrypted "treasure box". The generator works over the field K = GF($2^8$) with generator $\alpha$:

- Generate $H$, a random bivariate polynomial over $K$ of degree 63+63 (terms only go up to $x^{63} y^{63}$).
- Generate $S = H \bmod G$, where $G = \prod_{i=1}^{32} (x - \alpha^i) + \prod_{j=1}^{32} (y - \alpha^j)$.
- Generate $W = H + S$ (note that this is GF($2^8$), so this is also equal to $H - S$).
- Generate $D$, the sum of 16 random terms with random coefficients (i.e. $\sum_{k,l \in T} x^k y^l \alpha^{r_{kl}}$ for a random set of index pairs $T$ where $|T| = 16$). The random process ensures that all 16 values of $k$ are distinct (but $l$ may not be).
- The terms of $D$ are used to calculate an AES encryption key.
- Finally, produce the "map" by evaluating $C = H + S + D$ at $C(\alpha^i, \alpha^j)$ for $1 \le i, j \le 32$.

## Solution

This setup is similar to an error correction code, specifically a Reed-Solomon code. In a typical Reed-Solomon code, we encode the message to transmit as the coefficients of a polynomial $p$, and multiply it by a generator polynomial $g(x) = \prod_{i=1}^{n-k} (x - \alpha^i)$ to get the transmitted polynomial $s$. During transit, $s$ may be corrupted by some noise $e$ to yield the received polynomial $r = s + e$. If the number of non-zero terms in $e$ is small, the Reed-Solomon decoding procedure can be used to recover the original $s$. The number of non-zero terms must be at most $\frac{n - k}{2}$ terms, if the locations (exponents of $x$) are unknown.

The decoding process starts by evaluating the "syndrome" $S_j = r(\alpha_j)$ for $j = 1, 2, ... n-k$. Since $g$ has roots at all of these points, the correct message will evaluate to all zeros, and so $S_j = e(\alpha_j)$.

Analogously, in our setup, we are given $C$ evaluated at points $(\alpha^i, \alpha^j)$ for $1 \le i, j \le 32$, and $H + S$ evaluates to zero at all these points by construction of $G$ ($H + S = H - H \bmod G$). Thus, effectively, the "map" values are the syndrome values of $D(\alpha^i, \alpha^j) = \sum_{k,l \in T} \alpha^{ik} \alpha^{jl} \alpha^{r_{kl}}$.

By fixing a particular value of $j$, we observe that this resolves to $D_{y=\alpha^j} (\alpha^i) = \sum_{k,l \in T} \alpha^{ik} \alpha^{r_{kl} + jl}$, which is precisely the same as a normal Reed-Solomon syndrome calculation. So, for any row of the "witch map", we can apply a syndrome decoder to obtain the $x$-locations $k$, then solve a linear equation to recover $\alpha^{r_{kl} + jl}$. From there, a comparison with the outputs from a second value of $j$ will yield the individual $r_{kl}$ and $l$ values.

I implemented a Petersen-Gorenstein-Zierler (PGZ) decoder, which works great since we know there are exactly 16 errors (16 distinct values for $x$). Notably, my attack uses only two rows from the "map" to recover the entirety of $D$.

