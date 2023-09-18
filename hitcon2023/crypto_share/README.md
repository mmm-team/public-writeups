# Crypto - Share

## Problem

```
I hope I actually implemented Shamir Secret Sharing correctly this year. I am pretty sure you won't be able to guess my secret even when I give you all but one share.

share-dist-54ed28db36cd98dbc63f52eafc91bb7d6e4598b5.tar.gz
nc chal-share.chal.hitconctf.com 11111

Author: maple3142
47 Teams solved.
```

## Overview

This challenge's goal is to find a server's 32 bytes secret by querying the server. The secret is hidden with [Shamir's secret sharing scheme](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing). We can select `p`, the prime that defines the field, and `n`, the degree of the polynomial, for a query. `n` and `p` should satisfy the equation `int(13.37) < n < p`. For each query, the server returns shares evaluated on `x = 1..n-1`, which is missing one share to recover the secret. There's no limit on the number of queries, but the whole process should terminate under 30 seconds.

The bug is in the coefficient generation: it uses `getRandomRange(0, self.p - 1)` which returns value in `[0, p-2]` range. In other words, `p-1` is never used as a coefficient in any degree.

We observed that we can deterministically find the polynomial difference of two share sets by subtracting them and appending `f(x) = 0`. With repeated queries, we can collect all `p-1` possibilities for the highest coefficients, which allows us to determine the highest coefficient of all shares. Then, a new share of `n-1` degree can then be constructed with `new_share[x] = (old_share[x] - highest_coeff * pow(x, N - 1)) % p`. Since the new share has `n-1` degree and we have `n-1` evaluation result, we can now fully recover the secret polynomial with Lagrange interpolation and find `secret % p`. Repeating these steps for different prime values and applying the chinese remainder theorem gives us the full secret that can be exchanged with the real flag.

`hitcon{even_off_by_one_is_leaky_in_SSS}`

See [solver.sage](solver.sage) for the full exploit.
