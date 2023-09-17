# optinimize

The program computes `flag[i] = magic[i] ^ (Q(x) & 0xFF)` for larger and larger values of `x`.

We can manually reverse/decompile `Q`, which gives us this:

```
def Q(n):
  x = 0
  y = 0
  while x < n:
    y += 1
    if P(y) % y == 0:
      x += 1
  return y

def P(n): # Perrin sequence
  if n == 0:
    return 3
  if n == 1:
    return 0
  if n == 2:
    return 2
  x,y,z = 3,0,2
  for _ in range(n-2):
    x,y,z = y,z,x+y
  return z
```

Note that `P(y) % y == 0` iff `y` is either prime or a [Perrin pseudoprime](https://en.wikipedia.org/wiki/Perrin_number#Perrin_pseudoprimes).

Then `Q(n)` computes the `n`th prime+Perrin pseudoprime.

We can grab a list of Perrin pseudoprimes from [OEIS](https://oeis.org/A013998), then merge it with list of primes.

Solve script in [solve.py](`solve.py`).
