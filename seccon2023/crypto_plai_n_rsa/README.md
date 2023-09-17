# plai_n_rsa

We're given a typical RSA encryption challenge, with three differences:
1. $d$ is given
1. $n$ isn't given
1. $p+q$ is given

We know that $de \equiv 1\ (\mathrm{mod}\ \phi)$, meaning $\phi \cdot x + 1 = de$ for some integer $x$. Thus,

$$
\begin{align*}
(de-1) / x &= \phi \\
           &= (p-1)(q-1) \\
           &= pq - p - q + 1 \\
           &= n - (p+q) + 1
\end{align*}
$$

and as we're given $d$ and $p+q$, we can solve for $n$ and the plaintext. Because $d < \phi$, we know $x$ has an upper bound of $e$, so we can simply check every possible value of $1 \leq x \lt e$ and see if the resulting plaintext looks like an ASCII flag.

This takes around 3 seconds, and for $x = 53137$ we find the flag: `SECCON{thank_you_for_finding_my_n!!!_GOOD_LUCK_IN_SECCON_CTF}`.

The solve script is [solve.py](solve.py).
