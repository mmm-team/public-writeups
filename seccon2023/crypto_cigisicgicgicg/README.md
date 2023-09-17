## CIGISICGICGICG - Crypto Problem - Writeup by Robert Xiao (@nneonneo)

CIGISICGICGICG was a crypto challenge solved by 14 teams, worth 240 points.

Description:

> This CIG is composed of ICG, ICG and ICG!
> 
> dist.tar.gz 29bf714f78f38ae2f40cbf21d04571cde3d3a75c

We're given an implementation of a [compound inversive generator](https://en.wikipedia.org/wiki/Inversive_congruential_generator#Compound_inversive_generator) that is composed of three [inversive congruential generators](https://en.wikipedia.org/wiki/Inversive_congruential_generator). We're given the $a_i$, $b_i$ and $p_i$ parameters for each ICG, with each $p$ being 125 bits long. The generator produces a raw output mod $T = p_1 p_2 p_3$, around 375 bits long, which is then truncated to 256 bits.

The CIG is initialized randomly, used to encrypt a 68-byte flag using XOR, and then we're given 300 bytes of "leaked" output. Our task is to recover the state of the CIG to decrypt the flag.

## Solution

Each ICG generates the next output as $x_{i,n+1} = a_i x_{i,n}^{-1} + b_i \bmod p_i$. The outputs are then combined with a CRT-like construction using $x_{n+1} = \sum_{i} T_i x_{i,n+1} \bmod T$, where $T_i = T / p_i$. Notably, $x_{n+1} = T_i x_{i,n+1} \bmod p_i$.

We're given a total of 9 full blocks of output (plus another 12 bytes of partial output, which we'll ignore). Let $o_n$ represent the (known) outputs, with $q_n$ representing the (unknown) quotients of $x_n$ by $2^L$ ($L = 256$). Each $q_n$ is on the order of 117 bits long. Thus, for each block $n = 1, 2, ..., 9$ and generator $i = 1, 2, 3$, we can write the equations

$2^L q_n + o_n = x_{i,n} T_i \bmod p_i$

These aren't enough to solve the problem yet: we have about 4428 bits (9x117 + 27x125) of unknowns, but only about 3375 bits (27x125) of constraints (moduli).

To get additional equations, consider the product $x_{n} x_{n+1}$. Mod $p_i$, this expands to $T_i^2 (a_i + b_i x_{i,n})$. The left-hand side expands to $(2^L q_n + o_n)(2^L q_{n+1} + o_{n+1}) = 2^{2L} q_n q_{n+1} + 2^L (q_n o_{n+1} + q_{n+1} o_{n}) + o_{n} o_{n+1}$. Treating $q_n q_{n+1}$ as a new variable (on the order of 238 bits), this gives us 24 new equations, with 1872 bits (8x234) of new variables and 3000 bits (24x125) of constraints.

Summing up, we find that we now have 6300 bits of variables and 6375 bits of constraints, so this should be linearly solvable. I use [solvelinmod.py](https://github.com/nneonneo/pwn-stuff/blob/master/math/solvelinmod.py) for the job, which implements an LLL-based solver for systems of linear equations over arbitrary moduli.

After obtaining the $x_{i,n}$, we just need to run the ICGs in reverse to obtain the initial state, then decrypt the flag: `SECCON{ICG1c6iC6icgic6icgcIgIcg1C6ic6ICGICG1cGicG1C61CG1cG1c61cgIcg}`.

The full attack is implemented in [solve.py](solve.py).
