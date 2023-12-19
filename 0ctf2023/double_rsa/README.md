## Double RSA - 4-Part Crypto Problem - Writeup by Robert Xiao (@nneonneo)

Double RSA was a series of four crypto challenges (Double RSA 0, Double RSA 1, Double RSA 2, Double RSA 3). We solved the first two of these challenges.

### Double RSA 0

28 solves, worth 144 points. Description:

> A baby RSA challenge.
> 
> Attachment
> 
> CN: nc chall.ctf.0ops.sjtu.cn 32226
> 
> EU: nc eu.chall.ctf.0ops.sjtu.cn 32226

We're given a Python program that implements the challenge.

Some of the challenge involves a "double RSA" structure in which a message is sequentially encrypted using two RSA keys (Alice and Bob). Most of the encryption operations are "noisy": they are performed by using an exponent that is XORed with the pseudorandom output of a linear congruential generator (LCG).

Alice and Bob's keys consist of the 512-bit primes $p_a, q_a, p_b, q_b$, 1024-bit public moduli $n_a = p_a q_a, n_b = p_b q_b$, random 329-bit public exponents $e_a, e_b$ and private exponents $d_a, d_b$. We're able to choose $p_b$ and $q_b$, but all other parameters are randomly initialized. To perform a noisy encryption of $m$, we first update $e \leftarrow e \oplus s_k \bmod 2^{329}$, then compute $m^{e \oplus s_{k+1}} \bmod n$ where $s_k$, $s_{k+1}$ are the next two outputs of the LCG and $\oplus$ is binary XOR.

The challenge consists of the following interaction sequence:

1. We provide the two 512-bit primes $p_b$, $q_b$ for Bob.
2. The LCG is initialized with a random prime modulus $p$ of 1024 bits, six random coefficients $a$, one random addend $b$, and a six-term random state $s$.
    - Outputs are $s_0, s_1, s_2$, ... where $s_0$ through $s_5$ are the initial state, and for $n \ge 6$: $$s_n = \left(\sum_{i=0}^{5} s_{n - 6 + i} a_i\right) + b \bmod p$$
3. A random 1024-bit RSA key $p_a,q_a, n_a$, random 329-bit public exponent $e_a$, and corresponding private exponent $d_a$ are generated for Alice.
4. A random 329-bit public exponent $e_b$ and corresponding private exponent are generated for "Bob".
5. A random 64-bit "secret" $S$ is encrypted with Alice's public key to make $S_a$.
6. We're given Alice's $e_a, n_a$, and the LCG's $p, a, b, s$ parameters.
7. We can send a number of plaintext messages, which will be noisily encrypted by Alice, then noisily encrypted by Bob and sent to us.
8. The encrypted secret $S_a$ is noisily encrypted by Bob, and we receive the resulting ciphertext $S_{ab}$.
9. Bob is reinitialized with a new $e_b, d_b$. The LCG is reinitialized with new random $p, a, b, s$ parameters, and we are given the new LCG parameters.
10. We can send a number of unique ciphertexts, which will be decrypted by Alice, then noisely encrypted by Bob and sent to us.
11. Finally, we must guess the secret $S$, and get a flag if we are correct.

We can send a total of 7 messages combined across steps 7 and 10.

It's quite a convoluted protocol! Roughly speaking, we can split it into two phases: in the first phase, we can choose the plaintext for Alice to noisily encrypt, and in the second phase, we can choose the ciphertext for Alice to decrypt. In each phase, the output will be noisily encrypted by Bob.

In Double RSA 0 (this challenge), we are given all of the LCG parameters, but are not provided with Bob's $e_b$ for the two phases. The main task for us is to recover the exponents used for Bob's noisy encryptions, allowing us to decrypt all of the responses.

We can choose Bob's modulus so that solving the discrete log problem mod $n_b$ is easy. Specifically, we will choose both $p_b$ and $q_b$ such that $p_b - 1$, $q_b - 1$ are smooth, allowing us to compute discrete logarithms modulo each prime easily.

We will have to contend with a few mathematical issues, however. The first issue is that, because both $p-1$ and $q-1$ must be even, exponents are unique only mod $(p-1)(q-1)/2$, assuming there are no other shared factors (which we can ensure). However, the LCG output might exceed this value, so in order to make the XOR calculation correct, we may have to add a multiple of $(p-1)(q-1)/2$ to the computed exponent. To make things simpler, what we'll actually do is resolve exponents mod $(p-1)/2$, $(q-1)/2$, combine them via the Chinese Remainder Theorem (CRT) mod $(p-1)(q-1)/4$, then add an appropriate multiple of $(p-1)(q-1)/4$ to obtain the full exponent.

Second, the random noisy exponent might be even, which means that no unique decryption exponent exists (since 2 is not coprime to $\phi$). We could just try again repeatedly, but this isn't ideal; instead, what we will do is try all of the square roots of the ciphertext (by combining square roots mod $p, q$).

In the attached scripts, [`gen_smooth.py`](gen_smooth.py) generates the smooth RSA parameters which are saved in [`params.py`](params.py). [`fast_chalsolve.py`](fast_chalsolve.py) implements a multiprocessed PoW solver. [`solve0.py`](solve0.py) implements the solver for Double RSA 0; it uses various math utilities from [nneonneo/pwn-stuff](https://github.com/nneonneo/pwn-stuff/blob/master/math) and also depends on `task.py` (renamed to `drsa0.py`).

When run against the remote server, we get our flag: `flag{All_Crypto_challenges_in_0CTF/TCTF2023_are_solvable_on_laptop_good_luck_and_have_fun}`

### Double RSA 1

10 solves, worth 275 points. Description:

> An easy RSA challenge.
> 
> Attachment
> 
> CN: nc chall.ctf.0ops.sjtu.cn 32225
> 
> EU: nc eu.chall.ctf.0ops.sjtu.cn 32225

The challenge is largely similar to Double RSA 0, with the following changes:

- LCG $p$ is now 512 bits instead of 1024 bits
- We don't get Alice's $e_a$, $n_a$, nor do we get the LCG's $s$ in the first phase.
- We don't get any LCG parameters at all in the second phase.
- We can now send 70 plaintext/ciphertext messages (up from 7), combined across both phases.

#### Phase 1

In phase 1, we can repeatedly encrypt -1 to gain useful information: the first noisy encryption from Alice will produce either 1 (if the noisy exponent is even) or $n_a - 1$ (if the noisy exponent is odd); in the former case, Bob's noisy encryption will also produce 1, which we can discard. After several encryptions, we will obtain $c_k = (n_a - 1) ^ {e_k} \bmod n_b$ for several noisy exponents $e_k$. These exponents are related: each exponent is $e_k = e'_k \oplus (s_k \bmod p)$, where $e'_k$ is the current Bob exponent (mod $2^{329}$) and $s_k$ is an LCG output (up to $p$, which is 512 bits). Note that Bob's exponent will be updated before every noisy encryption.

We don't know $n_a - 1$, but we can compute discrete logarithms of $c_k$ modulo some "generator" base $g$, such that $n_a - 1 \equiv g^x \bmod n_b$. Note that since the multiplicative group $\mathbb{Z}_{n_b}^*$ is not a cyclic group, there is no single base that works for all $n_a - 1$. However, we can choose a suitable $g$ based on the parity of exponents from discrete log on $p$, $q$.

By taking the discrete log of each $c_k$ to the base $g$ (such that $c_k \equiv g^{x_k} \bmod n_b$), we will end up with a series of equations $x_k = x e_k \bmod \phi_{n_b}$, with $x_k$ known and all other variables unknown. Observe that $e_k = s_k \oplus e'_k = s_k + e''_k$ for some $|e''_k| < 2^{329}$. We can also set $y = x^{-1}$, giving us the linear equations $yx_k = s_k + e''_k \bmod \phi _{n_b}$.

By writing $s_k$ in terms of the initial $s_0, ..., s_5$ and known LCG parameters $a, b, p$, we get a linear system of modular equations where all of the unknowns are bounded, which can be solved with the general bounded-variable linear equation solver [solvelinmod](https://github.com/nneonneo/pwn-stuff/blob/master/math/solvelinmod.py) to simultaneously recover $s$ and $y$. The solver uses lattice reduction under the hood, and generalizes to problems such as the Hidden Number Problem and other linear modular equation problems.

Thus, after phase 1, we can successfully recover the LCG state $s$ and Alice's modulus $n_a$, allowing us to decrypt the $S_{ab}$ to obtain $S_a$.

#### Phase 2

Bob's $e_b$ is re-randomized, as is the LCG state. We do not receive any of the new LCG state at all. We're also not allowed to decrypt the same ciphertext twice.

In this phase, what we'll do is to decrypt $S_a^i$ for $i = 1, 2, ..., 12$. Once decrypted by Alice, these will become $S^i$, and because $S$ is only 64 bits long, $S^i$ will be at most 768 bits long - less than $n_a$. Thus, the decrypted values will also be equal to $S^i \bmod n_b$. We can again use a discrete log trick to recover $S$.

Let $S \equiv g^x \bmod n_b$ and $y \equiv x^{-1} \bmod \phi_{n_b}$. Let each obtained ciphertext be $c_i \equiv (S^i)^{e_i} \bmod n_b$, where $e_i < p < 2^{512}$, and take discrete logs such that $c_i \equiv g^{x_i} \bmod \phi_{n_b}$. Then we have $x_i \equiv i e_i x \bmod \phi_{n_b}$ and thus $x_i y \equiv i e_i \bmod \phi_{n_b}$. Since the $e_i$ are bounded, this is again an instance of a Hidden Number Problem which can be solved with lattice reduction (solvelinmod) to recover $y$ and thus $S$.

The final script is in [`solve1.py`](solve1.py), and requires Sage to run. After a few tries, it will spit out the flag: `flag{DLP_and_HNP_s0_345y}`
