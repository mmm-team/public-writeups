## Increasing Entropoid - Crypto Problem - Writeup by Robert Xiao (@nneonneo)

Increasing Entropoid was a crypto challenge solved by 7 teams, worth 322 points.

Description:

> I have reimplemented entropoid based Diffie-Hellman key exchange protocol.
> 
> dist.tar.gz 425d196792e1aaf3b80ba71e8f5f2b69526a5363

We're provided with an implementation of the Diffie-Hellman-like key exchange protocol from ["Entropoid Based Cryptography"](https://eprint.iacr.org/2021/469.pdf). This protocol is based on mathematical operations within an "entropoid" quasigroup $G$, which has a peculiar property: the group operation $*$ is non-commutative and non-associative, yet the exponentation operation *is* commutative when exponentiating to "generalized" exponents, *i.e.* exponents which encode the order in which operations are performed. That is, for generalized exponents $A$ and $B$ and an entropoid element $g$, $(g^A)^B = (g^B)^A$. This admits a Diffie-Hellman-like key exchange construction in which the exponents are the private keys and the $g^A$, $g^B$ are the public keys.

The provided script is a faithful implementation of the protocol. It represents entropoid elements as a pair of numbers modulo a specified prime $p$, and entropoid exponents as a tuple `(a, pattern, base)` where `a` specifies the number of multiplications to perform, and `pattern` and `base` control the order in which the multiplications happen. The script starts by performing 256 "debug" key exchanges using the small prime $p_d$ = `0xffff_ffff_ffff_fa43`, printing out Alice and Bob's public keys each time, then does a final key exchange with a 2048-bit $p$, using the final shared key to encrypt the flag.

## Solution

The entropoid cryptosystem has been successfully attacked in [this paper](https://eprint.iacr.org/2021/583.pdf). In the attack, the author defines an automorphism $\sigma$ and group operation $\cdot$ such that $x * y = \sigma(x) \cdot y$ and $\cdot$ is an abelian operation. Furthermore, it turns out that it's possible to map entropoid elements to pairs of elements in the multiplicative group mod $p$ via an isomorphism $\iota$, thus reducing the complex entropoid exponentiation process to simple discrete-log mod $p$. For a given $g^A$, the attack produces a pair of integers $(i, j)$ which can be used as the private key and are functionally equivalent to $A$.

The attack paper even provides functional Sage code, which works pretty much out of the box. However, discrete log mod a 2048-bit prime is not feasible. We observe that all of the random entries in the generalized exponents are generated using Sage's `randrange`, which uses Python's non-cryptographic Mersenne Twister-based RNG. By experimenting with the discrete log operation on known entropoid exponents, we determine that the $a$ of the generalized exponent is always equal to the sum of $i$ and $j$ in the discrete log output.

We have a total of 256 "debug" rounds. Each round involves producing two private/public keypairs using $p_d$ and printing out the public keys. Thus, we can recover two private $a$s in each round, but not the random pattern. Since $p_d$ is near $2^{64}$, this gives us basically 512 64-bit outputs, which is more than the 624 32-bit outputs necessary to recover the full Mersenne Twister state.

The full attack proceeds in three steps. In [`step1.sage`](step1.sage), we recover the discrete log values. In [`step2.py`](step2.py) we use these values to recover the RNG state. In [`step3.py`](step3.py) we rerun the original script with the recovered RNG state to recover the shared key and decrypt our flag: `SECCON{The law of entropoid increase postulates the existence of irreversible processes in crypto: the bit numbers of a safe cryptosystem based on DELP can increase, but cannot decrease.}`.

