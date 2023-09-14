## Collision - Crypto Problem - Writeup by Robert Xiao (@nneonneo)

Collision was a crypto challenge solved by 11 teams, worth 327 points.

Description:

> All you need is to find a hash collision for this, pretty simple right?
> 
> collision-dist-d5306a8324a2a2678c3fb7af0cde1e72d0775d57.tar.gz
> 
> `nc chal-collision.chal.hitconctf.com 33333`

We're provided with a package containing a Dockerfile that runs the following script 8 times, with random values for `PYTHONHASHSEED` and an overall timeout of 240 seconds:

```python
#!/usr/bin/env python3
import os
import signal

if __name__ == "__main__":
    salt = os.urandom(8)
    print("salt:", salt.hex())
    while True:
        m1 = bytes.fromhex(input("m1: "))
        m2 = bytes.fromhex(input("m2: "))
        if m1 == m2:
            continue
        h1 = hash(salt + m1)
        h2 = hash(salt + m2)
        if h1 == h2:
            exit(87)
        else:
            print(f"{h1} != {h2}")
```

In essence, we will get a flag if we can find eight collisions for the Python 3.11 `hash` function within four minutes.

## Step 1: Recovering PYTHONHASHSEED

Each run is initialized with a random 32-bit `PYTHONHASHSEED`. This seed is used to initialize the 128-bit key used by the hash implementation, as follows (from `Python/bootstrap_hash.c`):

```c
static void
lcg_urandom(unsigned int x0, unsigned char *buffer, size_t size)
{
    size_t index;
    unsigned int x;

    x = x0;
    for (index=0; index < size; index++) {
        x *= 214013;
        x += 2531011;
        /* modulo 2 ^ (8 * sizeof(int)) */
        buffer[index] = (x >> 16) & 0xff;
    }
}

[...]
lcg_urandom(config->hash_seed, secret, secret_size);
```

This is a rather poor random number generator. In particular, it only ever uses the third-least-significant byte of `x`, ignoring the top byte entirely. This means that we can treat all operations as being `mod 0xffffff`, i.e. the seed only has 24 bits of effective entropy, since the high byte does not affect the resulting secret at all.

Thus, recovering the `PYTHONHASHSEED` is simply a matter of observing any output, then trying all 16,777,216 possible seeds to find a seed that is equivalent to the original. [`findseed.cpp`](findseed.cpp) implements this attack.

## Step 2: Finding a collision

The hash function used for byte strings is SipHash 1-3, which uses a 128-bit key and produces a 64-bit hash. SipHash is actually a fairly decent ARX hash function; its only major (cryptographic) weakness is the short output, which is not a problem for its use in hash tables.

Thus, the most effective way to find a collision is straightforward bruteforce. Due to the birthday paradox, we expect to generate about 2^32 hashes before finding a collision.

There are many ways to avoid storing every hash to detect a collision. For example, we can use the idea of a rainbow table: generate a "chain" of hashes, where an initial value is hashed, and the hash is converted into a second input; this chain is continued for some number of iterations, but only the final hash in the chain is stored (with a pointer back to the initial input). To find a collision, we can keep generating chains until we find a hash that appears in the table, then start hashing from the start of each chain to find the point at which the chains initially collide.

[`brute.cpp`](brute.cpp) implements this attack, with [`solver.py`](solver.py) as the driver for the entire operation. We ran it on a 96-core server, which solved all eight instances in less than two minutes, and produced a flag: `hitcon{PYTHONHASHSEED_has_less_entropy_than_it_should_be}`
