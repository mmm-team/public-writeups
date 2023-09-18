from multiprocessing import Pool

from Crypto.Util.number import isPrime
from pwn import *

N = 14

con = remote("chal-share.chal.hitconctf.com", int(11111))

cur = int(17)
prod = int(1)
target = int(2 ** 280)
primes = []

while prod <= target:
    if isPrime(cur):
        primes.append(cur)
        prod *= cur
    cur += 2

print(f"primes = {primes}")


def read_share(con):
    con.recvuntil(b"shares = [")
    shares = list(map(int, con.recvline()[:-2].split(b", ")))
    return shares


def get_share(con, p):
    con.send(b"%d\n%d\n" % (p, N))
    return read_share(con)


def get_batch(con, first_share, p, batch_size):
    batch = []

    payload = b"%d\n%d\n" % (p, N)
    payload *= batch_size

    con.send(payload)

    for _ in range(batch_size):
        new_share = [(0, 0)]
        for i, share in enumerate(read_share(con)):
            new_share.append((i + 1, (p + share - first_share[i]) % p))
        batch.append(new_share)

    return batch


def solve_one(arg):
    p, shares = arg

    F.<y> = GF(p)
    R.<x> = PolynomialRing(F)

    f = R.lagrange_polynomial(shares)

    coeff = list(f.coefficients(sparse=False))
    while len(coeff) < N:
        coeff.append(0)

    return coeff


with Pool() as pool:
    crt = []
    for p in primes:
        observed = set()

        first_share = get_share(con, p)

        print(f"Start {p}")
        while True:
            batch = get_batch(con, first_share, p, p * 4)
            print("  Got batch")
            for coeff in pool.map(solve_one, map(lambda shares: (p, shares), batch)):
                assert coeff[0] == 0
                observed.add(coeff[-1])

            print("  Processed a batch")
            if len(observed) == p - 1:
                break

        all_sum = sum(range(p - 1))
        missing = all_sum - sum(observed)
        highest_coeff = p - missing

        shares = []
        for i in range(N - 1):
            num = (first_share[i] - highest_coeff * pow(i + 1, N - 1, p)) % p
            shares.append((i + 1, num))

        rem = int(solve_one((p, shares))[0])

        print(p, rem)
        crt.append((p, rem))


# Recover secret by CRT
secret = int(0)

for n_i, a_i in crt:
    pp = int(prod / n_i)
    secret += int(a_i * inverse_mod(pp, n_i) * pp)

secret = secret % int(prod)

print(f"secret = {secret}")
print(secret.bit_length())

con.sendlineafter(b"p = ", b"123")
con.sendlineafter(b"n = ", b"123")
con.sendlineafter(b"secret = ", b"%d" % secret)

print(con.recvall().decode())
