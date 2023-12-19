# Solve a proof-of-work challenge fast.
# This is meant to be copy-pasted and edited as appropriate
# (specifically, the lines after '# changeme' should be edited
#  to reflect your actual PoW: prefix/postfix, hash function, and success condition).
import string
import sys

def _solve_challenge_worker(arg):
    from hashlib import sha256
    from itertools import product

    i, s1, x, target, n, charset = arg
    print("proof of work ... %d" % (i*(len(charset)**n)), file=sys.stderr)
    for s2 in product(charset, repeat=n):
        s = bytearray(s1 + s2)

        news = s + x
        if sha256(news).hexdigest() == target:
            return s

def solve_challenge(x, target):
    ''' Solve a proof-of-work challenge with multiprocessing.

    x: known suffix
    target: known target hash
    '''
    from itertools import product
    from multiprocessing import Pool

    n = 4
    charset = (string.ascii_letters + string.digits).encode()
    n1 = 0
    while len(charset) ** n1 < 100000:
        n1 += 1
    if n1 > n:
        n1 = n // 2 + 1

    gen = ((i, s, x, target, n1, charset) for i, s in enumerate(product(charset, repeat=n-n1)))
    p = Pool()
    for res in p.imap_unordered(_solve_challenge_worker, gen):
        if res:
            p.terminate()
            return res

if __name__ == "__main__":
    import sys

    print(solve_challenge(sys.argv[1].encode(), sys.argv[2]).decode())
