## Echo - Crypto

> A secure, cryptographically signed echo-as-a-service.
> 
> echo-dist-082b1d8dc00c8b5389807cf468255bdc3b6de7fc.tar.gz
> 
> `nc chal-echo.chal.hitconctf.com 22222`

The challenge implements RSA-based signature verification system. The server only generates the signature that command starts with `echo `.

If we can provide command and proper signature, we can execute command on a system shell.

Since the server signs our command with `shlex.quote` function, we can't do command injection to `echo` command.

Our final goal is generating the signature for command `./give me flag please`.

## Vulnerabilities

Below code is RSA signature implementation.

```python
class RSA:
    def __init__(self, size):
        self.p = getPrime(size // 2)
        self.q = getPrime(size // 2)
        self.n = self.p * self.q
        self.e = getPrime(size // 2)
        self.d = pow(self.e, -1, (self.p - 1) * (self.q - 1))

    def sign(self, msg: bytes) -> int:
        m = bytes_to_long(msg)
        return pow(m, self.d, self.n)

    def verify(self, msg: bytes, sig: int) -> bool:
        return self.sign(msg) == sig
```

Since the `sign` function does not hash the message, we can control arbitrary plaintext `m`. Further, we can provide `m` for arbitrarily that bigger than `n`.

## Leaking public modulus `n`

The challenge does not provide public modulus `n`. So our first step is leaking modulus.

Since we can provide arbitrary `m` starts with `echo `, we can get pair for multiple of the modulus and it leads to leaking modulus through gcd.

Below is finding proper command that starting with `echo ` and satisfies `quote` function constraints.

```python
def generate():
    while True:
        r = ''.join(random.choices(string.ascii_letters, k=2))
        prefix = b2l(b"echo '" + r.encode())
        factors_w_exp = factor(prefix)
        factors = []
        for p, e in factors_w_exp:
            for i in range(e):
                factors.append(p)
        random.shuffle(factors)

        base1 = prod(factors[:len(factors) // 2])
        base2 = prod(factors[len(factors) // 2:])
        assert base1 * base2 == prefix

        x = base1 * 256 ** 7 + 13
        y = base2 * 256 ** 7 + 3
        z = base1 * 256 ** 8 + 13
        v = base2 * 256 ** 8 + 3

        A = x * y
        B = z * v
        C = x * v
        D = y * z

        c = 0
        for x in [A, B, C, D]:
            if all([a < 128 for a in l2b(x)]) and msg.encode().decode() == msg:
                c += 1
        if c == 4:
            break

    print(l2b(A))
    print(l2b(B))
    print(l2b(C))
    print(l2b(D))

    return [A, B, C, D]
```

The message pairs `A, B, C, D` satisfies A * B == C * D. So we can get multiple of modulus `kn` via `E(A) * E(B) - E(C) * E(D)`.

## Forging the arbitrary command

Since we can provide arbitrary plaintext that bigger than modulus, we can construct the same message over Z(n).

It found that plaintext is 0 over Z(n) and it can be done via LLL.

```python
for k in range(100, 200):
    print(k)
    c = b2l(b"./give me flag please;" + b'\x00' * k)
    M = Matrix(ZZ, k+2, k+2)
    M[:k+1, :k+1] = Matrix.identity(k+1)
    for i in range(k):
        M[i, -1] = 256 ** (k - i - 1)
        M[-2, i] = -80
    M[-2, -2] = 1
    M[-2, -1] = c
    M[-1, -1] = -modulus
    # M = M.LLL()
    M = flatter(M)

    for row in M:
        if row[-1] == 0 and row[-2] == 1:
            try:
                print("Found")
                suffix = [row[i] + 80 for i in range(k)]
                if (not all([0 <= c < 128 for c in suffix])) or (0xa in suffix):
                    print("no..")
                    print(suffix)
                    continue
                print("Okay")
                suffix = bytes(suffix)
                print(suffix)
                assert b2l(b"./give me flag please;" + suffix) % modulus == 0
                r.sendlineafter("> ", "2")
                r.sendlineafter(": ", b"./give me flag please;" + suffix)
                r.sendlineafter(": ", b"0")
                r.interactive()
            except:
                pass
```
