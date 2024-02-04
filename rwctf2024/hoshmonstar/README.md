## Hoshmonstar - Misc Problem - Writeup by Robert Xiao (@nneonneo)

This is a shellcoding challenge, in which we need to write a polyglot shellcode which simultaneously runs under RISC-V, AARCH64 and x86-64, and which calculates the HMAC-CRC64 of the code itself under a randomly chosen key.

The shellcode also needs to be golfed such that the size in bytes + the number of basic blocks executed across all three architectures is at most 283 (bytes + bbs).

### HMAC-CRC64

CRC64 is obviously not a cryptographically strong basis for implementing an HMAC construction. The problem uses the usual RFC-2104 formulation of the HMAC. The calculation we are being asked to perform is `HMAC-CRC64(key=key, msg=code + key)`, where `HMAC-CRC64(key, msg)` is defined as `CRC64((key ^ 0x5c5c...) || CRC64((key ^ 0x3636...) || msg))`.

The CRC64 computation is mathematically the reduction of the message polynomial modulo a fixed generator polynomial in GF(2^64). Let us work in the field `GF(2^64, modulus=0x42f0e1eba9ea3693)`, corresponding to the CRC64 parameters. We represent the polynomial $f(x)$ as the integer $f(2)$, that is, the integer whose bits are the coefficients of the polynomial.

Let `M = 0xffff_ffff_ffff_ffff` (that is, $\sum_{i=0}^{63} x^i$). Then, the CRC64 of an $n$-bit message $m$, represented as a degree-$n$ polynomial in GF(2), is $M x^n + m x^{64} + M$, modulo the generator polynomial.

We're asked to calculate the HMAC-CRC64 of the message $m || k$. Let the length of the message be $n$ bits, and let $p_o = \textrm{0x5c5c5c5c5c5c5c5c}, p_i = \textrm{0x3636363636363636}$. Then, we have

$\textrm{HMAC-CRC64}(k, m || k) = M x^{128} + ((k + p_o) x^{64} + (M x^{n+128} + ((k + p_i) x^{n+64} + m x^{64} + k) x^{64} + M)) x^{64} + M$

$= M x^{128} + (k + p_o) x^{128} + M x^{n+192} + (k + p_i) x^{n+192} + m x^{192} + k x^{128} + M x^{64} + M$

$= k x^{192 + n} + M x^{128} + M x^{192+n} + M x^{64} + M + p_o x^{128} + p_i x^{192+n} + m x^{192}$.

This is a fully linear function in $k$ (modulo the CRC polynomial). By manipulating the code, we can also arrange for the entire constant term to become zero (by editing bits in $m$ to make $m x^{192} = M x^{128} + M x^{192+n} + M x^{64} + M + p_o x^{128} + p_i x^{192+n}$), thereby reducing the HMAC-CRC64 calculation to a single multiply-and-reduce operation.

The naive way to do polynomial multiplication in GF(2^64) involves 64 shift-and-add operations, which would imply executing at least 64 basic blocks. Doing this for all three architectures would yield 192 basic block executions, leaving less than 100 bytes for the code.

Luckily, Unicorn supports the *pmull* instruction on AArch64, which implements polynomial multiplication in GF(2^64). We can use [Barrett reduction](https://en.wikipedia.org/wiki/Barrett_reduction) to replace the reduction operation with a multiplication by a constant, and thereby implement the HMAC-CRC64 with just three invocations of pmull and no looping. While RISCV and x86-64 have similar polynomial multiplication instructions (clmul and pclmulqdq, respectively), neither of these are supported under Unicorn.

We can unroll the inner loop to reduce the basic block count to 32 per architecture, at the cost of a few more instruction bytes. Thus, in the end, we will spend 64 or so basic blocks, leaving 200+ bytes for code.

In the end, here are the assembly programs used for all three architectures:

RISC-V:

```
  # assume a1 = 0
  # n.b. next three instructions are moved to the end of the polyglot stub
  ld x8, 16(a1)
  ld x9, 32(a1)
  mv x12, x1
.L4:
  andi  x11,x8,1
  mul x11, x11, x12
  xor x13, x13, x11
  sltz x11, x12
  slli  x12,x12,0x1
  srli  x8,x8,0x1
  mul x11, x11, x9
  xor x12, x12, x11
  andi  x11,x8,1
  mul x11, x11, x12
  xor x13, x13, x11
  sltz x11, x12
  slli  x12,x12,0x1
  srli  x8,x8,0x1
  mul x11, x11, x9
  xor x12, x12, x11
  bnez  x8, .L4
  mv x1, x13
```

x86-64:

```
mov    rcx, [rbp+16]
xchg   rax,rdi
L1:
  lea    r8,[rdi+rdi*1]
  mov    dl,cl
  and    edx,0x1
  imul   rdx,rdi
  xor    rax,rdx
  mov    r10,r8
  xor    r10,[rbp+32]
  test   rdi,rdi
  cmovns r10,r8
  mov    rdi,rax
  xor    rdi,r10
  lea    r11,[r10+r10*1]
  test   cl,0x2
  cmovne rax,rdi
  mov    rdi,r11
  xor    rdi,[rbp+32]
  test   r10,r10
  cmovns rdi,r11
  shr    rcx,0x2
  jne    L1
```

AArch64:

```
  mov v1.d[0], x0
  ldr q2, [x10, #16] // COEFF, MU
  pmull v3.1q, v1.1d, v2.1d   // [0] = R1, [1] = Q1
  pmull2 v5.1q, v3.2d, v2.2d  // [1] = Q3
  eor v6.16b, v5.16b, v3.16b  // [1] = Q1 ^ Q3
  ldr q7, [x10, #24] // POLY
  pmull2 v8.1q, v7.2d, v6.2d  // [0] = R2
  eor v1.8b, v8.8b, v3.8b     // [0] = R1 ^ R2
  mov x0, v1.d[0]
```

We use the polyglot sequence `42 75 55 54 09 00 00 14` at the start. The first four bytes contains an x86 jump (`75 55`), and is interpreted as a non-taking jump in AArch64, and some dummy loads on RISC-V. The second block of four bytes is an AArch64 jump, and a nop on RISC-V. After this, we can put regular RISC-V code. You can find our full merging script in [merge.py](merge.py), and the final payload in [code.bin](code.bin).

Putting all of this together results in a solution that *exactly* hits 283, and nets us a flag: `rwctf{nande_toxic_shellcoding_challenge_yattano}`. 
