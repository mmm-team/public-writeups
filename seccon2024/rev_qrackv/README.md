## qrackv

We're given a RISC-V binary along with a copy of `qemu-riscv64` and a dockerfile to run it. This is pretty suspicious: why not let players just use their own copy of `qemu-riscv64`?

If we examine the binary in Ghidra, we see that the flag checking function uses a few custom instructions:
```c
bool FUN_0001060e(char *flag)

{
  char cVar1;
  bool bVar2;
  int i;
  ulong fail;
  
  cVar1 = flag_check_format(flag);
  if (cVar1 == '\x01') {
    fail = 0;
    for (i = 0; i < 9; i = i + 1) {
      custom0();
      custom0();
      custom0();
      custom0.rs1(*(ulong *)(flag + (long)i * 8));
      fail = *(ulong *)(flag + (long)i * 8) | fail;
    }
    bVar2 = fail == 0;
  }
  else {
    bVar2 = false;
  }
  return bVar2;
}
```
(where `flag_check_format` checks that the flag is of the form `SECCON\{[0-9a-f]{64}\}`)

The decompilation is slightly messed up since the custom instructions modify `a5`.

Indeed, if we use our own copy of `qemu-riscv64`, the binary crashes with `illegal hardware instruction` (after passing the flag format check).

In particular, the custom instructions are:
```
0x1065a: 8B 87 07 00
0x10674: 8B 97 E7 00
0x10680: 8B 87 07 00
0x10690: 8B A7 E7 00
```

We're going to have to reverse the given `qemu-riscv64` and see how the custom instructions were implemented.

Lets go to the largest function at `0xd59b0`, since that's probably where the bulk of the instruction decoding stuff is. There's a huge switch case with lots of extracting certain bits from an int, which looks promising.

Looking for the cases which handle the custom instructions, we get:
```
0x1065a: 8B 87 07 00
sub_d24f0(0, (0, 0xf, 0xf))

0x10674: 8B 97 E7 00
sub_d17e0(0, (0xf, 0xf, 0xe))

0x10680: 8B 87 07 00
sub_d24f0(0, (0, 0xf, 0xf))

0x10690: 8B A7 E7 00
v202 = sub_b8a50(1, 0xf, 0)
v203 = sub_b8a50(1, 0xf, 0)
v204 = sub_b8a50(1, 0xe, 0)
v205 = __readfsqword(0xffffff58)
sub_17A290(off_2F7E60, &off_2F7E60, v205 + v202, v205 + qword_30B838, v205 + v203, v205 + v204)
```

QEMU uses the [TCG](https://www.qemu.org/docs/master/devel/index-tcg.html) to translate instructions from the target arch to the host arch, so we're going to have to look into how that works.

With extensive cross-referencing of the TCG source code and docs:
- https://github.com/qemu/qemu/blob/master/tcg/tcg.c
- https://github.com/qemu/qemu/blob/master/tcg/tcg-op.c
- https://www.qemu.org/docs/master/devel/tcg-ops.html
- https://github.com/qemu/qemu/blob/master/include/tcg/tcg-opc.h (contains all the TCG opcodes in order, for converting between ints and opcodes)
- https://github.com/qemu/qemu/blob/master/include/tcg/tcg-cond.h (condition codes)
we get that the first 3 custom instructions emit TCG, while the last one passes `a4` and `a5` to `0x58B40` via `tcg_gen_call3`.

This function just checks that `a5` matches some hardcoded values at `0x1EDB00`.
```
_BOOL8 __fastcall sub_58B40(__int64 a1, __int64 check_a5, __int64 i_a4)
{
  unsigned __int64 v3; // rax
  __int64 j; // rsi
  __int64 v7; // rdx
  __int64 v8; // rcx

  v3 = 0x803ED074B4320BA0LL;
  if ( i_a4 )
  {
    j = 0LL;
    v7 = 3LL;
    do
    {
      ++j;
      v8 = 3 * v7 % 29;
      v7 = v8;
    }
    while ( i_a4 != j );
    v3 = check_data[v8];
  }
  return check_a5 != v3;
}
```

Here's the first 3 custom instructions reimplemented in python (slightly cleaned up, recovered control flow):
```
MASK64 = 0xFFFFFFFF_FFFFFFFF

def custom_1_and_3(a5):
    tmp1 = 0x9282F38FD9DE6BB
    tmp2 = a5
    tmp4 = 0

    while tmp1 > 0:
        tmp3 = tmp1 & 1
        tmp5 = (tmp2 * tmp3) & MASK64

        t = tmp4 + tmp5

        t_hi = t >> 64
        t_lo = t & MASK64
        tmp6 = 0xFFFFFFFFFFFFFFFF % 0xFFFFFFFFFFFFFFC5
        tmp6 = (tmp6 + 1) & MASK64
        tmp6 = (tmp6 * t_hi) & MASK64
        tmp7 = t_lo % 0xFFFFFFFFFFFFFFC5
        tmp7 = (tmp7 + tmp6) & MASK64
        tmp7 = tmp7 % 0xFFFFFFFFFFFFFFC5

        tmp4 = tmp7
        tmp1 >>= 1
        t = tmp2 + tmp2

        t_hi = t >> 64
        t_lo = t & MASK64
        tmp6 = 0xFFFFFFFFFFFFFFFF % 0xFFFFFFFFFFFFFFC5
        tmp6 = (tmp6 + 1) & MASK64
        tmp6 = (tmp6 * t_hi) & MASK64
        tmp7 = t_lo % 0xFFFFFFFFFFFFFFC5
        tmp7 = (tmp7 + tmp6) & MASK64
        tmp7 = tmp7 % 0xFFFFFFFFFFFFFFC5

        tmp2 = tmp7

    t = tmp4 + 0x9A10A8B923AC8BF
    t_hi = t >> 64
    t_lo = t & MASK64
    tmp6 = 0xFFFFFFFFFFFFFFFF % 0xFFFFFFFFFFFFFFC5
    tmp6 = (tmp6 + 1) & MASK64
    tmp6 = (tmp6 * t_hi) & MASK64
    tmp7 = t_lo % 0xFFFFFFFFFFFFFFC5
    tmp7 = (tmp7 + tmp6) & MASK64
    tmp7 = tmp7 % 0xFFFFFFFFFFFFFFC5

    return tmp7 # returns in a5

def custom_2(a4, a5):
    tmp4 = a5
    tmp1 = 0
    for i in range(16):
        tmp5 = a4 >> (i * 4)
        tmp5 &= 7
        tmp7 = 0
        for j in range(8):
            tmp6 = j
            if j == 0:
                tmp6 = tmp5
            if j == tmp5:
                tmp6 = 0
            tmp3 = (tmp6 * 8) & MASK64
            tmp8 = tmp4 >> tmp3
            tmp8 &= 255
            tmp8 = (tmp8 << (j * 8)) & MASK64
            tmp7 |= tmp8
        tmp4 = tmp7
        tmp1 += 1
    return tmp4 # returns in a5
```

After experimenting with these for a bit, we recognize that `custom_1_and_3` implements `a5 = (0x9282F38FD9DE6BB * a5 + 0x9A10A8B923AC8BF) % 0xFFFFFFFFFFFFFFC5` and `custom_2` swaps around the bytes of `a5` based on `a4`.

This lets us do a fast bruteforce: `custom_1_and_3` is fully invertible, while `custom_2` only has 8!=40320 possible outputs. Since we know that the flag only has the characters `a-f0-9` (+`SECCON{}`), we can bruteforce all possible permutations, invert the custom instructions, and check if the result only uses flag characters.

This is implemented in [solve_fast.py](solve_fast.py).
