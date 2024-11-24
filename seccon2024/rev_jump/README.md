## Jump - Reversing Problem - @ubuntor, @nneonneo

Jump was a reversing challenge solved by 69 teams, worth 118 points.

Description:

> Who would have predicted that ARM would become so popular?
> 
> ※ We confirmed the binary of Jump accepts multiple flags. The SHA-1 of the correct flag is c69bc9382d04f8f3fbb92341143f2e3590a61a08 We're sorry for your patience and inconvenience
> 
> Jump.tar.gz 2040eea8d701ec57a9f38b204b443487e482c5fe

We're given a small AArch64 Linux binary which checks the flag provided as its first argument.

## Solution

The binary implements a simple obfuscation: certain jumps have been replaced with a code sequence that writes to register `x30` (the link register), then `ret`. `ret` is essentially just `br x30`, so this performs a jump to an arbitrary address, but most decompilers will analyze it as a function return and consequently cut the function off at the `ret`. For example:

Thus, when first opening the binary in e.g. Ghidra, we see this decompilation for `main`:

```c
char * FUN_00400ddc(int argc,char **argv)

{
  if (argc == 2) {
    return argv[1];
  }
  puts("Incorrect");
  return NULL;
}
```

However, the `argc == 2` branch contains the following assembly code at the "end":

```
00400e18 9e f1 ff 10     adr           x30,0x400c48
00400e1c e0 03 40 f9     ldr           x0,[sp]=>local_30
00400e20 c0 03 5f d6     ret
```

This is actually just a jump to 0x400c48, but Ghidra mistakenly analyzes it as a function return.

We can tell Ghidra to explicitly analyze `ret` as a simple jump by patching Ghidra's AArch64 disassembler (SLEIGH code) as follows:

```diff
diff --git a/Ghidra/Processors/AARCH64/data/languages/AARCH64base.sinc b/Ghidra/Processors/AARCH64/data/languagesARCH64base.sinc
index 5370387..304f286 100755
--- a/Ghidra/Processors/AARCH64/data/languages/AARCH64base.sinc
+++ b/Ghidra/Processors/AARCH64/data/languages/AARCH64base.sinc
@@ -4867,7 +4867,7 @@ is b_2531=0x6b & b_2324=0 & b_2122=2 & b_1620=0x1f & b_1015=0 & Rn_GPR64 & b_000
 is b_2531=0x6b & b_2324=0 & b_2122=2 & b_1620=0x1f & b_1015=0 & aa_Xn=30 & b_0004=0
 {
     pc = x30;
-    return [pc];
+    goto [pc];
 }
 
 # C6.2.255 RETAA, RETAB page C6-1731 line 102135 MATCH xd65f0bff/mask=xfffffbff
```

With this change applied, Ghidra produces much nicer decompilation; the decompiled output (with functions renamed) can be found in [`jump.c`](jump.c).

We can see that the binary implements a simple state machine. In state "2" it will perform one of eight checks on a 4-byte chunk of the flag, with the index incrementing by four each time. Note that there's a bug in the binary: it flips back and forth between state "1" and state "2", but actually increments the index by 4 on each state transition - meaning that it ends up only checking half of the input.

All we need to do is reverse the eight (simple) checks to recover the corresponding chunks of the flag, and we're done. This can be accomplished with the following script:

```python
flag = [None] * 8
flag[0] = 0x43434553
flag[1] = 0x357b4e4f
flag[2] = 0x336b3468
flag[3] = 0x5f74315f
flag[4] = -0x6b2c5e2c - flag[3]
flag[5] = -0x626b6223 - flag[4]
flag[6] = -0x62629d6b - flag[5]
flag[7] = 0x47cb363b + flag[6]

import struct
print(struct.pack("<8I", *[f & 0xffffffff for f in flag]))
```

which yields the flag `SECCON{5h4k3_1t_up_5h-5h-5h5hk3}`.
