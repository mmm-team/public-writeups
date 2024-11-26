## packed - @alueft

* rev warmup
* 119 solves
* 93 points

> Packer is one of the most common technique malwares are using.
>
> packed.tar.gz 320fa70af76e54f2b6aec55be4663103d199a4a5
>
> author: ptr-yudai

We're given a Linux ELF binary, which at first glance appears to be a simple
flag checker. Inspecting the output of `strings`, we see:
```
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $
```
which suggests that this binary was compressed with
[UPX](https://upx.github.io/). It turns out UPX has a decompression function,
and it seems to make the binary more readable, but if we look at the main
function in Ghidra...

```c
undefined8 main(void)
{
  long in_FS_OFFSET;
  undefined local_98 [136];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  write(1,"FLAG: ",6);
  read(0,local_98,0x80);
  write(1,"Wrong.\n",7);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
...hilariously, it always outputs `Wrong.`. This isn't very useful, so we have
to take a closer look at the original binary.

Thankfully, we can run this in gdb, interrupt when the binary reads input, and
look at what's happening:

```asm
   0x000000000044ee1d:  syscall
=> 0x000000000044ee1f:  cmp    eax,0x31
   0x000000000044ee22:  jne    0x44eec3  ; jumps to printing "wrong"
   0x000000000044ee28:  mov    ecx,eax
   0x000000000044ee2a:  pop    rdx
   0x000000000044ee2b:  pop    rsi
   0x000000000044ee2c:  lea    rdi,[rsp-0x90]
   0x000000000044ee34:  lods   al,BYTE PTR ds:[rsi]
   0x000000000044ee35:  xor    BYTE PTR [rdi],al
   0x000000000044ee37:  inc    rdi
   0x000000000044ee3a:  loopne 0x44ee34
   0x000000000044ee3c:  call   0x44ee72
```

In other words, it expects the flag input to be 0x31 characters long, including
an ending newline, and if the length check passes, xors input against some
block of bytes. Luckily, this block is static, and we can just inspect it after
the `pop rsi` instruction:
```
gef➤  x/48xb $rsi
0x7ffff7ff7f14: 0xe8    0x4a    0x00    0x00    0x00    0x83    0xf9    0x49
0x7ffff7ff7f1c: 0x75    0x44    0x53    0x57    0x48    0x8d    0x4c    0x37
0x7ffff7ff7f24: 0xfd    0x5e    0x56    0x5b    0xeb    0x2f    0x48    0x39
0x7ffff7ff7f2c: 0xce    0x73    0x32    0x56    0x5e    0xac    0x3c    0x80
0x7ffff7ff7f34: 0x72    0x0a    0x3c    0x8f    0x77    0x06    0x80    0x7e
0x7ffff7ff7f3c: 0xfe    0x0f    0x74    0x06    0x2c    0xe8    0x3c    0x01
```

After this xor, it calls `0x44ee72`, so let's take a look there:
```asm
   0x000000000044ee72:  mov    ecx,0x31
   0x000000000044ee77:  pop    rsi
   0x000000000044ee78:  lea    rdi,[rsp-0x90]
   0x000000000044ee80:  xor    edx,edx
   0x000000000044ee82:  lods   al,BYTE PTR ds:[rsi]
   0x000000000044ee83:  cmp    BYTE PTR [rdi],al
   0x000000000044ee85:  setne  al
   0x000000000044ee88:  or     dl,al
   0x000000000044ee8a:  inc    rdi
   0x000000000044ee8d:  loopne 0x44ee82
   0x000000000044ee8f:  test   edx,edx
```

It compares the xored flag against some other block of bytes and checks if
anything fails to match. Setting a breakpoint at `0x44ee72` and advancing a
few instructions, we can get the contents of the second block:

```
gef➤  x/48xb $rsi
0x44ee41:       0xbb    0x0f    0x43    0x43    0x4f    0xcd    0x82    0x1c
0x44ee49:       0x25    0x1c    0x0c    0x24    0x7f    0xf8    0x2e    0x68
0x44ee51:       0xcc    0x2d    0x09    0x3a    0xb4    0x48    0x78    0x56
0x44ee59:       0xaa    0x2c    0x42    0x3a    0x6a    0xcf    0x0f    0xdf
0x44ee61:       0x14    0x3a    0x4e    0xd0    0x1f    0x37    0xe4    0x17
0x44ee69:       0x90    0x39    0x2b    0x65    0x1c    0x8c    0x0f    0x7c
```

which interestingly is within program code, and includes some bogus
instructions. But anyway, we can throw together a Python script to xor these two
blocks together (where I'm sure there's some elegant way of doing this entirely
in gdb, but I'm more familiar with Python spaghetti):
```py
parse = lambda x: sum([i.split()[1:] for i in x.strip().split("\n")], [])

x = parse("""
0x7ffff7ff7f14: 0xe8    0x4a    0x00    0x00    0x00    0x83    0xf9    0x49
0x7ffff7ff7f1c: 0x75    0x44    0x53    0x57    0x48    0x8d    0x4c    0x37
0x7ffff7ff7f24: 0xfd    0x5e    0x56    0x5b    0xeb    0x2f    0x48    0x39
0x7ffff7ff7f2c: 0xce    0x73    0x32    0x56    0x5e    0xac    0x3c    0x80
0x7ffff7ff7f34: 0x72    0x0a    0x3c    0x8f    0x77    0x06    0x80    0x7e
0x7ffff7ff7f3c: 0xfe    0x0f    0x74    0x06    0x2c    0xe8    0x3c    0x01
""")

y = parse("""
0x44ee41:       0xbb    0x0f    0x43    0x43    0x4f    0xcd    0x82    0x1c
0x44ee49:       0x25    0x1c    0x0c    0x24    0x7f    0xf8    0x2e    0x68
0x44ee51:       0xcc    0x2d    0x09    0x3a    0xb4    0x48    0x78    0x56
0x44ee59:       0xaa    0x2c    0x42    0x3a    0x6a    0xcf    0x0f    0xdf
0x44ee61:       0x14    0x3a    0x4e    0xd0    0x1f    0x37    0xe4    0x17
0x44ee69:       0x90    0x39    0x2b    0x65    0x1c    0x8c    0x0f    0x7c
""")

print("".join(chr(int(a,16)^int(b,16)) for a,b in zip(x,y)))
```

This outputs the flag: `SECCON{UPX_s7ub_1s_a_g0od_pl4c3_f0r_h1din6_c0d3}`.

Sure enough, giving this as the input to the original binary results in an
output of `OK!`, while using the decompressed binary gives `Wrong.`. As the flag
(and description) suggests, this can be used to trick someone attempting to
reverse a UPX-compressed binary.
