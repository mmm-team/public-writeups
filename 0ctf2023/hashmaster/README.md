# hashmaster

Writeup by: [ath0](https://andrewh.tech)

```
./hashmaster_c427d255c4b7f046798b3a931df4c935
Are you master of hash ?
Choose level:
  0. baby
  1. easy
  2. middle
  3. hard
  4. insane
> 0
Your input:
ffffffffffffffffffff
failed
```


This was a 5-part challenge. We are given a stripped binary. After some light reversing (i.e. look at strings), you can figure out they statically linked in Unicorn. You can match up the functions with the public API fairly easily.

The binary takes two inputs, a level number (0-4) and then a shitton of bytes. Some decoding got inlined but we can guess based on some checks '=' that they are doing base64 decoding.

You can identify an emulation loop by looking at the unicorn calls. But first it maps two memory regions:

- 0x1000000 (size 0x200000), RWX
- 0x2000000 (size 0x1000), RWX

Your input is copied in to 0x1000000, and this is where execution begins. So we know we need to send in base64-encoded shellcode.

After emulation is over, it reads out the first 32 bytes at 0x2000000 and does a memcmp.

## baby

The memcmp in this case is with [0xff, 0xff, ..., 0xff] so we just send shellcode to write these bytes into memory at 0x2000000. I just did something like:

```
movabs rax, 0x2000000
movabx rbx, 0xffffffffffffffff
mov qword ptr [rax], rbx
mov qword ptr [rax+8], rbx
mov qword ptr [rax+0x10], rbx
mov qword ptr [rax+0x18], rbx
```

## the other levels

The other levels are much harder. We see that the memcmp now compares a hash of our input (our shellcode) with the data in 0x2000000 at the end. This seems to suggest we need some sort of quine. In particular, we need our shellcode to write the hash of itself to memory.

At first glance, this seems quite difficult. The hash function does not appear breakable (at first, I did not identify it, but after solving this i identified it as sha256. we can treat it as black-box), and whenever you change any of the bytes of the shellcode the hash will change.

But there are four levels ahead of us, so let's check the restrictions. 
- They install a memory ***read*** hook (hook type 0x400) which will cause the emulation loop to exit if we ***read*** outside of 0x2000000. This hook is in place in the "middle" and "insane" challenges. It's important to note that this only restricts reading -- we can still do self-modifying code.
- The emulation loop disallows backwards jumps in the "hard" and "insane" challenges.

In summary:
- easy: backwards jumps allowed, code is rw
- middle: backwards jumps allowed, code is write-only
- hard: no backwards jumps, code is rw
- insane: no backwards jumps, code is write-only

### The hash function

As mentioned above, we can treat the hash function as a black box. Reversing the binary, we see the hash function operates in rounds of 0x40 bytes. The hash function keeps an internal state which is updated by each round of the hash function
```
struct struct_2 __packed
{
    uint64_t in_bytes[0x8];
    int32_t num_bytes;
    char _pad[4];
    int64_t field_48;
    uint64_t internal_state[0x4];
};
```

Each round is handled by `FUN_001699a0`.

In all of the versions of the challenge, I literally copy-pasted the assembly out of objdump for a single round of the hash function, and just patched up the global data references. So I was executing the same implementation of the hash function as the original program.

## Easy

We can read our own code, so just compute the hash function block-by-block on ourselves. Ensure our size is 0x40-aligned for convenience.

There is some sort of final block that has some constant (size-dependent?) data. idk i didn't read how sha256 worked, I literally just ran the original binary and copied the final block out. This extra round of the hash function gets run at the end.

After we get the hash, we just copy the bytes into the 0x2000000 region to get the flag. After a moment of confusion, you realize you have to do an endian flip as well.

See `easy/ass.py`.

## The other levels

I realized that if you solved the insane version, you would get the rest. So I focused on that. I spent a long time trying to find a bug in Unicorn (https://github.com/unicorn-engine/unicorn/issues/1908 sus or what???) since that could allow us to bypass the read hook and just use our existing solution. However, I realized that this still wouldn't let us bypass the backward-jump restriction, and I wasn't sure how much I could unroll the hash function. So I needed another solution....


The trick is that since the hash is computed block by block, you can pre-compute the hash state after the first N bytes.

The "payload" as far as the program is concerned then consists of:

1. N bytes (the 'prefix'), which we can precompute the hash state for
2. a 0x40 (one hash block) assembly stub that writes the partial hash of the first N bytes (i.e. as immediates using movabs) into the writable portion of memory

So after the above two parts execute, the hash function is completely computed except for the last block. So we just need to make two more calls to the hash function: one for the final 0x40 stub and then one for the finalizer (some constant bytes).

Therefore, the first N bytes (the 'prefix') need to write some code out after the end of our payload (but still within the 0x1000000 segment) that will compute two rounds of the hash function. This code is effectively JIT-ed and not part of the hash, since the hash was computed on the payload before execution. Since we can't read-ourselves, we will have to construct a replica of the 0x40 block (but this isn't hard since we know the instruction sequence and we have the partial hash it wrote).

After this, you have a solution to 'middle'. The only thing you need to get 'hard' and 'insane' is to eliminate backwards jumps. There's just two loops in the hash round so I unroll these with assembler macros.


A python script puts it all together: see `insane/ass.py`.

