import fastcrc
import struct
import os

aarch_code = bytearray(open("sol_aarch64.bin", "rb").read().rstrip(b"\0")[0x28:])
rv64_code = bytearray(open("sol_riscv.bin", "rb").read().rstrip(b"\0")[0x28:])
x86_code = bytearray(open("sol_x86.bin", "rb").read().rstrip(b"\0")[0x28:])

print(f"{len(aarch_code) = }")
print(f"{len(rv64_code) = }")
print(f"{len(x86_code) = }")

def aarch_jump(pc, target):
    return (0x14000000 + ((target - pc) >> 2)).to_bytes(4, "little")

def rv64_jump(pc, target):
    disp = (target - pc)
    v = ((disp >> 11) & 1) << 10
    v |= ((disp >> 4) & 1) << 9
    v |= ((disp >> 8) & 3) << 7
    v |= ((disp >> 10) & 1) << 6
    v |= ((disp >> 6) & 1) << 5
    v |= ((disp >> 7) & 1) << 4
    v |= ((disp >> 1) & 7) << 1
    v |= ((disp >> 5) & 1) << 0
    return (0xa001 | (v << 2)).to_bytes(2, "little")

def x86_jump(pc, target):
    return b"\xeb" + bytes([(target - (pc + 2)) & 0xff])

# must match the polyglot header
aarch_offset = 40
x86_offset = 88
rv64_offset = 162
final_len = rv64_offset + len(rv64_code)
padding = (-final_len) % 4
final_len += padding
DUMMY_LEN = 8
CONST_OFFSET = 16

code = open("stub.bin", "rb").read()
assert len(code) == CONST_OFFSET
code += struct.pack("<QQQ", 1, 2, 3)
assert len(code) == aarch_offset, "aarch offset is now %d" % len(code)
code += aarch_code
code += aarch_jump(len(code), final_len)
DUMMY_START = len(code)
code += b"\xcc" * 8
assert len(code) == x86_offset, "x86 offset is now %d" % len(code)
code += x86_code
code += b"\xf4"
assert len(code) == rv64_offset, "rv64 offset is now %d" % len(code)
code += rv64_code
code += b"\x01\x00" * (padding // 2)
assert len(code) == final_len

code = bytearray(code)

POLY = 0x42f0e1eba9ea3693
M = 0xffff_ffff_ffff_ffff
CRC64 = fastcrc.crc64.we
CODELEN = len(code)

def mulx_gf64(x):
    x <<= 1
    if x & (1 << 64):
        x ^= (1 << 64) | POLY
    return x

def mul_gf64(a, b):
    res = 0
    for i in range(64):
        if b & (1 << i):
            res ^= a
        a = mulx_gf64(a)
    return res

xmul = 1
for i in range(CODELEN + 8):
    xmul = mul_gf64(xmul, 256)

xmul = 1
for i in range(len(code) + 8):
    xmul = mul_gf64(xmul, 256)
cinit = CRC64(b"\x00" * (8 + len(code))) ^ M
E = CRC64(b"\x5c" * 8 + b"\0" * 8)
ginit = CRC64(b"\x00" * 8) ^ M

c1 = mul_gf64(POLY, cinit ^ mul_gf64(M, xmul) ^ M)
c2 = mul_gf64(POLY, ginit ^ c1) ^ E
c3 = mul_gf64(POLY, mul_gf64(POLY, xmul))

print("c3 =", hex(c3))
consts = struct.pack("<QQQ",
    c3,
    0x578d29d06cc4f872, # MU = (x^128 / POLY) ^ (x^64)
    0x42f0e1eba9ea3693, # POLY
)
assert code[CONST_OFFSET:CONST_OFFSET + 8] == (1).to_bytes(8, "little")
code[CONST_OFFSET: CONST_OFFSET + len(consts)] = consts

# solve to get A = 0
assert code[DUMMY_START:DUMMY_START + DUMMY_LEN] == b"\xcc" * DUMMY_LEN

# https://github.com/nneonneo/pwn-stuff/blob/master/math/gf2.py
from gf2 import transpose, num2vec, solve_gf2
def xorstr(x, y):
    return bytes(cx ^ cy for cx, cy in zip(x, y))

PINV = 0xe0f50af22858fb10 # 1/x^64
target = mul_gf64(PINV, E) ^ ginit ^ c1 
input = []
crcs = []
for i in range(96):
    v = b"\x36" * 8 + code[:DUMMY_START] + os.urandom(DUMMY_LEN) + code[DUMMY_START + DUMMY_LEN:] + b"\x00" * 8
    input.append(v)
    crcs.append(CRC64(v))

A = transpose([num2vec(c, 64) for c in crcs])
b = num2vec(target, 64)

for x in solve_gf2(A, b):
    if sum(x) % 2 == 1:
        # crc64 starts with the constant -1, so only odd-parity solutions will be valid
        break
else:
    raise Exception("no solution!")

out = b'\0' * len(input[0])
for i, v in enumerate(x):
    if v:
        out = xorstr(out, input[i])

print(out.hex(), hex(CRC64(out)))
assert CRC64(out) == target

code[DUMMY_START:DUMMY_START + DUMMY_LEN] = out[8 + DUMMY_START:8 + DUMMY_START + DUMMY_LEN]

with open("code.bin", "wb") as outf:
    outf.write(code)

# rwctf{nande_toxic_shellcoding_challenge_yattano}
