from pwn import *


def math_func(next_byte):
    rdi = next_byte + 1
    assert rdi < 0x10000
    r9 = 1
    rax = 0x101
    r8 = 0
    rdx = -1
    rsi = -1

    while rdx != 0:
        rdx = rax % rdi
        rax = rax // rdi
        rsi = r9
        rax *= rsi
        r8 = (r8 - rax) % 0x10000
        r9 = r8
        rax = rdi
        rdi = rdx
        r8 = rsi
        # print(hex(rax), hex(rdx), hex(rdi), hex(rsi), hex(r8), hex(r9))

    rax = 0
    if rsi > 0 and rsi < 0x8000:
        rax = rsi

    rdx = rsi % 0x10000
    if rsi >= 0x8000:
        temp = 0x10000 - rsi
        rdi = 0x100000000 - temp
    # print(hex(rax), hex(rdx), hex(rdi), hex(rsi), hex(r8), hex(r9))

    rdi = rdi >> 0xf
    if rdi >= 0x10000:
        rdi = 0xffff0000 + (rdi % 0x10000)
    rdx = rdx >> 0xf
    # print(hex(rax), hex(rdx), hex(rdi), hex(rsi), hex(r8), hex(r9))

    rdi -= rsi
    rdi += rax
    rax = rdi % 0x10000
    rax *= 0xff01
    rax >>= 0x18
    # print(hex(rax), hex(rdx), hex(rdi), hex(rsi), hex(r8), hex(r9))

    rdx += rsi
    rdx += rax
    rdx %= 256
    rdx += 0x71
    rdx %= 256
    rdx ^= 0x89

    return rdx

sub_boxes = [61, 46, 51, 26, 39, 58, 15, 17, 62, 54, 38, 37, 7, 30, 21, 1, 41, 28, 14, 42, 48, 3, 63, 44, 12, 23, 5, 19, 22, 33, 56, 43, 29, 45, 55, 57, 32, 59, 8, 16, 50, 27, 35, 0, 52, 18, 49, 25, 11, 10, 24, 6, 47, 13, 53, 34, 40, 2, 31, 60, 9, 36, 4, 20]

def do_sub(inp_list):
    res_list = [0] * 0x40
    for i, b in enumerate(inp_list):
        res_list[sub_boxes[i]] = b
    return res_list

def undo_sub(inp_list):
    res_list = [0] * 0x40
    for i in range(len(inp_list)):
        res_list[i] = inp_list[sub_boxes[i]]
    return res_list

math_transforms = [0] * 0x100
for i in range(0x100):
    math_transforms[i] = math_func(i)

def undo_math(inp_list):
    res_list = [0] * 0x40
    for i in range(0x40):
        res_list[i] = math_transforms.index(inp_list[i])
    return res_list

def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
 
# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
 
max_bits = 32



# testing forward
# test_inp = bytearray(b"A" * 0x40)
# for i in range(0x100):
#     test_inp = do_sub(test_inp)
#     for j in range(0x40):
#         test_inp[j] = math_func(test_inp[j])
# print([hex(x) for x in test_inp])

# values taken from shellcode
flag_result = [ 0xa7, 0x51, 0x68, 0x52, 0x85, 0x27, 0xff, 0x31, 0x88, 0x87, 0xd2, 0xc7, 0xd3, 0x23, 0x3f, 0x52, 0x55, 0x10, 0x1f, 0xaf, 0x27, 0xf0, 0x94, 0x5c, 0xcd, 0x3f, 0x7a, 0x79, 0x9f, 0x2f, 0xf0, 0xe7, 0x45, 0xf0, 0x86, 0x3c, 0xf9, 0xb0, 0xea, 0x6d, 0x90, 0x42, 0xf7, 0x91, 0xed, 0x3a, 0x9a, 0x7c, 0x01, 0x6b, 0x84, 0xdc, 0x6c, 0xc8, 0x43, 0x07, 0x5c, 0x08, 0xf7, 0xdf, 0xeb, 0xe3, 0xae, 0xa4 ]

for i in range(0, len(flag_result), 4):
    # get 4 bytes of flag_result as one hex number
    t = int(hex(flag_result[i] + (flag_result[i+1] << 8) + (flag_result[i+2] << 16) + (flag_result[i+3] << 24)), 16)
    t ^= 0x31f3831f # /dev/zero
    t = bit_not(t)
    t = rol(t, 0xb, max_bits)
    t ^= 0x746f6f72 # /etc/passwd header
    t -= 0x464c457f # /bin/sh header
    t %= 0x100000000
    # write back to flag_result
    flag_result[i] = t & 0xff
    flag_result[i+1] = (t >> 8) & 0xff
    flag_result[i+2] = (t >> 16) & 0xff
    flag_result[i+3] = (t >> 24) & 0xff

for i in range(0x100):
    flag_result = undo_math(flag_result)
    flag_result = undo_sub(flag_result)
print(bytes(flag_result))



# r = gdb.debug("./blade", open("./commands").read())
# r.sendlineafter(">", "shell")
# r.sendlineafter("$", b"flag " + bytes(flag_result))
# r.interactive()
