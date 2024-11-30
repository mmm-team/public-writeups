from z3 import *

inp = [BitVec('inp%d' % i, 8) for i in range(0x40)]

s = Solver()
for i in range(0x40):
    s.add(inp[i] >= 0x20)
    s.add(inp[i] <= 0x7e)

def step1_map(inp):
    m = [7, 0, 12, 13, 2, 15, 11, 8, 6, 5, 9, 4, 10, 1, 14, 3][::-1]
    m = [BitVecVal(x, 4) for x in m]

    mapped_inp = []

    for i in range(0x40):
        # Create an if-then-else tree
        low_nibble = inp[i] & 0xf
        high_nibble = LShR(inp[i], 4)

        new_low = m[0]
        for j in range(1, 16):
            new_low = If(low_nibble == j, m[j], new_low)

        new_high = m[0]
        for j in range(1, 16):
            new_high = If(high_nibble == j, m[j], new_high)

        mapped_inp.append(Concat(new_high, new_low))
    return mapped_inp

mapped_inp = step1_map(inp)
mapped_ints = []
for i in range(0, 0x40, 4):
    mapped_ints.append(Concat(mapped_inp[i+3], mapped_inp[i+2], mapped_inp[i+1], mapped_inp[i]))

mapped_inp2 = [x * BitVecVal(0x4e6a44b9, 32) for x in mapped_ints]

# test_input = (b"ABCDEFGH").ljust(0x40, b"A")
# for i in range(0x40):
#     s.add(inp[i] == test_input[i])


def rol(val, r):
    return (val << r) | LShR(val, 32 - r)

mapped_inp3 = []
for i in range(16-3):
    k1 = rol(mapped_inp2[i+3], 29)
    k2 = rol(mapped_inp2[i+2], 17)
    k3 = rol(mapped_inp2[i+1], 7)
    k4 = mapped_inp2[i]
    mapped_inp3.append(k1 ^ k2 ^ k3 ^ k4)

for i in range(16-3, 16):
    mapped_inp3.append(mapped_inp2[i])

def step1_map_full(inp):
    mapped_inp3_bytes = []
    for v in inp:
        for i in range(4):
            mapped_inp3_bytes.append(Extract(8*i+7, 8*i, v))

    inp4 = step1_map(mapped_inp3_bytes)
    inp4_ints = []
    for i in range(0, 0x40, 4):
        inp4_ints.append(Concat(inp4[i+3], inp4[i+2], inp4[i+1], inp4[i]))

    return inp4_ints

inp4_ints = step1_map_full(mapped_inp3)

def step2_xor(inp4_ints):
    return [x * BitVecVal(0x4e6a44b9, 32) for x in inp4_ints]

inp5 = step2_xor(inp4_ints)

def step3_rotate(inp5, skip):
    inp6 = []
    for i in range(min(skip, 3)):
        inp6.append(inp5[i])

    for i in range(skip, skip+13):
        k1 = rol(inp5[(i+3)%16], 29)
        k2 = rol(inp5[(i+2)%16], 17)
        k3 = rol(inp5[(i+1)%16], 7)
        k4 = inp5[(i+0)%16]
        inp6.append(k1 ^ k2 ^ k3 ^ k4)

    for i in range(16-(3-min(skip, 3)), 16):
        inp6.append(inp5[i])

    assert len(inp6) == 16
    return inp6

inp6 = step3_rotate(inp5, 1)

inp7 = step1_map_full(inp6) # 8741
inp8 = step2_xor(inp7) # 8e67
inp9 = step3_rotate(inp8, 2) # 0x983e

inp10 = step1_map_full(inp9) # 8741
inp11 = step2_xor(inp10) # 8e67
inp12 = step3_rotate(inp11, 3) # 0x983e

def step3_rotate2(inp5, index):
    inp6 = []
    for i in range(0, 16):
        if (i >= index and i < index+3):
            inp6.append(inp5[i])
        else:
            k1 = rol(inp5[(i+3)%16], 29)
            k2 = rol(inp5[(i+2)%16], 17)
            k3 = rol(inp5[(i+1)%16], 7)
            k4 = inp5[(i+0)%16]
            inp6.append(k1 ^ k2 ^ k3 ^ k4)

    assert len(inp6) == 16
    return inp6

inp13 = step1_map_full(inp12) # 8741
inp14 = step2_xor(inp13) # 8e67
inp15 = step3_rotate2(inp14, 1) # 0x983e

inp16 = step1_map_full(inp15) # 8741
inp17  = step2_xor(inp16) # 8e67
inp18 = step3_rotate2(inp17, 2) # 0x983e

inp19 = step1_map_full(inp18) # 8741
inp20  = step2_xor(inp19) # 8e67
inp21 = step3_rotate2(inp20, 3) # 0x983e

inp22= step1_map_full(inp21) # 8741
inp23  = step2_xor(inp22) # 8e67
inp24 = step3_rotate2(inp23, 4) # 0x983e


expected = ['0xb7e9a2a4', '0x1904c652', '0xbe8afe4d', '0xbd18775a', '0x82841cf4', '0xd2c1d5af', '0xf389c4a', '0x451f151a', '0xd5689a8c', '0x927b5bd9', '0xf86c82d7', '0x34bc7c60', '0x97aef869', '0x2c0cccdd', '0x88d2ec9b', '0x11793013']
expected = [ int(x, 16) for x in expected[::-1] ]

for (i, x) in enumerate(expected):
    s.add(inp24[i] == x)

if s.check() == sat:
    m = s.model()
    # print out the mapped_inp bytes
    # res = [hex(m.eval(inp24[i]).as_long()) for i in range(0x40 // 4)]
    res = [m.eval(inp[i]).as_long() for i in range(0x40)]
    print(res)
    print(bytes(res))
else:
    print("unsat")


