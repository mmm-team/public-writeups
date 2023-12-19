# from v8::internal::Runtime_TypedArrayVerify
import struct

target = [None] * 32
target[0] = 0x28
target[1] = 0xa5
target[2] = 0xa9
target[3] = 0xcd
target[4] = 0x34
target[5] = 10
target[6] = 0xb9
target[7] = 0xb2
target[8] = 0xf2
target[9] = 0x54
target[10] = 0xe5
target[11] = 0x56
target[12] = 0x68
target[13] = 0x41
target[14] = 0xfd
target[15] = 0xee
target[16] = 0x1a
target[17] = 0xe8
target[18] = 0x33
target[19] = 0xb3
target[20] = 0x25
target[21] = 0x8a
target[22] = 0x97
target[23] = 0xb9
target[24] = 0xd0
target[25] = 0xac
target[26] = 0xcd
target[27] = 0xf0
target[28] = 0x85
target[29] = 0xba
target[30] = 7
target[31] = 0xeb

target = bytes(target)
blocks = [struct.unpack("<II", target[i:i+8]) for i in range(0, 32, 8)]
k = 0x6a8838cf
iv = (k ^ 0x6527b8cf, k ^ 0xa14bc8df)
k0, k1 = k ^ 0x3412bade, k ^ 0x7698baad

decrypted = bytearray()
for block in blocks:
    l, r = block
    i = 0xf4dca6e0
    while i != 0:
        r = (r - ((l * 0x10) + k0 ^ (l >> 5) + k1 ^ i + l)) & 0xffffffff
        l = (l - ((r * 0x10) + k0 ^ (r >> 5) + k1 ^ r + i)) & 0xffffffff
        i = (i - 0x97a6e537) & 0xffffffff

    l ^= iv[0]
    r ^= iv[1]
    iv = block
    decrypted += struct.pack("<II", l, r)

print(decrypted.hex())
flag = [f - i for i, f in enumerate(decrypted)]
flag[0] ^= 0x3e
flag[1] -= 0x64
flag[2] -= 0x5c
flag[3] -= 0x22
flag[4] -= 0xe7
flag[5] += 0x7a
flag[6] += 0x17
flag[7] -= 0xa2
flag[8] += 0xa2
flag[9] += 0xd2
flag[10] += 0xef
flag[11] += 0xb9
flag[12] += 0x76
flag[13] ^= 0x63
flag[14] -= 0x11
flag[15] += 0x1c
flag[16] -= 0xe2
flag[17] ^= 0x0b
flag[18] += 0x48
flag[19] -= 0x2d
flag[20] ^= 0x87
flag[21] -= 0xb7
flag[22] ^= 0x46
flag[23] += 0x07
flag[24] -= 0xf2
flag[25] += 0x1a
flag[26] ^= 0xc4
flag[27] -= 0x81
flag[28] ^= 0x3a
flag[29] ^= 0x87
flag[30] -= 0x76
flag[31] += 0x6e

print(bytearray([c & 0xff for c in flag]))
# flag{97170f6727bc6757e69eb04c045478be}
