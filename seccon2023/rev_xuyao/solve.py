from pwn import *

e = ELF('xuyao')
fish = e.read(e.symbols['fish'], 16)
fish = [u32(fish[i:i+4]) for i in range(0, len(fish), 4)]
cat = e.read(e.symbols['cat'], 4*32)
cat = [u32(cat[i:i+4]) for i in range(0, len(cat), 4)]
sbox_bytes = list(e.read(e.symbols['sbox'], 256))

enc = e.read(e.symbols['enc'], 0x70)

def rol(x, n):
    return ((x << n) | (x >> (32-n))) & 0xFFFFFFFF
def ror(x, n):
    return rol(x, 32-n)
def byteswap(x):
    return u32(p32(x, endian='little'), endian='big')
def sbox(x):
    x = list(p32(x, endian='big'))
    x = [sbox_bytes[i] for i in x]
    return u32(bytes(x), endian='big')

def r(inp, key):
    x = sbox(key ^ inp[1] ^ inp[2] ^ inp[3])
    x = x ^ rol(x,3) ^ rol(x,14) ^ rol(x,15) ^ rol(x,9)
    x ^= inp[0]
    return x

def r_inv(inp, key, prev):
    x = sbox(key ^ inp[1] ^ inp[2] ^ inp[3])
    x = x ^ rol(x,3) ^ rol(x,14) ^ rol(x,15) ^ rol(x,9)
    x ^= prev
    return x

def decrypt_block(orig_inp, keys):
    inp = orig_inp[:][::-1]
    for i in range(32)[::-1]:
        tmp = inp[3]
        inp[3] = inp[2]
        inp[2] = inp[1]
        inp[1] = inp[0]
        inp[0] = r_inv(inp, keys[i], tmp)
    out = b''
    out += p32(byteswap(inp[0]))
    out += p32(byteswap(inp[1]))
    out += p32(byteswap(inp[2]))
    out += p32(byteswap(inp[3]))
    return out

def decrypt(inp, xorkey):
    bufs_b = [0,0,0,0]
    for i in range(4):
        bufs_b[i] = fish[i] ^ byteswap(u32(xorkey[i*4:i*4+4]))
    bufs_c = [0]*32
    for i in range(32):
        x = sbox(cat[i] ^ bufs_b[1] ^ bufs_b[2] ^ bufs_b[3])
        x = x ^ rol(x,11) ^ ror(x,7) ^ bufs_b[0]
        bufs_c[i] = x
        bufs_b[0] = bufs_b[1]
        bufs_b[1] = bufs_b[2]
        bufs_b[2] = bufs_b[3]
        bufs_b[3] = x

    print('round keys:', [hex(i) for i in bufs_c])

    out = b''

    for j in range(0, len(inp), 16):
        block_keys = [0]*4
        for i in range(4):
            block_keys[i] = byteswap(u32(inp[j+i*4:j+i*4+4]))
        out += decrypt_block(block_keys, bufs_c)
    return out

print(decrypt(enc, b"SECCON CTF 2023!"))
