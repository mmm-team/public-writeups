# xuyao

The program implements the following cipher, which we can write a decryption method for:
```
def r(inp, key):
    x = sbox(key ^ inp[1] ^ inp[2] ^ inp[3])
    x = x ^ rol(x,3) ^ rol(x,14) ^ rol(x,15) ^ rol(x,9)
    x ^= inp[0]
    return x

def encrypt_block(orig_inp, key, out):
    inp = [0,0,0,0]
    for i in range(4):
        inp[i] = byteswap(orig_inp[i])
    for i in range(32):
        tmp = r(inp, key[i])
        inp[0] = inp[1]
        inp[1] = inp[2]
        inp[2] = inp[3]
        inp[3] = tmp
    out[0] = byteswap(keys[3])
    out[1] = byteswap(keys[2])
    out[2] = byteswap(keys[1])
    out[3] = byteswap(keys[0])

def encrypt(inp, length, xorkey, out):
    for i in range(4):
        bufs_b[i] = fish[i] ^ byteswap(xorkey[i])
    for i in range(32):
        x = sbox(cat[i] ^ bufs_b[1] ^ bufs_b[2] ^ bufs_b[3])
        x = x ^ rol(x,11) ^ ror(x,7) ^ bufs_b[0]
        bufs_c[i] = x
        bufs_b[0] = bufs_b[1]
        bufs_b[1] = bufs_b[2]
        bufs_b[2] = bufs_b[3]
        bufs_b[3] = x
    for j in range(0, length, 16):
        for i in range(4):
            inp_state[i] = inp[j] # input as u32s, maybe byteswapped
        encrypt_block(inp_state, bufs_c, out) # output as u32s, maybe byteswapped
```

Solve script in [solve.py](`solve.py`).
