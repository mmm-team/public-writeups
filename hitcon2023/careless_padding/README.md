## Careless Padding - Crypto Problem

Careless Padding was a crypto challenge solved by 30 teams, worth 255 points.

Description:

> How careless can you be as an assistant...
> 
> dist-6818b607f6269d08bfa8f2f65c9af56bee8fb128.tar.gz
> 
> nc chal-careless-padding.chal.hitconctf.com 11111

We're provided with a package containing a Dockerfile that runs the following service:

```python
#!/usr/bin/env python3
#!/usr/local/bin/python
import random
import os
from secret import flag
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

N = 16

# 0 -> 0, 1~N -> 1, (N+1)~(2N) -> 2 ...
def count_blocks(length):
    block_count = (length-1) // N + 1
    return block_count

def find_repeat_tail(message):
    Y = message[-1]
    message_len = len(message)
    for i in range(len(message)-1, -1, -1):
        if message[i] != Y:
            X = message[i]
            message_len = i + 1
            break
    return message_len, X, Y

def my_padding(message):
    message_len = len(message)
    block_count = count_blocks(message_len)
    result_len =  block_count * N
    if message_len % N == 0:
        result_len += N
    X = message[-1]
    Y = message[(block_count-2)*N+(X%N)]
    if X==Y:
        Y = Y^1
    padded = message.ljust(result_len, bytes([Y]))
    return padded

def my_unpad(message):
    message_len, X, Y = find_repeat_tail(message)
    block_count = count_blocks(message_len)
    _Y = message[(block_count-2)*N+(X%N)]
    if (Y != _Y and Y != _Y^1):
        raise ValueError("Incorrect Padding")
    return message[:message_len]

def chal():
    k = os.urandom(16)
    m = json.dumps({'key':flag}).encode()

    iv = os.urandom(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)

    padded = my_padding(m)
    enc = cipher.encrypt(padded)
    print(f"""
*********************************************************
You are put into the careless prison and trying to escape.
Thanksfully, someone forged a key for you, but seems like it's encrypted... 
Fortunately they also leave you a copied (and apparently alive) prison door.
The replica pairs with this encrypted key. Wait, how are this suppose to help?
Anyway, here's your encrypted key: {(iv+enc).hex()}
*********************************************************
""")

    while True:
        enc = input("Try unlock:")
        enc = bytes.fromhex(enc)
        iv = enc[:16]
        cipher = AES.new(k, AES.MODE_CBC, iv)
        try:
            message = my_unpad(cipher.decrypt(enc[16:]))
            if message == m:
                print("Hey you unlock me! At least you know how to use the key")
            else:
                print("Bad key... do you even try?")
        except ValueError:
            print("Don't put that weirdo in me!")
        except Exception:
            print("What? Are you trying to unlock me with a lock pick?")

if __name__ == "__main__":
    chal()

```

This is a server providing a padding oracle for AES-CBC with a custom padding scheme. In particular, the padding is defined by taking the last byte of the plaintext, taking its value mod 16, and using repeated instances of the byte at that index in the previous block of plaintext as padding. In the event that the determined padding byte and the last byte of the plaintext are the same value, the padding byte has its bottom bit flipped.

We have to use this padding oracle to recover the flag, which is provided to us as a block of ciphertext upon connecting to the service.

## Step 1: Recovering 2 possibilities per byte

We first notice that we actually know the entire plaintext of the first block of the provided ciphertext. Because we know that all HITCON flags start with `hitcon{`, and that this flag is JSON-encoded in a dictionary before being encrypted & sent to us, the first 16 bytes of the plaintext must be `b'{"key": "hitcon{'`.

Because of this, if we switch up the order of the blocks such that this first block is last, we can predict what the padding byte and the pre-padding byte will be for any previous block. For any index into the ciphertext, we can then do the following:
- let B be the block that contains that index
- construct a new ciphertext consisting of B followed by the first block of the ciphertext
- determine whether that decryption's second-to-last byte, modulo 16, points to the target index (and isn't equal to the last byte of the decryption, to avoid multiple-character padding issues)
- if so, iterate through all possible IVs affecting that target index, and determine which one makes the padding work

Two such IVs will make the padding work: the one that corresponds to the decryption having the padding byte at that index, and the one corresponding to the decryption having the padding byte with its bottom bit flipped at that index.

We can do this as follows:
```python
from tqdm import tqdm
from pwn import *

first_block_pt = b'{"key": "hitcon{'

def getp():
    #p = process(['python3', 'chal.py'])
    p = remote('chal-careless-padding.chal.hitconctf.com', 11111)
    return p

p = getp()

p.recvuntil("here's your encrypted key: ")
enc = p.recvline().strip(b'\n')

FULL_ORIG_LEN = len(bytes.fromhex(enc.decode('ascii')))
p.close()

for BLOCK_IDX in range(1, FULL_ORIG_LEN // 16 - 1):
    d = {}
    while len(d) < 16:
        p = getp()

        p.recvuntil("here's your encrypted key: ")
        enc = p.recvline().strip(b'\n')
        p.recvuntil('Try unlock:')

        actual = bytes.fromhex(enc.decode('ascii'))
        orig_iv = actual[:16]
        first_two_blocks = actual[16:48]

        attack_iv = xor(first_block_pt, orig_iv)
        assert len(attack_iv) == 16

        ct = actual[16:32]
        pt = attack_iv
        then_pt = xor(actual[BLOCK_IDX*16+16:BLOCK_IDX*16+16+16], pt)
        padding_byte = then_pt[-1]
        if then_pt[-2] == then_pt[-1]:
            p.close()
            continue
        idx = then_pt[-2] % 16
        if idx in d:
            p.close()
            continue

        new_attack_blocks = actual[BLOCK_IDX*16+16:BLOCK_IDX*16+16+16] + ct
        new_cand = set()
        for k in tqdm(range(0, 256, 2)):
            base_iv = [0] * 16
            base_iv[idx] = k
            new_iv = bytes(base_iv)
            p.sendline(hexlify(new_iv + new_attack_blocks))
            response = p.recvline()
            if b'Bad key... do you even try?' in response:
                poss = (k ^ padding_byte ^ actual[BLOCK_IDX*16+idx])
                if poss in b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!.,0123456789_{}": ':
                    new_cand.add(poss)
                if (poss ^ 1) in b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!.,0123456789_{}": ':
                    new_cand.add(poss ^ 1)
                break
        d[idx] = new_cand
        print(d)

        p.close()
```

At this point in the loop, we'll have generated for each index of the currently considered block at most 2 possibilities for the value at that index. In some cases we may have only one, due to assumptions we've made around which characters are likely to be in the flag - but notice this is just a speedup, and we don't need these assumptions.

However, this is still too many candidate values: the ciphertext is ~80 bytes long, and 2^80 is far too many possibilities to go through. At this point, we tried to guess the answers assuming the flag would be human-readable, but quickly ran into trouble as there was a long random string appended to the human-readable portion of the flag.

So we had to do better.

## Step 2: Disambiguating bytes

From here, we have another key insight: if we have two blocks A and B arranged in order, if we manipulate the ciphertext of A, we change the plaintext of B in a predictable fashion: namely, any bits flipped in the ciphertext of A will be flipped in the plaintext of B. We can use this to control the last bytes of B, even though we don't know their starting value, at the cost of corrupting the decryption of A. At first glance, this isn't super useful: while we can find some alternate value A' of A and an IV such that `oracle(IV, A', B)` has valid padding, we don't know the value of the byte in `A'` that corresponds to the padding byte.

However: since we can tweak the IV one byte at a time, we can know *which* byte of `A'` corresponds to the padding byte, even if we can't know its value. That implies that we can know the value of the last non-padding byte of the decryption of `B`, modulo 16!

To exploit this, we take a dummy block A and our target block B, and we manipulate A until the padding doesn't work with some IV (in our attack, we take the block preceding A - but there's no fundamental reason this is necessary). The majority of the time, this takes no manipulation at all. We then iterate through the indexes 0-16, and iterate through all possible values of the byte at that index until the padding works. This will only possibly fix the padding for one particular index: and that will (with high probability) be the index that corresponds to the second-to-last byte of B's plaintext! We can use this to then recover a set of possible byte values for that byte of B, and intersect it with our known pairs. This is guaranteed to only return one possible value.

For earlier bytes in the block, we manipulate the value of `A` such that the last byte of the decryption of `B` in that constructed ciphertext matches the padding byte, and then repeat the attack. Here, we must try two different values, since we have not yet disambiguated the value of the padding byte! Odds, however, are pretty good that only one of the two possible values will produce a non-empty intersection at the end of the attack - and in that case, we have successfully disambiguated the value of the last byte.

We implement this attack as follows:

```python

def leak(p, new_construction, k, candidate_idx):
    # Find a way to break the padding
    x = None
    for b in tqdm(range(256)):
        new_construction[16+k] ^= b
        p.sendline(hexlify(bytes(new_construction)))
        new_construction[16+k] ^= b
        response = p.recvline()
        #print(response)
        if b"Don't put that weirdo in me!" in response:
            x = b
            break
    assert x is not None

    print("got break")

    new_construction[16+k] ^= x
    tgt_idx = None
    done = False
    for b in tqdm(range(0, 256, 2)):
        i = candidate_idx
        if True:
            new_construction[i] ^= b
            p.sendline(hexlify(bytes(new_construction)))
            new_construction[i] ^= b
            response = p.recvline()
            if b"Bad key... do you even try?" in response:
                tgt_idx = i
                done = True
                break
        if done:
            break
    new_construction[16+k] ^= x
    if tgt_idx is None:
        return set()

    vals = set([v for v in range(256) if v % 16 == tgt_idx and chr(v) in printable])
    return vals

# [... in the for loop from the block above ...]

    # first we grab the value for the 15th byte
    for i in range(16):
        p = getp()
        p.recvuntil("here's your encrypted key: ")
        enc = p.recvline().strip(b'\n')
        p.recvuntil('Try unlock:')

        actual = bytes.fromhex(enc.decode('ascii'))
        orig_iv = actual[:16]
        known_ct = actual[16:32]
        target_block = actual[(BLOCK_IDX+1)*16:(BLOCK_IDX+2)*16]
        pre_block = actual[BLOCK_IDX*16:(BLOCK_IDX+1)*16]
        if BLOCK_IDX == 1:
            pre_pre_block = orig_iv
        else:
            pre_pre_block = actual[(BLOCK_IDX-1)*16:(BLOCK_IDX)*16]
        new_construction = list(pre_pre_block + pre_block + target_block)
        vals |= leak(p, new_construction, 15, i)
        p.close()
        if len(vals) > 0:
            break

    d[14] &= vals
    assert len(d[14]) == 1
    val_d14 = list(d[14])[0]
    real = {14: val_d14}

    # now we have it, so we can tweak the ciphertext until the padding lines up
    # so we can attack the previous bytes
    other_poss = None
    real_poss = None
    worked = set()
    avail_cache = {}
    for k in range(13, -1, -1):
        avail = {}
        if len(d[k]) == 1:
            real[k] = list(d[k])[0]
            avail_cache[k] = {po: set([real[k]]) for po in d[15]}
            continue

        for poss in d[15]:
            if real_poss is not None and poss != real_poss:
                continue

            print(avail_cache)
            print(k, avail_cache, real_poss, poss)
            my_reals = {c: list(avail_cache[c][poss])[0] for c in avail_cache} | real
            print(my_reals)

            tgt_idx = None
            done = False
            for i in tqdm(set(qewr%16 for qewr in d[k])):
                p = getp()
                p.recvuntil("here's your encrypted key: ")
                enc = p.recvline().strip(b'\n')
                p.recvuntil('Try unlock:')

                actual = bytes.fromhex(enc.decode('ascii'))
                orig_iv = actual[:16]
                known_ct = actual[16:32]
                target_block = actual[(BLOCK_IDX+1)*16:(BLOCK_IDX+2)*16]
                pre_block = actual[BLOCK_IDX*16:(BLOCK_IDX+1)*16]
                if BLOCK_IDX == 1:
                    pre_pre_block = orig_iv
                else:
                    pre_pre_block = actual[(BLOCK_IDX-1)*16:(BLOCK_IDX)*16]

                new_construction = list(pre_pre_block + pre_block + target_block)
                target_val = my_reals[k+1]
                new_construction[16+15] ^= (poss ^ target_val)
                for o in range(k+2, 15):
                    new_construction[16+o] ^= (my_reals[o] ^ target_val)

                for b in range(0, 256, 2):
                    new_construction[i] ^= b
                    p.sendline(hexlify(bytes(new_construction)))
                    new_construction[i] ^= b
                    response = p.recvline()

                    if b"Bad key... do you even try?" in response:
                        tgt_idx = i
                        done = True
                        break

                p.close()
                if done:
                    break
                

            vals = set([v for v in range(256) if v % 16 == tgt_idx and chr(v) in printable])
            z = vals & d[k]
            #print(k, z)
            if len(z) > 0:
                avail[poss] = z
            p.close()

        avail_cache[k] = avail
        if len(avail) == 0:
            # the attack fails in this case
            print("uh-oh...", BLOCK_IDX, k)
        elif len(avail) == 1:
            # we can disambiguate the last byte!
            real_poss = [k for k in avail][0]
            for c in avail_cache:
                d[c] &= avail_cache[c][real_poss]
                assert len(d[c]) == 1
                real[c] = list(d[c])[0]

    d[15] = set([real_poss])
    real[15] = real_poss

    res = bytes(real[i] for i in range(16))
```

Note that this implementation has some chance to get unlucky: if by random chance the randomness in the challenge lines up to cause our estimate of which byte we're attacking to be incorrect, the attack will fail. However, the probability of this is very small: 1/256 per block. So if this happens, we just try again and have pretty good odds of succeeding. This attack also doesn't quite work out of the box for the last block - the last block is virtually guaranteed to run into this failure case. In order to fix that, we stop after the first stage of the attack and use that to determine how long the plaintext could possibly be. We can do this because we know that the plaintext ends in `}`, so we assume any bytes after the last one that contains `}` in the possibilities set are padding and run the attack from there. If a long tail of the last bytes contain `}`, that implies that the padding bytes are all `|`, and that `}` is the first of that long tail - but we did not observe this in practice.

At this point, we have recovered the plaintext for the entire block. We repeat this attack for each successive block, and we obtain the flag. This is implemented in [`sploit.py`](./sploit.py), except for the last-block logic (which was done by hand by tweaking for loop boundaries).

During the competition, we ran this attack a block at a time. This eventually produced the flag: `hitcon{p4dd1ng_w0n7_s4v3_y0u_Fr0m_4_0rac13_617aa68c06d7ab91f57d1969e8e8532}`.
