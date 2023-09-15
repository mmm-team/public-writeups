from pwn import *

from string import printable

from tqdm import tqdm

from binascii import hexlify

import itertools

def repxor(k, b):
    return bytes([c ^ k for c in b])

context.log_level = 'error'
def getp():
    #p = process(['python3', 'chal.py'])
    p = remote('chal-careless-padding.chal.hitconctf.com', 11111)
    return p


p = getp()

p.recvuntil("here's your encrypted key: ")
enc = p.recvline().strip(b'\n')

FULL_ORIG_LEN = len(bytes.fromhex(enc.decode('ascii')))
p.close()

first_block_pt = b'{"key": "hitcon{'

print(FULL_ORIG_LEN // 16 - 1)
input()

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

tot = b''

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

    print(d)

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
            print("uh-oh...", BLOCK_IDX, k)
        elif len(avail) == 1:
            real_poss = [k for k in avail][0]
            for c in avail_cache:
                d[c] &= avail_cache[c][real_poss]
                assert len(d[c]) == 1
                real[c] = list(d[c])[0]

    d[15] = set([real_poss])
    real[15] = real_poss

    res = bytes(real[i] for i in range(16))
    tot += res
    print(tot)

    p.close()
