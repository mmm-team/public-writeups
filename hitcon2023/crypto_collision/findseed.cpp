#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define _le64toh(x) ((uint64_t)(x))
#define ROTATE(x, b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define HALF_ROUND(a,b,c,d,s,t)     \
    a += b; c += d;                 \
    b = ROTATE(b, s) ^ a;           \
    d = ROTATE(d, t) ^ c;           \
    a = ROTATE(a, 32);

#define SINGLE_ROUND(v0,v1,v2,v3)   \
    HALF_ROUND(v0,v1,v2,v3,13,16);  \
    HALF_ROUND(v2,v1,v0,v3,17,21);

static uint64_t
siphash13(uint64_t k0, uint64_t k1, const void *src, size_t src_sz) {
    uint64_t b = (uint64_t)src_sz << 56;
    const uint8_t *in = (const uint8_t*)src;

    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    uint64_t t;
    uint8_t *pt;

    while (src_sz >= 8) {
        uint64_t mi;
        memcpy(&mi, in, sizeof(mi));
        mi = _le64toh(mi);
        in += sizeof(mi);
        src_sz -= sizeof(mi);
        v3 ^= mi;
        SINGLE_ROUND(v0,v1,v2,v3);
        v0 ^= mi;
    }

    t = 0;
    pt = (uint8_t *)&t;
    switch (src_sz) {
        case 7: pt[6] = in[6]; /* fall through */
        case 6: pt[5] = in[5]; /* fall through */
        case 5: pt[4] = in[4]; /* fall through */
        case 4: memcpy(pt, in, sizeof(uint32_t)); break;
        case 3: pt[2] = in[2]; /* fall through */
        case 2: pt[1] = in[1]; /* fall through */
        case 1: pt[0] = in[0]; /* fall through */
    }
    b |= _le64toh(t);

    v3 ^= b;
    SINGLE_ROUND(v0,v1,v2,v3);
    v0 ^= b;
    v2 ^= 0xff;
    SINGLE_ROUND(v0,v1,v2,v3);
    SINGLE_ROUND(v0,v1,v2,v3);
    SINGLE_ROUND(v0,v1,v2,v3);

    /* modified */
    t = (v0 ^ v1) ^ (v2 ^ v3);
    return t;
}

static void
lcg_urandom(unsigned int x0, unsigned char *buffer, size_t size) {
    size_t index;
    unsigned int x;

    x = x0;
    for (index=0; index < size; index++) {
        x *= 214013;
        x += 2531011;
        /* modulo 2 ^ (8 * sizeof(int)) */
        buffer[index] = (x >> 16) & 0xff;
    }
}

int main(int argc, char **argv) {
    uint64_t key[2];

    if(argc < 3) {
        fprintf(stderr, "Usage: %s <salt in hex> <target hash(salt+'ABCD') in dec>\n", argv[0]);
        return 1;
    }

    uint8_t to_hash[12];
    int64_t target;
    for(int i=0; i<8; i++) {
        unsigned int c;
        sscanf(argv[1] + i * 2, "%02x", &c);
        to_hash[i] = c;
    }
    target = strtoll(argv[2], NULL, 10);
    memcpy(&to_hash[8], "ABCD", 4);

    // lcg may as well be mod 0x1000000 since it only takes the 0xff0000 byte
    for(unsigned int i=0; i<16777216; i++) {
        lcg_urandom(i, (unsigned char *)&key, 16);
        uint64_t v = siphash13(key[0], key[1], to_hash, sizeof(to_hash));
        if (v == target) {
            printf("%u\n", i);
            break;
        }
    }
}
