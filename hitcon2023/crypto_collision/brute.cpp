#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unordered_map>
#include <pthread.h>

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

uint64_t cache[16777216];
uint64_t ov0, ov1, ov2, ov3;

#define CM 0xffffffULL
#define ITER 256
#define unlikely(x) __builtin_expect(!!(x), 0)

static uint64_t do_second_block(uint64_t x) {
    uint64_t v0 = ov0;
    uint64_t v1 = ov1;
    uint64_t v2 = ov2;
    uint64_t v3 = ov3;

    /* We will only consider 15-byte messages: 8-byte salt + 7-byte suffix */
    uint64_t b = (x & ~(0xffULL << 56)) | (15ULL << 56);
    v3 ^= b;
    SINGLE_ROUND(v0,v1,v2,v3);
    v0 ^= b;
    v2 ^= 0xff;
    SINGLE_ROUND(v0,v1,v2,v3);
    SINGLE_ROUND(v0,v1,v2,v3);
    SINGLE_ROUND(v0,v1,v2,v3);

    /* modified */
    return (v0 ^ v1) ^ (v2 ^ v3);
}

static void check_collision(uint64_t t0, uint64_t t1) {
    std::unordered_map<uint64_t, uint64_t> backlink;
    for(int it = 0; it < ITER; it++) {
        uint64_t h = do_second_block(t0);
        backlink[h] = t0;
        t0 = h;
    }

    for(int it = 0; it < ITER; it++) {
        uint64_t h = do_second_block(t1);
        if (backlink.find(h) != backlink.end()) {
            t0 = backlink[h];
            bool ok = (t0 & ~(0xffULL << 56)) != (t1 & ~(0xffULL << 56));
            fprintf(stderr, ": %016llx %016llx [%s]\n", t0, t1, ok ? "SUCCESS!" : "fail");
            if (ok) {
                printf("%016llx %016llx\n", t0, t1);
                exit(0);
            }
            return;
        }
        t1 = h;
    }
}

int NTHREADS;

static void *table_builder_tfn(void *arg) {
    uint64_t start = (uint64_t)arg * (16777216 / NTHREADS);
    uint64_t end = ((uint64_t)arg + 1) * (16777216 / NTHREADS);
    for(uint64_t t = start; t < end; t++) {
        if((t & 0xfffff) == 0) {
            fprintf(stderr, "building table ... %lld\n", t);
        }
        uint64_t x = t;
        for(int it = 0; it < ITER; it++) {
            x = do_second_block(x);
        }
        cache[x & CM] = (x & ~CM) | t;
    }
    return NULL;
}

static void *table_searcher_tfn(void *arg) {
    uint64_t t = (uint64_t)arg + 0x100000000ULL;

    for(uint64_t i=0; ; i++) {
        if((i & 0xfffff) == 0) {
            fprintf(stderr, "searching table ... %lld:%lld\n", (uint64_t)arg, i);
        }
        uint64_t x = t;
        for(int it = 0; it < ITER; it++) {
            x = do_second_block(x);
            if (unlikely((cache[x & CM] & ~CM) == (x & ~CM))) {
                fprintf(stderr, "candidate: %016llx %016llx ", t, cache[x & CM]);
                check_collision(cache[x & CM] & CM, t);
            }
        }
        t = t * 2862933555777941757ULL + 3037000493ULL;
    }
    return NULL;
}

int main(int argc, char **argv) {
    if(argc < 4) {
        fprintf(stderr, "Usage: %s <nthreads> <hash seed in dec> <salt in hex>\n", argv[0]);
        return 1;
    }

    NTHREADS = atoi(argv[1]);

    uint64_t key[2];
    uint32_t hashseed = strtoul(argv[2], NULL, 10);
    lcg_urandom(hashseed, (unsigned char *)&key, 16);

    uint64_t v0 = key[0] ^ 0x736f6d6570736575ULL;
    uint64_t v1 = key[1] ^ 0x646f72616e646f6dULL;
    uint64_t v2 = key[0] ^ 0x6c7967656e657261ULL;
    uint64_t v3 = key[1] ^ 0x7465646279746573ULL;

    uint8_t salt[8];
    for(int i=0; i<8; i++) {
        unsigned int c;
        sscanf(argv[3] + i * 2, "%02x", &c);
        salt[i] = c;
    }
    /* First block */
    uint64_t mi;
    memcpy(&mi, salt, 8);
    mi = _le64toh(mi);
    v3 ^= mi;
    SINGLE_ROUND(v0,v1,v2,v3);
    v0 ^= mi;

    ov0 = v0;
    ov1 = v1;
    ov2 = v2;
    ov3 = v3;

    /* Rainbow tabling */
    pthread_t threads[NTHREADS];
    for(uint64_t i=0; i<NTHREADS; i++) {
        pthread_create(&threads[i], NULL, table_builder_tfn, (void *)i);
    }
    for(int i=0; i<NTHREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Searching */
    for(uint64_t i=0; i<NTHREADS; i++) {
        pthread_create(&threads[i], NULL, table_searcher_tfn, (void *)i);
    }
    for(int i=0; i<NTHREADS; i++) {
        pthread_join(threads[i], NULL);
    }
}
