/* sha256.c — 标准 FIPS 180-4 实现（零依赖，壳侧唯一摘要基元）。 */
#include "sha256.h"
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void block(uint32_t st[8], const uint8_t p[64]) {
    uint32_t w[64], a, b, c, d, e, f, g, h;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
               ((uint32_t)p[4 * i + 2] << 8) | (uint32_t)p[4 * i + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = st[0]; b = st[1]; c = st[2]; d = st[3];
    e = st[4]; f = st[5]; g = st[6]; h = st[7];
    for (i = 0; i < 64; i++) {
        uint32_t t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) +
                      ((e & f) ^ ((~e) & g)) + K[i] + w[i];
        uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) +
                      ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

/* ---------- 流式接口（分块喂入；tail 逻辑与单发版等价） ---------- */

void pkapp_sha256_init(pkapp_sha256_ctx *c) {
    c->st[0] = 0x6a09e667u; c->st[1] = 0xbb67ae85u; c->st[2] = 0x3c6ef372u;
    c->st[3] = 0xa54ff53au; c->st[4] = 0x510e527fu; c->st[5] = 0x9b05688cu;
    c->st[6] = 0x1f83d9abu; c->st[7] = 0x5be0cd19u;
    c->tlen = 0;
    c->bits = 0;
}

void pkapp_sha256_update(pkapp_sha256_ctx *c, const uint8_t *data, size_t len) {
    c->bits += (uint64_t)len * 8;
    if (c->tlen) {
        size_t take = 64 - c->tlen;
        if (take > len) take = len;
        memcpy(c->tail + c->tlen, data, take);
        c->tlen += take;
        data += take;
        len -= take;
        if (c->tlen == 64) {
            block(c->st, c->tail);
            c->tlen = 0;
        }
    }
    while (len >= 64) {
        block(c->st, data);
        data += 64;
        len -= 64;
    }
    if (len) {
        memcpy(c->tail, data, len);
        c->tlen = len;
    }
}

void pkapp_sha256_final(pkapp_sha256_ctx *c, uint8_t out[32]) {
    size_t rem = c->tlen;
    uint64_t bits = c->bits;
    int i;
    c->tail[rem] = 0x80;
    rem++;
    if (rem > 56) {
        memset(c->tail + rem, 0, 64 - rem);
        block(c->st, c->tail);
        memset(c->tail, 0, 64);
    } else {
        memset(c->tail + rem, 0, 56 - rem);
    }
    for (i = 0; i < 8; i++)
        c->tail[63 - i] = (uint8_t)(bits >> (8 * i));
    block(c->st, c->tail);
    for (i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(c->st[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->st[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->st[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->st[i];
    }
}

void pkapp_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    pkapp_sha256_ctx c;
    pkapp_sha256_init(&c);
    pkapp_sha256_update(&c, data, len);
    pkapp_sha256_final(&c, out);
}
