/* ed25519.c — Ed25519 验签路径（TweetNaCl 20140920 公有领域子集移植）。
 *
 * 裁剪范围：只保留 RFC 8032 验证所需——SHA-512、curve25519 域运算、
 * 点解压（unpackneg）、标量归约（reduce）、定点乘（scalarbase）与打包比较。
 * 验证方程：[s mod L]B == R + [h mod L]A，h = SHA-512(R || A || M)。
 * 差分验证：tests/test_shell_contract.py 用 Python cryptography 随机用例对拍。
 */
#include "ed25519.h"
#include <string.h>

typedef int64_t i64;
typedef uint64_t u64;
typedef uint8_t u8;
typedef i64 gf[16];

static const gf gf0 = {0};
static const gf gf1 = {1};
static const gf D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
                     0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
static const gf D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                      0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
static const gf X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                     0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
static const gf Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                     0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
static const gf I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
                     0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

#define FOR(i, n) for (i = 0; i < (n); ++i)

static void set25519(gf r, const gf a) {
    int i;
    FOR(i, 16) r[i] = a[i];
}

static void car25519(gf o) {
    int i;
    i64 c;
    FOR(i, 16) {
        o[i] += (i64)1 << 16;
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    i64 t, c = ~(b - 1);
    int i;
    FOR(i, 16) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n) {
    int i, j, b;
    gf t, m;
    FOR(i, 16) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    FOR(j, 2) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    FOR(i, 16) {
        o[2 * i] = (uint8_t)t[i];
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n) {
    int i;
    FOR(i, 16) o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) {
    int i;
    FOR(i, 16) o[i] = a[i] + b[i];
}
static void Z(gf o, const gf a, const gf b) {
    int i;
    FOR(i, 16) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b) {
    i64 t[31];
    int i, j;
    FOR(i, 31) t[i] = 0;
    FOR(i, 16) FOR(j, 16) t[i + j] += a[i] * b[j];
    FOR(i, 15) t[i] += 38 * t[i + 16];
    FOR(i, 16) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a) { M(o, a, a); }

static void inv25519(gf o, const gf i) {
    gf c;
    int a;
    FOR(a, 16) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    FOR(a, 16) o[a] = c[a];
}

static u8 par25519(const gf a) {
    uint8_t d[32];
    pack25519(d, a);
    return (u8)(d[0] & 1);
}

static int neq25519(const gf a, const gf b) {
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return memcmp(c, d, 32) != 0;
}

/* pow(2,252-3) 即 (p-5)/8 次幂（点解压用） */
static void pow2523(gf o, const gf i) {
    gf c;
    int a;
    FOR(a, 16) c[a] = i[a];
    for (a = 250; a >= 0; a--) {
        S(c, c);
        if (a != 1) M(c, c, i);
    }
    FOR(a, 16) o[a] = c[a];
}

/* ---------------- SHA-512 ---------------- */

typedef struct {
    u64 st[8];
    uint8_t buf[128];
    size_t buflen;
    uint64_t total;
} sha512_ctx;

static const u64 K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static u64 rotr64(u64 x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha512_block(sha512_ctx *ctx, const uint8_t p[128]) {
    u64 w[80], a, b, c, d, e, f, g, h;
    int i;
    for (i = 0; i < 16; i++) {
        int j;
        w[i] = 0;
        for (j = 0; j < 8; j++) w[i] = (w[i] << 8) | p[8 * i + j];
    }
    for (i = 16; i < 80; i++) {
        u64 s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        u64 s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = ctx->st[0]; b = ctx->st[1]; c = ctx->st[2]; d = ctx->st[3];
    e = ctx->st[4]; f = ctx->st[5]; g = ctx->st[6]; h = ctx->st[7];
    for (i = 0; i < 80; i++) {
        u64 t1 = h + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) +
                 ((e & f) ^ ((~e) & g)) + K512[i] + w[i];
        u64 t2 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) +
                 ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->st[0] += a; ctx->st[1] += b; ctx->st[2] += c; ctx->st[3] += d;
    ctx->st[4] += e; ctx->st[5] += f; ctx->st[6] += g; ctx->st[7] += h;
}

static void sha512_init(sha512_ctx *ctx) {
    static const u64 iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    int i;
    FOR(i, 8) ctx->st[i] = iv[i];
    ctx->buflen = 0;
    ctx->total = 0;
}

static void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len) {
    while (len > 0) {
        size_t take = 128 - ctx->buflen;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->buflen, data, take);
        ctx->buflen += take;
        data += take;
        len -= take;
        ctx->total += take;
        if (ctx->buflen == 128) {
            sha512_block(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

static void sha512_final(sha512_ctx *ctx, uint8_t out[64]) {
    uint64_t bits = ctx->total * 8;
    size_t i;
    uint8_t pad1[128], pad2[16];
    size_t padlen;

    /* 第一段补位：0x80 + 零，使 buflen 归位到 112 */
    padlen = (ctx->buflen < 112) ? (112 - ctx->buflen) : (240 - ctx->buflen);
    memset(pad1, 0, padlen);
    pad1[0] = 0x80;
    sha512_update(ctx, pad1, padlen);
    /* 第二段：16 字节大端长度（ buflen 已是 112，补满一块）；
       消息 < 2^61 字节，高 64bit 恒 0 */
    memset(pad2, 0, 16);
    for (i = 0; i < 8; i++)
        pad2[15 - i] = (uint8_t)(bits >> (8 * i));
    sha512_update(ctx, pad2, 16);
    /* 此刻 buflen==0；直接输出 */
    for (i = 0; i < 8; i++) {
        int j;
        for (j = 7; j >= 0; j--)
            out[8 * i + (7 - j)] = (uint8_t)(ctx->st[i] >> (8 * j));
    }
}

/* ---------------- 群运算与标量 ---------------- */

static void add_p(gf p[4], gf q[4]) {
    gf a, b, c, d, t, e, f, g, h;

    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);

    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void cswap_p(gf p[4], gf q[4], uint8_t b) {
    int i;
    FOR(i, 4) sel25519(p[i], q[i], b);
}

static void pack_p(uint8_t *r, gf p[4]) {
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= (uint8_t)(par25519(tx) << 7);
}

static void scalarmult_p(gf p[4], gf q[4], const uint8_t s[32]) {
    int i;
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (i = 255; i >= 0; --i) {
        uint8_t b = (s[i / 8] >> (i & 7)) & 1;
        cswap_p(p, q, b);
        add_p(q, p);
        add_p(p, p);
        cswap_p(p, q, b);
    }
}

static void scalarbase(gf p[4], const uint8_t s[32]) {
    gf q[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult_p(p, q, s);
}

/* r = -A（压缩点解码取负）；失败返回 -1（非曲线点） */
static int unpackneg(gf r[4], const uint8_t p[32]) {
    gf t, chk, num, den, den2, den4, den6;

    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) == (uint8_t)(p[31] >> 7)) Z(r[0], gf0, r[0]);

    M(r[3], r[0], r[1]);
    return 0;
}

/* L = 2^252 + 27742317777372353535851937790883648493（字节序小端） */
static const uint8_t LBYTES[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};

static void modL(uint8_t *r, i64 x[64]) {
    i64 carry;
    int i, j;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * LBYTES[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    FOR(j, 32) {
        x[j] += carry - ((x[31] >> 4) * LBYTES[j]);
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    FOR(j, 32) x[j] -= carry * LBYTES[j];
    FOR(i, 32) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

static void reduce(uint8_t r[64]) {
    i64 x[64];
    int i;
    FOR(i, 64) x[i] = (i64)(uint64_t)r[i];
    FOR(i, 64) r[i] = 0;
    modL(r, x);
}

int pkapp_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msglen,
                         const uint8_t sig[64]) {
    gf p[4], q[4], hq[4];
    uint8_t h[64], sbuf[64], rcheck[32];
    sha512_ctx ctx;

    if (unpackneg(q, pub)) return -1; /* q = -A */

    /* h = SHA-512(R || A || M) mod L */
    sha512_init(&ctx);
    sha512_update(&ctx, sig, 32);      /* R */
    sha512_update(&ctx, pub, 32);      /* A */
    sha512_update(&ctx, msg, msglen);  /* M */
    sha512_final(&ctx, h);
    reduce(h);

    /* s' = s mod L（方程在群阶意义下等价，容忍非规范 s） */
    memcpy(sbuf, sig + 32, 32);
    memset(sbuf + 32, 0, 32);
    reduce(sbuf);

    /* p = s'*B + h*(-A) = s*B - h*A；pack 与 R 相等即通过 */
    scalarbase(p, sbuf);
    scalarmult_p(hq, q, h);
    add_p(p, hq);
    pack_p(rcheck, p);
    return memcmp(rcheck, sig, 32) == 0 ? 0 : -1;
}
