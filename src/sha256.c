/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Minimal SHA-256 (FIPS 180-4). Not constant-time; used only to let the
 * receiver verify the bytes it just received match what we hashed. */
#include "sha256.h"
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void wbe32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *c, const uint8_t *b) {
    uint32_t w[64], a, bv, cv, dv, ev, fv, gv, h, t1, t2;
    for (int i = 0; i < 16; i++) w[i] = be32(b + i * 4);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = c->state[0]; bv = c->state[1]; cv = c->state[2]; dv = c->state[3];
    ev = c->state[4]; fv = c->state[5]; gv = c->state[6]; h = c->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR(ev, 6) ^ ROTR(ev, 11) ^ ROTR(ev, 25);
        uint32_t ch = (ev & fv) ^ ((~ev) & gv);
        t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint32_t mj = (a & bv) ^ (a & cv) ^ (bv & cv);
        t2 = S0 + mj;
        h = gv; gv = fv; fv = ev; ev = dv + t1;
        dv = cv; cv = bv; bv = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += bv; c->state[2] += cv; c->state[3] += dv;
    c->state[4] += ev; c->state[5] += fv; c->state[6] += gv; c->state[7] += h;
}

void sha256_init(sha256_ctx *c) {
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
    c->total = 0; c->pos = 0;
}

void sha256_update(sha256_ctx *c, const void *data, size_t n) {
    const uint8_t *p = data;
    c->total += n;
    while (n) {
        size_t t = 64 - c->pos;
        if (t > n) t = n;
        memcpy(c->buf + c->pos, p, t);
        c->pos += t; p += t; n -= t;
        if (c->pos == 64) { sha256_block(c, c->buf); c->pos = 0; }
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    c->buf[c->pos++] = 0x80;
    if (c->pos > 56) {
        while (c->pos < 64) c->buf[c->pos++] = 0;
        sha256_block(c, c->buf); c->pos = 0;
    }
    while (c->pos < 56) c->buf[c->pos++] = 0;
    for (int i = 7; i >= 0; i--) c->buf[c->pos++] = (bits >> (i * 8)) & 0xff;
    sha256_block(c, c->buf);
    for (int i = 0; i < 8; i++) wbe32(out + i * 4, c->state[i]);
}

void sha256_hex(const uint8_t digest[32], char out[65]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2*i]     = hx[digest[i] >> 4];
        out[2*i + 1] = hx[digest[i] & 0x0f];
    }
    out[64] = '\0';
}
