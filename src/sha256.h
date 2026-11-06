/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Minimal SHA-256 (FIPS 180-4). Embedded so the on-console payload has
 * no link dependency on libcrypto. */
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t total;
    size_t   pos;
    uint8_t  buf[64];
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t n);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256_hex(const uint8_t digest[32], char out[65]);
