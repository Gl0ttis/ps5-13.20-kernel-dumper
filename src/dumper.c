/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Console payload. Connects to the host receiver and streams the pages
 * named by the operator's independently validated layout, in layout
 * order, as hello / page* / eof.
 *
 * WARNING: SDK kernel_copyout mutates kernel pipe metadata on every
 * call. A full capture executes one call per listed page across every
 * range, so pipe-metadata churn scales with layout size. Validate that
 * side effect separately before deployment; this payload does not
 * attempt to mitigate it. The receiver verifies every page by SHA-256
 * before checkpointing; a mid-session disconnect leaves the receiver's
 * checkpoint intact and the operator can retry the same layout. */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <ps5/kernel.h>

#include "layout.h"
#include "sha256.h"

#ifndef RECEIVER_HOST
#define RECEIVER_HOST "127.0.0.1"
#endif
#ifndef RECEIVER_PORT
#define RECEIVER_PORT 8888
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int sock = -1;

static int send_all(const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len) {
        ssize_t n = send(sock, p, len, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_fmt(const char *fmt, ...) {
    /* Receiver caps a JSON header line at 8192 bytes; our page headers
     * are well under that, so a small stack buffer is enough. */
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(line)) return -1;
    return send_all(line, (size_t)n);
}

static uint8_t page_buf[LAYOUT_PAGE_SIZE];

static int dump_page(uint64_t addr) {
    int32_t rv = kernel_copyout((intptr_t)addr, page_buf, LAYOUT_PAGE_SIZE);
    if (rv != 0) {
        /* The receiver rejects status=error with errno=0, so pick a
         * positive sentinel if neither the SDK return value nor errno
         * carries one. */
        int e = rv > 0 ? rv : (errno > 0 ? errno : 5 /* EIO */);
        return send_fmt(
            "{\"type\":\"page\",\"addr\":%llu,\"length\":%u,"
            "\"status\":\"error\",\"errno\":%d,\"sha256\":null}\n",
            (unsigned long long)addr, (unsigned)LAYOUT_PAGE_SIZE, e);
    }

    sha256_ctx c;
    uint8_t digest[32];
    char hex[65];
    sha256_init(&c);
    sha256_update(&c, page_buf, LAYOUT_PAGE_SIZE);
    sha256_final(&c, digest);
    sha256_hex(digest, hex);

    if (send_fmt(
            "{\"type\":\"page\",\"addr\":%llu,\"length\":%u,"
            "\"status\":\"ok\",\"errno\":0,\"sha256\":\"%s\"}\n",
            (unsigned long long)addr, (unsigned)LAYOUT_PAGE_SIZE, hex) != 0)
        return -1;
    return send_all(page_buf, LAYOUT_PAGE_SIZE);
}

int main(void) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(RECEIVER_PORT);
    if (inet_pton(AF_INET, RECEIVER_HOST, &addr.sin_addr) != 1) return 1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 2;
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return 3;
    }

    if (send_all(LAYOUT_HELLO_LINE, LAYOUT_HELLO_LINE_LEN) != 0) {
        close(sock);
        return 4;
    }

    /* Optional: skip pages whose address is strictly less than
     * RESUME_FROM. Pass -DRESUME_FROM=0x... at build time to resume
     * a prior partial session; the receiver dedups by addr so no
     * conflict with already-captured earlier pages. */
#ifndef RESUME_FROM
#define RESUME_FROM 0
#endif
    for (unsigned i = 0; i < LAYOUT_RANGE_COUNT; i++) {
        uint64_t start  = LAYOUT_RANGES[i].start;
        uint64_t length = LAYOUT_RANGES[i].length;
        for (uint64_t off = 0; off < length; off += LAYOUT_PAGE_SIZE) {
            uint64_t addr = start + off;
            if (addr < (uint64_t)RESUME_FROM) continue;
            if (dump_page(addr) != 0) {
                close(sock);
                return 5;
            }
        }
    }

    if (send_all("{\"type\":\"eof\"}\n", 15) != 0) {
        close(sock);
        return 6;
    }
    close(sock);
    return 0;
}
