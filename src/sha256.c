#include "sentinel.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32U - n));
}

static const uint32_t k[64] = {
    0x428a2f98U,
    0x71374491U,
    0xb5c0fbcfU,
    0xe9b5dba5U,
    0x3956c25bU,
    0x59f111f1U,
    0x923f82a4U,
    0xab1c5ed5U,
    0xd807aa98U,
    0x12835b01U,
    0x243185beU,
    0x550c7dc3U,
    0x72be5d74U,
    0x80deb1feU,
    0x9bdc06a7U,
    0xc19bf174U,
    0xe49b69c1U,
    0xefbe4786U,
    0x0fc19dc6U,
    0x240ca1ccU,
    0x2de92c6fU,
    0x4a7484aaU,
    0x5cb0a9dcU,
    0x76f988daU,
    0x983e5152U,
    0xa831c66dU,
    0xb00327c8U,
    0xbf597fc7U,
    0xc6e00bf3U,
    0xd5a79147U,
    0x06ca6351U,
    0x14292967U,
    0x27b70a85U,
    0x2e1b2138U,
    0x4d2c6dfcU,
    0x53380d13U,
    0x650a7354U,
    0x766a0abbU,
    0x81c2c92eU,
    0x92722c85U,
    0xa2bfe8a1U,
    0xa81a664bU,
    0xc24b8b70U,
    0xc76c51a3U,
    0xd192e819U,
    0xd6990624U,
    0xf40e3585U,
    0x106aa070U,
    0x19a4c116U,
    0x1e376c08U,
    0x2748774cU,
    0x34b0bcb5U,
    0x391c0cb3U,
    0x4ed8aa4aU,
    0x5b9cca4fU,
    0x682e6ff3U,
    0x748f82eeU,
    0x78a5636fU,
    0x84c87814U,
    0x8cc70208U,
    0x90befffaU,
    0xa4506cebU,
    0xbef9a3f7U,
    0xc67178f2U
};
static void transform(struct slx_sha256 *c, const uint8_t b[64])
{
    uint32_t w[64];
    uint32_t a, bv, d, e, f, g, h, cc;
    size_t i;
    for (i = 0; i < 16; ++i) {
        size_t j = i * 4U;
        w[i] = ((uint32_t)b[j] << 24) | ((uint32_t)b[j + 1] << 16) | ((uint32_t)b[j + 2] << 8) | (uint32_t)b
        [j + 3];
    }
    for (i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0];
    bv = c->h[1];
    cc = c->h[2];
    d = c->h[3];
    e = c->h[4];
    f = c->h[5];
    g = c->h[6];
    h = c->h[7];
    for (i = 0; i < 64; ++i) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & bv) ^ (a & cc) ^ (bv & cc);
        uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = bv;
        bv = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += bv;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;
}

void slx_sha256_init(struct slx_sha256 *c)
{
    c->h[0] = 0x6a09e667U;
    c->h[1] = 0xbb67ae85U;
    c->h[2] = 0x3c6ef372U;
    c->h[3] = 0xa54ff53aU;
    c->h[4] = 0x510e527fU;
    c->h[5] = 0x9b05688cU;
    c->h[6] = 0x1f83d9abU;
    c->h[7] = 0x5be0cd19U;
    c->bits = 0;
    c->used = 0;
}

void slx_sha256_update(struct slx_sha256 *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->bits += (uint64_t)len * 8U;
    while (len > 0U) {
        size_t n = 64U - c->used;
        if (n > len)
            n = len;
        memcpy(c->block + c->used, p, n);
        c->used += n;
        p += n;
        len -= n;
        if (c->used == 64U) {
            transform(c, c->block);
            c->used = 0;
        }
    }
}

void slx_sha256_final(struct slx_sha256 *c, uint8_t out[32])
{
    size_t i;
    uint64_t bits = c->bits;
    c->block[c->used++] = 0x80U;
    if (c->used > 56U) {
        while (c->used < 64U)
            c->block[c->used++] = 0;
        transform(c, c->block);
        c->used = 0;
    } while (c->used < 56U)
        c->block[c->used++] = 0;
    for (i = 0; i < 8; ++i)
        c->block[56U + i] = (uint8_t)(bits >> (56U - 8U *i));
    transform(c, c->block);
    for (i = 0; i < 8; ++i) {
        out[i * 4U] = (uint8_t)(c->h[i] >> 24);
        out[i * 4U + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4U + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4U + 3] = (uint8_t)c->h[i];
    }
}

void slx_sha256_file(const char *path, char out_hex[SLX_HASH_HEX])
{
    static const char hex[] = "0123456789abcdef";
    struct slx_sha256 c;
    uint8_t buf[8192], digest[32];
    ssize_t n;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    size_t i;
    memset(out_hex, '0', SLX_HASH_HEX);
    out_hex[64] = '\0';
    if (fd < 0)
        return;
    slx_sha256_init(&c);
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        slx_sha256_update(&c, buf, (size_t)n);
    if (n < 0) {
        close(fd);
        return;
    }
    slx_sha256_final(&c, digest);
    close(fd);
    for (i = 0; i < 32; i++) {
        out_hex[i * 2U] = hex[digest[i] >> 4];
        out_hex[i * 2U + 1] = hex[digest[i] & 15U];
    }
}
