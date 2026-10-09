#include "sentinel.h"
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static int read_hex32(const char *hex, unsigned char out[32])
{
    size_t i;
    if (strlen(hex) != 64U)
        return -1;
    for (i = 0; i < 32U; ++i) {
        unsigned int v;
        if (sscanf(hex + i * 2U, "%2x", &v) != 1 || v > 255U)
            return -1;
        out[i] = (unsigned char)v;
    }
    return 0;
}

static int file_digest(const char *path, unsigned char digest[32])
{
    char hex[SLX_HASH_HEX];
    slx_sha256_file(path, hex);
    return read_hex32(hex, digest);
}

static int key_is_ed25519(EVP_PKEY *pkey)
{
    return pkey != NULL && EVP_PKEY_base_id(pkey) == EVP_PKEY_ED25519;
}

static int sign_digest(const unsigned char digest[32], const char *keyfile, unsigned char sig[64],
size_t *siglen)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int rc = -1;
    bio = BIO_new_file(keyfile, "rb");
    if (bio == NULL)
        goto out;
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!key_is_ed25519(pkey))
        goto out;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto out;
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1)
        goto out;
    *siglen = 64U;
    if (EVP_DigestSign(ctx, sig, siglen, digest, 32U) != 1)
        goto out;
    rc = *siglen == 64U ? 0 : -1;
    out:
        EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return rc;
}

static int verify_digest(const unsigned char digest[32], const unsigned char sig[64], const char *
keyfile)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int rc = -1;
    bio = BIO_new_file(keyfile, "rb");
    if (bio == NULL)
        goto out;
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!key_is_ed25519(pkey))
        goto out;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto out;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1)
        goto out;
    rc = EVP_DigestVerify(ctx, sig, 64U, digest, 32U) == 1 ? 0 : -1;
    out:
        EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return rc;
}

static int signature_path(const char *path, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s.sig", path);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

int slx_sign_artifact(const char *path)
{
    const char *key = getenv("SLX_SIGNING_KEY");
    unsigned char digest[32];
    unsigned char sig[64];
    size_t siglen = 0U;
    char outpath[SLX_PATH_MAX];
    FILE *f = NULL;
    int rc = -1;
    if (key == NULL || *key == '\0')
        return 0;
    if (file_digest(path, digest) != 0 || sign_digest(digest, key, sig, &siglen) != 0)
        return -1;
    if (signature_path(path, outpath, sizeof(outpath)) != 0)
        return -1;
    f = fopen(outpath, "wb");
    if (f == NULL)
        return -1;
    if (fchmod(fileno(f), 0400) != 0)
        goto out;
    if (fwrite(sig, 1, siglen, f) != siglen)
        goto out;
    if (fflush(f) != 0)
        goto out;
    if (fsync(fileno(f)) != 0)
        goto out;
    rc = 0;
    out:
        if (f != NULL)
            fclose(f);
    if (rc != 0)
        (void)unlink(outpath);
    return rc;
}

int slx_verify_artifact(const char *path)
{
    const char *key = getenv("SLX_VERIFY_KEY");
    unsigned char digest[32];
    unsigned char sig[64];
    char sigpath[SLX_PATH_MAX];
    FILE *f;
    if (key == NULL || *key == '\0')
        return 0;
    if (file_digest(path, digest) != 0 || signature_path(path, sigpath, sizeof(sigpath)) != 0)
        return -1;
    f = fopen(sigpath, "rb");
    if (f == NULL)
        return -1;
    if (fread(sig, 1, sizeof(sig), f) != sizeof(sig) || fgetc(f) != EOF) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return verify_digest(digest, sig, key);
}
