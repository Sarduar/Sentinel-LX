#include "sentinel.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#define SHIP_MAX_BYTES (64U * 1024U * 1024U)
#define SHIP_IO_TIMEOUT_SEC 30
#define SHIP_CONNECT_TIMEOUT_SEC 10
static int env_required(const char *name, const char **out)
{
    const char *v = getenv(name);
    if (v == NULL || *v == '\0') {
        fprintf(stderr, "missing environment variable: %s\n", name);
        return -1;
    }
    *out = v;
    return 0;
}

static int wait_connect(int fd)
{
    struct pollfd p;
    int err = 0;
    socklen_t len = sizeof(err);
    p.fd = fd;
    p.events = POLLOUT;
    p.revents = 0;
    if (poll(&p, 1, SHIP_CONNECT_TIMEOUT_SEC * 1000) <= 0)
        return -1;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0)
        return -1;
    return 0;
}

static int open_connection(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    int fd = -1;
    int flags;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    for (it = res; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0 || (errno == EINPROGRESS && wait_connect(fd) == 0)) {
            if (fcntl(fd, F_SETFL, flags) == 0)
                break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int set_socket_timeouts(int fd)
{
    struct timeval tv;
    tv.tv_sec = SHIP_IO_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
        return -1;
    return 0;
}

static int ssl_write_all(SSL *ssl, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    while (len > 0U) {
        int n = SSL_write(ssl, p, (int)(len > 1048576U ? 1048576U : len));
        if (n <= 0)
            return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int ssl_read_line(SSL *ssl, char *out, size_t cap)
{
    size_t n = 0;
    while (n + 1U < cap) {
        char c;
        int r = SSL_read(ssl, &c, 1);
        if (r <= 0)
            return -1;
        out[n++] = c;
        if (c == '\n') {
            out[n] = '\0';
            return 0;
        }
    }
    return -1;
}

static int read_signature_hex(const char *path, char out[129])
{
    char sigpath[SLX_PATH_MAX];
    FILE *f;
    unsigned char sig[64];
    size_t i;
    static const char hex[] = "0123456789abcdef";
    int n = snprintf(sigpath, sizeof(sigpath), "%s.sig", path);
    if (n < 0 || (size_t)n >= sizeof(sigpath))
        return -1;
    f = fopen(sigpath, "rb");
    if (f == NULL)
        return -1;
    if (fread(sig, 1, sizeof(sig), f) != sizeof(sig) || fgetc(f) != EOF) {
        fclose(f);
        return -1;
    }
    fclose(f);
    for (i = 0; i < sizeof(sig); i++) {
        out[i * 2U] = hex[sig[i] >> 4];
        out[i * 2U + 1U] = hex[sig[i] & 15U];
    }
    out[128] = '\0';
    return 0;
}

static int send_file(SSL *ssl, const char *path, uint64_t size)
{
    FILE *f = fopen(path, "rb");
    unsigned char buf[16384];
    if (f == NULL)
        return -1;
    while (size > 0U) {
        size_t want = size > sizeof(buf) ? sizeof(buf) :(size_t)size;
        size_t n = fread(buf, 1, want, f);
        if (n == 0U || ssl_write_all(ssl, buf, n) != 0) {
            fclose(f);
            return -1;
        }
        size -= (uint64_t)n;
    }
    fclose(f);
    return 0;
}

int slx_ship_file(const char *path)
{
    const char *host;
    const char *port;
    const char *ca;
    const char *cert;
    const char *key;
    const char *server_name;
    struct stat st;
    int fd = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int rc = -1;
    char reply[256];
    if (env_required("SLX_SHIP_HOST", &host) != 0 || env_required("SLX_SHIP_PORT", &port) != 0 ||
    env_required("SLX_SHIP_CA", &ca) != 0 || env_required("SLX_SHIP_CERT", &cert) != 0 || env_required(
    "SLX_SHIP_KEY", &key) != 0 || env_required("SLX_SHIP_SERVER_NAME", &server_name) != 0) return -1;
    if (stat(path, &st) != 0 || st.st_size < 0 || (uint64_t)st.st_size > SHIP_MAX_BYTES) {
        fprintf(stderr, "invalid capsule size: %s\n", path);
        return -1;
    }
    if (getenv("SLX_VERIFY_KEY") != NULL && slx_verify_artifact(path) != 0) {
        fprintf(stderr, "capsule signature verification failed: %s\n", path);
        return -1;
    }
    (void)OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        goto out;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1)
        goto out;
    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1)
        goto out;
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1)
        goto out;
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1)
        goto out;
    if (SSL_CTX_check_private_key(ctx) != 1)
        goto out;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    fd = open_connection(host, port);
    if (fd < 0 || set_socket_timeouts(fd) != 0)
        goto out;
    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto out;
    if (SSL_set_fd(ssl, fd) != 1)
        goto out;
    if (SSL_set_tlsext_host_name(ssl, server_name) != 1)
        goto out;
    if (SSL_set1_host(ssl, server_name) != 1)
        goto out;
    if (SSL_connect(ssl) != 1)
        goto out;
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        goto out;
    {
        char header[192];
        char sighex[129];
        int n;
        int has_sig = read_signature_hex(path, sighex) == 0;
        if (!has_sig && getenv("SLX_SHIP_REQUIRE_SIGNATURE") != NULL && strcmp(getenv(
        "SLX_SHIP_REQUIRE_SIGNATURE"), "1") == 0) goto out;
        n = has_sig ? snprintf(header, sizeof(header), "SLX/2 %llu %s\n", (unsigned long long)st.st_size,
        sighex) : snprintf(header, sizeof(header), "SLX/1 %llu\n", (unsigned long long)st.st_size);
        if (n < 0 || (size_t)n >= sizeof(header))
            goto out;
        if (ssl_write_all(ssl, header, (size_t)n) != 0)
            goto out;
    }
    if (send_file(ssl, path, (uint64_t)st.st_size) != 0)
        goto out;
    if (ssl_read_line(ssl, reply, sizeof(reply)) != 0)
        goto out;
    if (strncmp(reply, "OK ", 3) != 0)
        goto out;
    printf("shipped capsule=%s response=%s", path, reply);
    rc = 0;
    out:
        if (rc != 0)
            fprintf(stderr, "ship failed for %s\n", path);
    if (ssl != NULL) {
        (void)SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (fd >= 0)
        close(fd);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    return rc;
}
