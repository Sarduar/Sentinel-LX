#include "sentinel.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#define RECEIVE_MAX_BYTES (64U * 1024U * 1024U)
#define RECEIVE_IO_TIMEOUT_SEC 30
#define RECEIVE_MAX_CLIENTS 16U
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

static int secure_dir(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
        return -1;
    if (st.st_uid != geteuid() || (st.st_mode & 077U) != 0)
        return -1;
    return 0;
}

static int set_socket_timeouts(int fd)
{
    struct timeval tv;
    tv.tv_sec = RECEIVE_IO_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
        return -1;
    return 0;
}

static int client_fingerprint_ok(X509 *cert, const char *wanted)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    char hex[65];
    static const char d[] = "0123456789abcdef";
    if (X509_digest(cert, EVP_sha256(), digest, &len) != 1 || len != 32U)
        return -1;
    for (size_t i = 0; i < 32U; i++) {
        hex[i * 2U] = d[digest[i] >> 4];
        hex[i * 2U + 1U] = d[digest[i] & 15U];
    }
    hex[64] = '\0';
    return strcmp(hex, wanted) == 0 ? 0 : -1;
}

static int open_listener(const char *bind_addr, const char *port)
{
    struct addrinfo hints, *res = NULL, *it;
    int fd = -1, one = 1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(bind_addr && *bind_addr ? bind_addr : NULL, port, &hints, &res) != 0)
        return -1;
    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, it->ai_addr, it->ai_addrlen) == 0 && listen(fd, 16) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
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

static int ssl_write_all(SSL *ssl, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    while (len) {
        int n = SSL_write(ssl, p, (int)(len > 1048576U ? 1048576U : len));
        if (n <= 0)
            return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_exact(SSL *ssl, FILE *f, uint64_t total)
{
    unsigned char buf[16384];
    uint64_t left = total;
    while (left) {
        size_t want = left > sizeof(buf) ? sizeof(buf) :(size_t)left;
        int n = SSL_read(ssl, buf, (int)want);
        if (n <= 0)
            return -1;
        if (fwrite(buf, 1, (size_t)n, f) != (size_t)n)
            return -1;
        left -= (uint64_t)n;
    }
    return 0;
}

static int hex_signature(const char *hex, unsigned char sig[64])
{
    size_t i;
    if (strlen(hex) != 128U)
        return -1;
    for (i = 0; i < 64U; i++) {
        unsigned int v;
        if (sscanf(hex + i * 2U, "%2x", &v) != 1 || v > 255U)
            return -1;
        sig[i] = (unsigned char)v;
    }
    return 0;
}

static int parse_header(const char *line, uint64_t *size, unsigned char sig[64], int *has_sig)
{
    unsigned long long v = 0;
    char hex[129];
    char extra;
    int n;
    *has_sig = 0;
    n = sscanf(line, "SLX/2 %llu %128s %c", &v, hex, &extra);
    if (n == 2) {
        if (hex_signature(hex, sig) != 0)
            return -1;
        *has_sig = 1;
    } else {
        n = sscanf(line, "SLX/1 %llu %c", &v, &extra);
        if (n != 1)
            return -1;
    }
    if (v == 0ULL || v > RECEIVE_MAX_BYTES)
        return -1;
    *size = (uint64_t)v;
    return 0;
}

static int store_capsule(const char *tmp, const char *sig_tmp, const char *store, char out_hash[65])
{
    char final[SLX_PATH_MAX];
    char final_sig[SLX_PATH_MAX];
    struct stat st;
    if (slx_incident_verify(tmp) != 0)
        return -1;
    slx_sha256_file(tmp, out_hash);
    if (stat(tmp, &st) != 0 || !S_ISREG(st.st_mode) || secure_dir(store) != 0)
        return -1;
    {
        int n = snprintf(final, sizeof(final), "%s/%s.jsonl", store, out_hash);
        if (n < 0 || (size_t)n >= sizeof(final))
            return -1;
        n = snprintf(final_sig, sizeof(final_sig), "%s/%s.jsonl.sig", store, out_hash);
        if (n < 0 || (size_t)n >= sizeof(final_sig))
            return -1;
    }
    if (link(tmp, final) != 0) {
        if (errno == EEXIST) {
            (void)unlink(tmp);
            if (sig_tmp)
                (void)unlink(sig_tmp);
            return 0;
        }
        return -1;
    }
    if (sig_tmp != NULL) {
        if (link(sig_tmp, final_sig) != 0) {
            (void)unlink(final);
            (void)unlink(tmp);
            return -1;
        }
        (void)unlink(sig_tmp);
    }
    (void)unlink(tmp);
    return 0;
}

static int handle_client(SSL_CTX *ctx, int client, const char *tmpdir, const char *store, const char
*client_sha256, int listener)
{
    SSL *ssl = NULL;
    X509 *peer = NULL;
    char line[192];
    uint64_t size;
    unsigned char sig[64];
    int has_sig = 0;
    char tmp[SLX_PATH_MAX];
    char sig_tmp[SLX_PATH_MAX];
    FILE *f = NULL;
    FILE *sf = NULL;
    char hash[65];
    int rc = 1;
    close(listener);
    if (set_socket_timeouts(client) != 0)
        goto out;
    ssl = SSL_new(ctx);
    if (!ssl)
        goto out;
    (void)SSL_set_fd(ssl, client);
    if (SSL_accept(ssl) != 1)
        goto out;
    peer = SSL_get_peer_certificate(ssl);
    if (peer == NULL || client_fingerprint_ok(peer, client_sha256) != 0)
        goto out;
    X509_free(peer);
    peer = NULL;
    if (ssl_read_line(ssl, line, sizeof(line)) != 0 || parse_header(line, &size, sig, &has_sig) != 0)
    goto out;
    if (snprintf(tmp, sizeof(tmp), "%s/.slx-XXXXXX", tmpdir) < 0)
        goto out;
    {
        int tfd = mkstemp(tmp);
        if (tfd < 0)
            goto out;
        f = fdopen(tfd, "wb");
        if (!f) {
            close(tfd);
            (void)unlink(tmp);
            goto out;
        }
    }
    if (read_exact(ssl, f, size) != 0 || fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        f = NULL;
        (void)unlink(tmp);
        goto out;
    }
    fclose(f);
    f = NULL;
    sig_tmp[0] = '\0';
    if (has_sig) {
        int n = snprintf(sig_tmp, sizeof(sig_tmp), "%s.sig", tmp);
        if (n < 0 || (size_t)n >= sizeof(sig_tmp))
            goto out;
        sf = fopen(sig_tmp, "wb");
        if (sf == NULL)
            goto out;
        if (fwrite(sig, 1, sizeof(sig), sf) != sizeof(sig) || fflush(sf) != 0 || fsync(fileno(sf)) != 0) {
            fclose(sf);
            sf = NULL;
            (void)unlink(sig_tmp);
            goto out;
        }
        fclose(sf);
        sf = NULL;
    }
    if (store_capsule(tmp, has_sig ? sig_tmp : NULL, store, hash) != 0) {
        (void)unlink(tmp);
        if (sig_tmp[0])
            (void)unlink(sig_tmp);
        goto out;
    }
    {
        char reply[96];
        int n = snprintf(reply, sizeof(reply), "OK %s\n", hash);
        if (n > 0)
            (void)ssl_write_all(ssl, reply, (size_t)n);
    }
    printf("stored hash=%s size=%llu pid=%ld\n", hash, (unsigned long long)size, (long)getpid());
    rc = 0;
    out:
        if (peer)
            X509_free(peer);
    if (f)
        fclose(f);
    if (sf)
        fclose(sf);
    if (ssl) {
        (void)SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(client);
    return rc;
}

int slx_receive_server(void)
{
    const char *bind_addr = getenv("SLX_RECEIVE_BIND");
    const char *port, *ca, *cert, *key, *store, *client_sha256;
    const char *tmpdir = getenv("SLX_RECEIVE_TMP");
    int listener = -1;
    SSL_CTX *ctx = NULL;
    unsigned clients = 0U;
    int rc = -1;
    if (env_required("SLX_RECEIVE_PORT", &port) != 0 || env_required("SLX_RECEIVE_CA", &ca) != 0 ||
    env_required("SLX_RECEIVE_CERT", &cert) != 0 || env_required("SLX_RECEIVE_KEY", &key) != 0 ||
    env_required("SLX_RECEIVE_STORE", &store) != 0 || env_required("SLX_RECEIVE_CLIENT_SHA256", &
    client_sha256) != 0) return -1;
    if (tmpdir == NULL || *tmpdir == '\0')
        tmpdir = store;
    (void)OPENSSL_init_ssl(0, NULL);
    if (mkdir(store, 0700) != 0 && errno != EEXIST)
        return -1;
    if (secure_dir(store) != 0)
        return -1;
    if (mkdir(tmpdir, 0700) != 0 && errno != EEXIST)
        return -1;
    if (secure_dir(tmpdir) != 0)
        return -1;
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        goto out;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1)
        goto out;
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1)
        goto out;
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1)
        goto out;
    if (SSL_CTX_check_private_key(ctx) != 1)
        goto out;
    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1)
        goto out;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    listener = open_listener(bind_addr, port);
    if (listener < 0)
        goto out;
    fprintf(stdout, "receiver listening port=%s store=%s max_clients=%u\n", port, store,
    RECEIVE_MAX_CLIENTS);
    fflush(stdout);
    for (; ; ) {
        int status;
        pid_t dead;
        while ((dead = waitpid(-1, &status, WNOHANG)) > 0) {
            if (clients > 0U)
                --clients;
        }
        {
            int client = accept(listener, NULL, NULL);
            if (client < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (clients >= RECEIVE_MAX_CLIENTS) {
                static const char busy[] = "BUSY\n";
                (void)write(client, busy, sizeof(busy) - 1U);
                close(client);
                continue;
            }
            {
                pid_t pid = fork();
                if (pid < 0) {
                    close(client);
                    continue;
                }
                if (pid == 0) {
                    int child_rc = handle_client(ctx, client, tmpdir, store, client_sha256, listener);
                    SSL_CTX_free(ctx);
                    _exit(child_rc == 0 ? 0 : 1);
                }
                close(client);
                ++clients;
            }
        }
    }
    rc = 0;
    out:
        if (listener >= 0)
            close(listener);
    if (ctx)
        SSL_CTX_free(ctx);
    return rc;
}
