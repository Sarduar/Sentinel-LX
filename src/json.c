#include "sentinel.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int journal_fd = -1;
static int journal_lock_fd = -1;
static uint64_t next_event_id;
static char journal_path[SLX_PATH_MAX];
static char prev_hash[65] = "0000000000000000000000000000000000000000000000000000000000000000";
static const char *etype(enum slx_event_type t)
{
    switch (t) {
        case SLX_EV_FIM:
        return "fim";
        case SLX_EV_PROC:
        return "process";
        case SLX_EV_NET:
        return "network";
        case SLX_EV_AI:
        return "ai";
        case SLX_EV_OVERFLOW:
        return "overflow";
        default:
        return "unknown";
    }
}

static int esc(char *out, size_t cap, const char *s)
{
    size_t u = 0, i;
    for (i = 0; s[i]; i++) {
        char tmp[8];
        const char *r = tmp;
        switch ((unsigned char)s[i]) {
            case '"':
            r = "\\\"";
            break;
            case '\\':
            r = "\\\\";
            break;
            case '\n':
            r = "\\n";
            break;
            case '\r':
            r = "\\r";
            break;
            case '\t':
            r = "\\t";
            break;
            default:
            if ((unsigned char)s[i] < 0x20U)
                snprintf(tmp, sizeof(tmp), "\\u%04x", (unsigned char)s[i]);
            else
            {
                tmp[0] = s[i];
                tmp[1] = 0;
            }
            break;
        }
        size_t n = strlen(r);
        if (u + n + 1 >= cap)
            return -1;
        memcpy(out + u, r, n);
        u += n;
    }
    out[u] = 0;
    return (int)u;
}

int slx_json_event(const struct slx_event *e, char *out, size_t cap)
{
    char s[8192], v[2048], t[1024], pi[256], ppi[256];
    if (esc(s, sizeof(s), e->subject) < 0 || esc(v, sizeof(v), e->evidence) < 0 || esc(t, sizeof(t), e->tags)
    < 0 || esc(pi, sizeof(pi), e->proc_id) < 0 || esc(ppi, sizeof(ppi), e->parent_proc_id) < 0) return -
    1;
    return snprintf(out, cap,
    "{\"event_id\":%llu,\"cause_id\":%llu,\"exec_id\":%llu,\"parent_exec_id\":%llu,\"proc_id\":\"%s\",\"parent_proc_id\":\"%s\",\"ts_ns\":%llu,\"type\":\"%s\",\"score\":%d,\"pid\":%ld,\"ppid\":%ld,\"uid\":%ld,\"subject\":\"%s\",\"evidence\":\"%s\",\"tags\":\"%s\"}\n",
    (unsigned long long)e->event_id, (unsigned long long)e->cause_id, (unsigned long long)e->exec_id, (
    unsigned long long)e->parent_exec_id, pi, ppi, (unsigned long long)e->ts_ns, etype(e->type), e->score,
    (long)e->pid, (long)e->ppid, (long)e->uid, s, v, t);
}

static void hash_line(const char *line, const char *prev, char out[65])
{
    struct slx_sha256 c;
    uint8_t d[32];
    static const char *x = "0123456789abcdef";
    slx_sha256_init(&c);
    slx_sha256_update(&c, prev, 64);
    slx_sha256_update(&c, line, strlen(line));
    slx_sha256_final(&c, d);
    for (size_t i = 0; i < 32; i++) {
        out[i * 2] = x[d[i] >> 4];
        out[i * 2 + 1] = x[d[i] & 15];
    }
    out[64] = 0;
}

static int recover_prev_hash(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[16384];
    char last[65];
    if (!f)
        return 0;
    last[0] = '\0';
    while (fgets(line, sizeof(line), f)) {
        const char *k = "\"event_hash\":\"";
        char *p = strstr(line, k);
        if (p) {
            p += strlen(k);
            if (strlen(p) >= 64U) {
                memcpy(last, p, 64U);
                last[64] = '\0';
                if (strspn(last, "0123456789abcdef") == 64U)
                    memcpy(prev_hash, last, 65U);
            }
        }
        k = "\"event_id\":";
        p = strstr(line, k);
        if (p) {
            p += strlen(k);
            char *end = NULL;
            unsigned long long v = strtoull(p, &end, 10);
            if (end != p && v >= next_event_id)
                next_event_id = (uint64_t)v + 1ULL;
        }
    }
    fclose(f);
    return 0;
}

const char *slx_journal_path(void)
{
    if (journal_path[0])
        return journal_path;
    const char *env = getenv("SLX_JOURNAL");
    return env && *env ? env : SLX_JOURNAL_DEFAULT;
}

int slx_journal_init(void)
{
    const char *env = getenv("SLX_JOURNAL");
    struct stat st;
    (void)snprintf(journal_path, sizeof(journal_path), "%s", env && *env ? env : SLX_JOURNAL_DEFAULT);
    journal_fd = open(journal_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (journal_fd < 0)
        return -1;
    if (fstat(journal_fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 0077U) != 0) {
        close(journal_fd);
        journal_fd = -1;
        errno = EPERM;
        return -1;
    }
    if (flock(journal_fd, LOCK_EX | LOCK_NB) != 0) {
        close(journal_fd);
        journal_fd = -1;
        return -1;
    }
    journal_lock_fd = journal_fd;
    if (st.st_size > 0) {
        if (slx_journal_verify(journal_path) != 0) {
            flock(journal_fd, LOCK_UN);
            close(journal_fd);
            journal_fd = -1;
            journal_lock_fd = -1;
            errno = EILSEQ;
            return -1;
        }
    }
    (void)recover_prev_hash(journal_path);
    return 0;
}

void slx_journal_close(void)
{
    if (journal_fd >= 0) {
        (void)fsync(journal_fd);
        if (journal_lock_fd >= 0)
            flock(journal_lock_fd, LOCK_UN);
        close(journal_fd);
        journal_fd = -1;
        journal_lock_fd = -1;
    }
}

uint64_t slx_journal_last_event_id(void)
{
    return next_event_id ? next_event_id - 1ULL : 0;
}

uint64_t slx_journal_next_event_id(void)
{
    return next_event_id ? next_event_id : 1ULL;
}

static int write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

int slx_journal_append(const struct slx_event *e)
{
    char line[12288], wrapped[14000], h[65];
    int n, m;
    struct slx_event tmp;
    if (journal_fd < 0 && slx_journal_init() != 0)
        return -1;
    tmp = *e;
    if (tmp.event_id == 0)
        tmp.event_id = slx_journal_next_event_id();
    n = slx_json_event(&tmp, line, sizeof(line));
    if (n < 0 || (size_t)n >= sizeof(line))
        return -1;
    hash_line(line, prev_hash, h);
    m = snprintf(wrapped, sizeof(wrapped),
    "{\"prev_hash\":\"%s\",\"event\":%.*s,\"event_hash\":\"%s\"}\n", prev_hash, n - 1, line, h);
    if (m < 0 || (size_t)m >= sizeof(wrapped))
        return -1;
    if (write_all(journal_fd, wrapped, (size_t)m) != 0)
        return -1;
    if (fsync(journal_fd) != 0)
        return -1;
    memcpy(prev_hash, h, 65);
    next_event_id = tmp.event_id + 1ULL;
    slx_ring_push(&tmp);
    return 0;
}

int slx_journal_verify(const char *path)
{
    FILE *f;
    char line[16384];
    char prev[65] = "0000000000000000000000000000000000000000000000000000000000000000";
    uint64_t count = 0U;
    uint64_t next_id = 1U;
    if (path == NULL || *path == '\0')
        return -1;
    f = fopen(path, "r");
    if (f == NULL)
        return -1;
    while (fgets(line, sizeof(line), f) != NULL) {
        const char *pk = "{\"prev_hash\":\"";
        const char *ek = "\",\"event\":";
        const char *hk = ",\"event_hash\":\"";
        const char *p = strstr(line, pk);
        const char *e = strstr(line, ek);
        const char *h = strstr(line, hk);
        const char *idp = strstr(line, "\"event_id\":");
        char supplied_prev[65];
        char supplied_hash[65];
        char calculated[65];
        size_t event_len;
        if (p == NULL || e == NULL || h == NULL || idp == NULL) {
            fclose(f);
            return -1;
        }
        idp += strlen("\"event_id\":");
        {
            char *end = NULL;
            unsigned long long id = strtoull(idp, &end, 10);
            if (end == idp || id != (unsigned long long)next_id) {
                fclose(f);
                return -1;
            }
            next_id++;
        }
        p += strlen(pk);
        if (strlen(p) < 64U || strlen(h + strlen(hk)) < 64U) {
            fclose(f);
            return -1;
        }
        memcpy(supplied_prev, p, 64U);
        supplied_prev[64] = '\0';
        memcpy(supplied_hash, h + strlen(hk), 64U);
        supplied_hash[64] = '\0';
        if (strcmp(supplied_prev, prev) != 0 || strspn(supplied_prev, "0123456789abcdef") != 64U || strspn(
        supplied_hash, "0123456789abcdef") != 64U) {
            fclose(f);
            return -1;
        }
        e += strlen(ek);
        event_len = (size_t)(h - e);
        if (event_len < 2U || e[event_len - 1U] != '}') {
            fclose(f);
            return -1;
        }
        if (e[event_len] != ',') {
            fclose(f);
            return -1;
        }
        {
            struct slx_sha256 c;
            uint8_t d[32];
            static const char hex[] = "0123456789abcdef";
            slx_sha256_init(&c);
            slx_sha256_update(&c, prev, 64U);
            slx_sha256_update(&c, e, event_len);
            slx_sha256_update(&c, "\n", 1U);
            slx_sha256_final(&c, d);
            for (size_t i = 0; i < 32U; ++i) {
                calculated[i * 2U] = hex[d[i] >> 4];
                calculated[i * 2U + 1U] = hex[d[i] & 15U];
            }
            calculated[64] = '\0';
        }
        if (strcmp(calculated, supplied_hash) != 0) {
            fclose(f);
            return -1;
        }
        memcpy(prev, supplied_hash, sizeof(prev));
        count++;
    }
    fclose(f);
    return count > 0U ? 0 : -1;
}
