#include "sentinel.h"
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define RING_MAX 16384U
static struct slx_event ring[RING_MAX];
static size_t head;
static size_t count;
static uint64_t pre_ns = 300ULL * 1000000000ULL;
static uint64_t post_ns = 900ULL * 1000000000ULL;
static int threshold = 70;
static int active;
static uint64_t trigger_ts;
static uint64_t trigger_event_id;
static char trigger_reason[160];
static uint64_t last_flush_ns;
static uint64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t) != 0)
        return 0;
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static uint64_t env_u64(const char *name, uint64_t def)
{
    const char *s = getenv(name);
    char *e = NULL;
    unsigned long long v;
    if (!s || ! *s)
        return def;
    v = strtoull(s, &e, 10);
    if (e == s || *e || v == 0ULL)
        return def;
    return (uint64_t)v;
}

static int env_int(const char *name, int def)
{
    const char *s = getenv(name);
    char *e = NULL;
    long v;
    if (!s || ! *s)
        return def;
    v = strtol(s, &e, 10);
    if (e == s || *e || v < 1L || v > 100000L)
        return def;
    return (int)v;
}

static size_t logical_index(size_t off)
{
    size_t oldest = (head + RING_MAX - count) % RING_MAX;
    return (oldest + off) % RING_MAX;
}

static void prune(uint64_t now)
{
    while (count) {
        size_t idx = logical_index(0);
        if (now - ring[idx].ts_ns <= pre_ns + post_ns + 60ULL * 1000000000ULL)
            break;
        count--;
    }
}

static void make_capsule_path(char *out, size_t cap, uint64_t id)
{
    const char *j = slx_journal_path();
    (void)snprintf(out, cap, "%s.incident-%llu.jsonl", j, (unsigned long long)id);
}

static int write_capsule(const char *path, uint64_t first_id, uint64_t last_id, uint64_t ts,
uint64_t begin, uint64_t end)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
    if (fd < 0)
        return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return -1;
    }
    char prev[65] = "0000000000000000000000000000000000000000000000000000000000000000";
    char line[14000], hash[65];
    if (fprintf(f,
    "{\"format\":\"slx-incident-v1\",\"trigger_event_id\":%llu,\"reason\":\"%s\",\"trigger_ts_ns\":%llu,\"begin_ts_ns\":%llu,\"end_ts_ns\":%llu,\"first_event_id\":%llu,\"last_event_id\":%llu}\n",
    (unsigned long long)trigger_event_id, trigger_reason, (unsigned long long)ts, (unsigned long long)
    begin, (unsigned long long)end, (unsigned long long)first_id, (unsigned long long)last_id) < 0) {
        fclose(f);
        return -1;
    }
    for (size_t n = 0; n < count; n++) {
        const struct slx_event *e = &ring[logical_index(n)];
        if (e->ts_ns < begin || e->ts_ns > end)
            continue;
        struct slx_event tmp = *e;
        int json_n = slx_json_event(&tmp, line, sizeof(line));
        if (json_n < 0)
            continue;
        if (json_n > 0 && line[json_n - 1] == '\n')
            line[--json_n] = 0;
        struct slx_sha256 c;
        uint8_t d[32];
        static const char hex[] = "0123456789abcdef";
        slx_sha256_init(&c);
        slx_sha256_update(&c, prev, 64U);
        slx_sha256_update(&c, line, strlen(line));
        slx_sha256_final(&c, d);
        for (size_t i = 0; i < 32; i++) {
            hash[i * 2] = hex[d[i] >> 4];
            hash[i * 2 + 1] = hex[d[i] & 15U];
        }
        hash[64] = 0;
        if (fprintf(f, "{\"capsule_prev\":\"%s\",\"event_hash\":\"%s\",\"event\":%s}\n", prev, hash, line) <
        0) {
            fclose(f);
            return -1;
        }
        memcpy(prev, hash, sizeof(prev));
    }
    if (fflush(f) != 0) {
        fclose(f);
        return -1;
    }
    if (fsync(fileno(f)) != 0) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int copy_one_export(const char *src, const char *dir)
{
    const char *base = strrchr(src, '/');
    base = base ? base + 1 : src;
    char dst[SLX_PATH_MAX];
    int n = snprintf(dst, sizeof(dst), "%s/%s", dir, base);
    if (n < 0 || (size_t)n >= sizeof(dst))
        return -1;
    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0)
        return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
    if (out < 0) {
        close(in);
        return -1;
    }
    char b[16384];
    ssize_t nread;
    int rc = 0;
    while ((nread = read(in, b, sizeof(b))) > 0) {
        ssize_t off = 0;
        while (off < nread) {
            ssize_t w = write(out, b + off, (size_t)(nread - off));
            if (w <= 0) {
                rc = -1;
                break;
            }
            off += w;
        }
        if (rc < 0)
            break;
    }
    if (nread < 0)
        rc = -1;
    if (fsync(out) != 0)
        rc = -1;
    close(out);
    close(in);
    if (rc < 0)
        (void)unlink(dst);
    return rc;
}

static int copy_export(const char *src)
{
    const char *dir = getenv("SLX_EXPORT_DIR");
    if (!dir || ! *dir)
        return 0;
    if (copy_one_export(src, dir) != 0)
        return -1;
    char sig[SLX_PATH_MAX];
    int n = snprintf(sig, sizeof(sig), "%s.sig", src);
    if (n > 0 && (size_t)n < sizeof(sig)) {
        struct stat st;
        if (stat(sig, &st) == 0) {
            if (copy_one_export(sig, dir) != 0)
                return -1;
        }
    }
    return 0;
}

static void note_internal_failure(const char *subject, const char *evidence)
{
    struct slx_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.ts_ns = now_ns();
    ev.type = SLX_EV_OVERFLOW;
    ev.score = 90;
    ev.pid = getpid();
    ev.ppid = getppid();
    ev.uid = getuid();
    snprintf(ev.subject, sizeof(ev.subject), "%s", subject);
    snprintf(ev.evidence, sizeof(ev.evidence), "%s", evidence);
    snprintf(ev.tags, sizeof(ev.tags), "integrity,investigate");
    slx_corr_context("", "", 0, &ev.exec_id, &ev.parent_exec_id, &ev.cause_id);
    (void)slx_journal_append(&ev);
}

static void flush_incident(void)
{
    if (!active)
        return;
    char path[SLX_PATH_MAX];
    uint64_t begin = trigger_ts > pre_ns ? trigger_ts - pre_ns : 0, end = trigger_ts + post_ns;
    uint64_t first = 0, last = 0;
    for (size_t n = 0; n < count; n++) {
        const struct slx_event *e = &ring[logical_index(n)];
        if (e->ts_ns < begin || e->ts_ns > end)
            continue;
        if (first == 0)
            first = e->event_id;
        last = e->event_id;
    }
    if (first == 0) {
        active = 0;
        return;
    }
    make_capsule_path(path, sizeof(path), trigger_event_id);
    if (write_capsule(path, first, last, trigger_ts, begin, end) == 0) {
        if (slx_sign_artifact(path) != 0) {
            (void)unlink(path);
            note_internal_failure(path, "evidence signing failed");
        } else {
            (void)copy_export(path);
            fprintf(stdout, "INCIDENT capsule=%s events=%llu..%llu reason=%s\n", path, (unsigned long long)first,
            (unsigned long long)last, trigger_reason);
        }
    }
    active = 0;
    last_flush_ns = now_ns();
}

void slx_ring_init(void)
{
    uint64_t sec = env_u64("SLX_RING_SECONDS", 300ULL);
    uint64_t post = env_u64("SLX_INCIDENT_POST_SECONDS", 900ULL);
    int th = env_int("SLX_INCIDENT_THRESHOLD", 70);
    if (sec > 3600ULL)
        sec = 3600ULL;
    if (post > 3600ULL)
        post = 3600ULL;
    pre_ns = sec * 1000000000ULL;
    post_ns = post * 1000000000ULL;
    threshold = th;
    memset(ring, 0, sizeof(ring));
    head = 0;
    count = 0;
    active = 0;
    trigger_ts = 0;
    trigger_event_id = 0;
    trigger_reason[0] = 0;
    last_flush_ns = 0;
}

void slx_ring_push(const struct slx_event *ev)
{
    uint64_t now = now_ns();
    if (!ev || ev->ts_ns == 0)
        return;
    prune(now);
    ring[head] = *ev;
    head = (head + 1U) % RING_MAX;
    if (count < RING_MAX)
        count++;
    if (!active && (uint64_t)ev->score >= (uint64_t)threshold) {
        if (last_flush_ns == 0 || now - last_flush_ns > 30ULL * 1000000000ULL)
            slx_ring_request_trigger(ev->type
        == SLX_EV_OVERFLOW ? "telemetry-overflow" : "high-signal-event");
    }
}

void slx_ring_request_trigger(const char *reason)
{
    uint64_t now = now_ns();
    if (active)
        return;
    if (last_flush_ns && now - last_flush_ns <= 30ULL * 1000000000ULL)
        return;
    active = 1;
    trigger_ts = now;
    trigger_event_id = slx_journal_last_event_id();
    snprintf(trigger_reason, sizeof(trigger_reason), "%s", reason && *reason ? reason : "manual");
    fprintf(stdout, "INCIDENT trigger event=%llu reason=%s post_seconds=%llu\n", (unsigned long long)
    trigger_event_id, trigger_reason, (unsigned long long)(post_ns / 1000000000ULL));
}

void slx_ring_tick(void)
{
    if (active && now_ns() >= trigger_ts + post_ns)
        flush_incident();
}

static int incident_chain_check(const char *path, uint64_t *record_count, char final_hash[65])
{
    FILE *file;
    char line[16384];
    char previous[65] = "0000000000000000000000000000000000000000000000000000000000000000";
    uint64_t verified_records = 0U;
    if (path == NULL || *path == '\0')
        return -1;
    file = fopen(path, "r");
    if (file == NULL)
        return -1;
    if (fgets(line, sizeof(line), file) == NULL || strstr(line, "\"format\":\"slx-incident-v1\"") ==
    NULL) {
        (void)fclose(file);
        return -1;
    } while (fgets(line, sizeof(line), file) != NULL) {
        const char *previous_key = "\"capsule_prev\":\"";
        const char *hash_key = "\"event_hash\":\"";
        const char *event_key = "\"event\":";
        const char *previous_pos = strstr(line, previous_key);
        const char *hash_pos = strstr(line, hash_key);
        const char *event_pos = strstr(line, event_key);
        char supplied_previous[65];
        char supplied_hash[65];
        char calculated_hash[65];
        size_t event_length;
        struct slx_sha256 context;
        uint8_t digest[32];
        static const char hex[] = "0123456789abcdef";
        size_t i;
        if (previous_pos == NULL || hash_pos == NULL || event_pos == NULL) {
            (void)fclose(file);
            return -1;
        }
        previous_pos += strlen(previous_key);
        hash_pos += strlen(hash_key);
        if (strlen(previous_pos) < 65U || strlen(hash_pos) < 65U || previous_pos[64] != '"' || hash_pos[64]
        != '"') {
            (void)fclose(file);
            return -1;
        }
        memcpy(supplied_previous, previous_pos, 64U);
        supplied_previous[64] = '\0';
        memcpy(supplied_hash, hash_pos, 64U);
        supplied_hash[64] = '\0';
        if (strcmp(supplied_previous, previous) != 0 || strspn(supplied_previous, "0123456789abcdef") != 64U
        || strspn(supplied_hash, "0123456789abcdef") != 64U) {
            (void)fclose(file);
            return -1;
        }
        event_pos += strlen(event_key);
        event_length = strlen(event_pos);
        while (event_length > 0U && (event_pos[event_length - 1U] == '\n' || event_pos[event_length - 1U] ==
        '\r'))--event_length;
        if (event_length < 3U || event_pos[event_length - 1U] != '}' || event_pos[event_length - 2U] != '}') {
            (void)fclose(file);
            return -1;
        }
        --event_length;
        slx_sha256_init(&context);
        slx_sha256_update(&context, previous, 64U);
        slx_sha256_update(&context, event_pos, event_length);
        slx_sha256_final(&context, digest);
        for (i = 0U; i < sizeof(digest); ++i) {
            calculated_hash[i * 2U] = hex[digest[i] >> 4];
            calculated_hash[i * 2U + 1U] = hex[digest[i] & 0x0fU];
        }
        calculated_hash[64] = '\0';
        if (strcmp(calculated_hash, supplied_hash) != 0) {
            (void)fclose(file);
            return -1;
        }
        memcpy(previous, calculated_hash, sizeof(previous));
        ++verified_records;
    }
    {
        int read_error = ferror(file);
        int close_error = fclose(file);
        if (read_error || close_error != 0 || verified_records == 0U)
            return -1;
    }
    if (record_count != NULL)
        *record_count = verified_records;
    if (final_hash != NULL)
        memcpy(final_hash, previous, sizeof(previous));
    return 0;
}

int slx_incident_chain_verify(const char *path)
{
    return incident_chain_check(path, NULL, NULL);
}

int slx_incident_verify(const char *path)
{
    uint64_t records;
    char final_hash[65];
    if (incident_chain_check(path, &records, final_hash) != 0)
        return -1;
    if (slx_verify_artifact(path) != 0) {
        (void)fprintf(stderr, "incident signature verification failed\n");
        return -1;
    }
    (void)printf("incident verified: records=%" PRIu64 " final_hash=%s\n", records, final_hash);
    return 0;
}
