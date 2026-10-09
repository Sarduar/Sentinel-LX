#include "sentinel.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#define AUDIT_PENDING_MAX 512U
struct audit_pending {
    unsigned long long serial;
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    unsigned long syscall_nr;
    char arch[32];
    unsigned long long a1;
    unsigned long long a2;
    char exe[SLX_PATH_MAX];
    char comm[128];
    int success;
    int used;
};
static off_t audit_off;
static struct audit_pending pending[AUDIT_PENDING_MAX];
static const char *audit_paths[] = {
    "/var/log/audit/audit.log",
    "/var/log/audit.log"
};
static const char *audit_path(void)
{
    const char *env = getenv("SLX_AUDIT_PATH");
    if (env && *env)
        return env;
    size_t i;
    struct stat st;
    for (i = 0; i < sizeof(audit_paths) / sizeof(audit_paths[0]); i++)
        if (stat(audit_paths[i], &st) ==
    0 && S_ISREG(st.st_mode)) return audit_paths[i];
    return NULL;
}

static uint64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t) != 0)
        return 0;
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static long field_long(const char *s, const char *key)
{
    const char *p = strstr(s, key);
    char *e;
    long v;
    if (!p)
        return -1;
    p += strlen(key);
    v = strtol(p, &e, 10);
    return e == p ? -1 : v;
}

static unsigned long long field_ull(const char *s, const char *key)
{
    const char *p = strstr(s, key);
    char *e;
    unsigned long long v;
    if (!p)
        return 0;
    p += strlen(key);
    v = strtoull(p, &e, 0);
    return e == p ? 0ULL : v;
}

static int field_word(const char *s, const char *key, char *out, size_t cap)
{
    const char *p = strstr(s, key);
    size_t i = 0;
    if (!p)
        return -1;
    p += strlen(key);
    while (*p && *p != ' ' && *p != '\n' && i + 1 < cap)
        out[i++] = *p++;
    out[i] = 0;
    return i ? 0 : -1;
}

static int field_quoted(const char *s, const char *key, char *out, size_t cap)
{
    const char *p = strstr(s, key);
    size_t i = 0;
    if (!p)
        return -1;
    p += strlen(key);
    if (*p != '"')
        return -1;
    p++;
    while (*p && *p != '"' && i + 1 < cap) {
        if (*p == '\\' && p[1]) {
            if (i + 1 < cap)
                out[i++] = p[1];
            p += 2;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = 0;
    return (*p == '"') ? 0 : -1;
}

static int audit_serial(const char *s, unsigned long long *out)
{
    const char *p = strstr(s, "msg=audit(");
    char *colon;
    char *e;
    unsigned long long v;
    if (!p)
        return -1;
    p += 10;
    colon = strchr(p, ':');
    if (!colon)
        return -1;
    v = strtoull(colon + 1, &e, 10);
    if (e == colon + 1 || *e != ')')
        return -1;
    *out = v;
    return 0;
}

static int ai_cmd(const char *s)
{
    const char *k[] = {
        "python",
        "node",
        "ollama",
        "llama",
        "vllm",
        "mcp",
        "agent",
        "langchain",
        "openclaw"
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++)
        if (s && strstr(s, k[i]))
            return 1;
    return 0;
}

static struct audit_pending *pending_slot(unsigned long long serial)
{
    size_t empty = 0;
    for (size_t i = 0; i < AUDIT_PENDING_MAX; i++) {
        if (pending[i].used && pending[i].serial == serial)
            return &pending[i];
        if (!pending[i].used)
            empty = i;
    }
    pending[empty].used = 1;
    pending[empty].serial = serial;
    return &pending[empty];
}

static int syscall_is_mutating(const struct audit_pending *p)
{
    unsigned long long flags = 0;
    if (p->syscall_nr == 2UL && strstr(p->arch, "c000003e")) {
        flags = p->a1;
    } else if ((p->syscall_nr == 257UL && strstr(p->arch, "c000003e")) || (p->syscall_nr == 56UL &&
    strstr(p->arch, "c00000b7"))) {
        flags = p->a2;
    }
    if (flags &(1ULL | 2ULL | 64ULL | 512ULL))
        return 1;
    if (strstr(p->arch, "c000003e")) {
        switch (p->syscall_nr) {
            case 83UL:
            case 84UL:
            case 85UL:
            case 86UL:
            case 87UL:
            case 88UL:
            case 257UL:
            case 258UL:
            case 263UL:
            case 264UL:
            case 265UL:
            case 266UL:
            case 316UL:
            return 1;
            default:
            break;
        }
    }
    if (strstr(p->arch, "c00000b7")) {
        switch (p->syscall_nr) {
            case 34UL:
            case 35UL:
            case 36UL:
            case 37UL:
            case 38UL:
            case 39UL:
            case 45UL:
            case 46UL:
            case 56UL:
            return 1;
            default:
            break;
        }
    }
    return 0;
}

static void emit_proc_event(const char *line, int is_exec)
{
    long pid = field_long(line, " pid="), ppid = field_long(line, " ppid="), uid = field_long(line,
    " uid=");
    int ai = ai_cmd(line), score = 0;
    if (uid == 0)
        score += 25;
    if (strstr(line, "exe="))
        score += 10;
    if (is_exec)
        score += 10;
    if (ai)
        score += 30;
    if (score <= 0)
        return;
    struct slx_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.ts_ns = now_ns();
    ev.type = ai ? SLX_EV_AI : SLX_EV_PROC;
    ev.score = score;
    ev.pid = (pid_t)(pid < 0 ? 0 : pid);
    ev.ppid = (pid_t)(ppid < 0 ? 0 : ppid);
    ev.uid = (uid < 0 ? (uid_t) - 1 :(uid_t)uid);
    char comm[128];
    comm[0] = 0;
    (void)slx_proc_identity(ev.pid, ev.proc_id, sizeof(ev.proc_id), NULL, NULL, comm, sizeof(comm));
    (void)slx_proc_identity(ev.ppid, ev.parent_proc_id, sizeof(ev.parent_proc_id), NULL, NULL, NULL, 0);
    slx_corr_context(ev.proc_id, ev.parent_proc_id, is_exec, &ev.exec_id, &ev.parent_exec_id, &ev.cause_id);
    snprintf(ev.subject, sizeof(ev.subject), "%s", comm[0] ? comm : "audit-exec");
    snprintf(ev.evidence, sizeof(ev.evidence), "audit=%.*s", (int)sizeof(ev.evidence) - 7, line);
    snprintf(ev.tags, sizeof(ev.tags), "%s%s,audit,%s,correlate", ai ? "ai," : "", uid == 0 ? "root," :
    "", is_exec ? "exec" : "syscall");
    (void)slx_journal_append(&ev);
    printf("AUDIT score=%d pid=%ld ppid=%ld uid=%ld ai=%d exec=%d\n", score, pid, ppid, uid, ai, is_exec);
}

static void store_syscall(const char *line)
{
    unsigned long long serial = 0;
    if (audit_serial(line, &serial) != 0)
        return;
    struct audit_pending *p = pending_slot(serial);
    memset(p, 0, sizeof(*p));
    p->used = 1;
    p->serial = serial;
    long pidv = field_long(line, " pid=");
    long ppidv = field_long(line, " ppid=");
    long uidv = field_long(line, " uid=");
    p->pid = (pid_t)(pidv < 0 ? 0 : pidv);
    p->ppid = (pid_t)(ppidv < 0 ? 0 : ppidv);
    p->uid = (uid_t)(uidv < 0 ? (uid_t) - 1 : uidv);
    p->syscall_nr = (unsigned long)field_ull(line, "syscall=");
    (void)field_quoted(line, "comm=", p->comm, sizeof(p->comm));
    (void)field_quoted(line, "exe=", p->exe, sizeof(p->exe));
    (void)field_word(line, "arch=", p->arch, sizeof(p->arch));
    p->a1 = field_ull(line, "a1=");
    p->a2 = field_ull(line, "a2=");
    p->success = strstr(line, "success=yes") != NULL;
}

static void emit_path_event(const char *line)
{
    unsigned long long serial = 0;
    if (audit_serial(line, &serial) != 0)
        return;
    struct audit_pending *p = pending_slot(serial);
    char path[SLX_PATH_MAX] = "";
    char nametype[64] = "";
    if (field_quoted(line, "name=", path, sizeof(path)) != 0)
        return;
    (void)field_word(line, "nametype=", nametype, sizeof(nametype));
    if (!p->success)
        return;
    int mut = 0;
    if (!strcmp(nametype, "CREATE") || !strcmp(nametype, "DELETE") || !strcmp(nametype, "MKTEMP"))
        mut =
    1;
    else if (!strcmp(nametype, "NORMAL") && syscall_is_mutating(p))
        mut = 1;
    if (!mut)
        return;
    struct slx_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.ts_ns = now_ns();
    ev.type = SLX_EV_FIM;
    ev.score = 35 + (p->uid == 0 ? 20 : 0);
    ev.pid = p->pid;
    ev.ppid = p->ppid;
    ev.uid = p->uid;
    char comm[128] = "";
    (void)slx_proc_identity(ev.pid, ev.proc_id, sizeof(ev.proc_id), &ev.ppid, NULL, comm, sizeof(comm));
    (void)slx_proc_identity(ev.ppid, ev.parent_proc_id, sizeof(ev.parent_proc_id), NULL, NULL, NULL, 0);
    slx_corr_context(ev.proc_id, ev.parent_proc_id, 0, &ev.exec_id, &ev.parent_exec_id, &ev.cause_id);
    snprintf(ev.subject, sizeof(ev.subject), "%s", path);
    snprintf(ev.evidence, sizeof(ev.evidence),
    "linux-audit writer_pid=%ld syscall=%lu serial=%llu nametype=%.*s exe=%.*s", (long)p->pid, p->syscall_nr,
    serial, 63, nametype, 300, p->exe);
    snprintf(ev.tags, sizeof(ev.tags), "audit,fim,writer-pid,kernel");
    if (slx_journal_append(&ev) == 0)
        printf("AUDIT_FIM writer_pid=%ld path=%s serial=%llu\n", (long)p->pid,
    path, serial);
}

int slx_scan_audit(void)
{
    const char *path = audit_path();
    if (!path)
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (fseeko(f, audit_off, SEEK_SET) != 0) {
        audit_off = 0;
        (void)fseeko(f, 0, SEEK_SET);
    }
    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "type=SYSCALL")) {
            store_syscall(line);
            emit_proc_event(line, 0);
            continue;
        }
        if (strstr(line, "type=EXECVE")) {
            emit_proc_event(line, 1);
            continue;
        }
        if (strstr(line, "type=PATH")) {
            emit_path_event(line);
            continue;
        }
    }
    audit_off = ftello(f);
    fclose(f);
    return 0;
}
