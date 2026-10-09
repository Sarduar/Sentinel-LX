#include "sentinel.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(__FreeBSD__) || defined(__NetBSD__)
static uint64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t) != 0)
        return 0;
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}
#endif
#if defined(__FreeBSD__)
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>
static int audit_fd = -1;
static FILE *audit_fp;
static int is_exec_event(au_event_t e)
{
    return e == AUE_EXEC || e == AUE_EXECVE;
}

static int is_net_event(au_event_t e)
{
    return e == AUE_CONNECT || e == AUE_ACCEPT || e == AUE_BIND || e == AUE_SHUTDOWN;
}

static int is_file_event(au_event_t e)
{
    return e == AUE_OPEN || e == AUE_CREAT || e == AUE_LINK || e == AUE_UNLINK || e == AUE_DELETE || e
    == AUE_SYMLINK || e == AUE_RENAME || e == AUE_TRUNCATE || e == AUE_FTRUNCATE || e == AUE_MKDIR || e
    == AUE_RMDIR || e == AUE_CHMOD || e == AUE_CHOWN;
}

static int ai_text(const char *s)
{
    static const char *k[] = {
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

static void freebsd_emit(const struct slx_event *src)
{
    struct slx_event ev = *src;
    if (ev.pid > 0) {
        (void)slx_proc_identity(ev.pid, ev.proc_id, sizeof(ev.proc_id), NULL, NULL, NULL, 0);
        (void)slx_proc_identity(ev.ppid, ev.parent_proc_id, sizeof(ev.parent_proc_id), NULL, NULL, NULL, 0);
    }
    slx_corr_context(ev.proc_id, ev.parent_proc_id, ev.type == SLX_EV_PROC, &ev.exec_id, &ev.parent_exec_id,
    &ev.cause_id);
    if (slx_journal_append(&ev) == 0) {
        uint64_t id = slx_journal_last_event_id();
        slx_corr_add_for_build(ev.type == SLX_EV_NET ? 2 : ev.type == SLX_EV_FIM ? 3 : ev.type == SLX_EV_AI
        ? 4 : 1, ev.pid, ev.ppid, ev.uid, ev.score, ev.subject, ev.proc_id, ev.parent_proc_id);
        slx_corr_note_event(id, ev.pid, ev.proc_id, ev.type == SLX_EV_PROC);
    }
}

static int freebsd_parse_record(u_char *buf, int len)
{
    tokenstr_t tok;
    int off = 0;
    au_event_t aue = AUE_NULL;
    uint64_t ts = now_ns();
    pid_t pid = 0;
    uid_t uid = (uid_t) - 1;
    char subject[SLX_PATH_MAX] = "freebsd-audit";
    char evidence[512] = "";
    while (off < len) {
        if (au_fetch_tok(&tok, buf + off, len - off) != 0 || tok.len == 0U || tok.len > (size_t)(len - off))
        break;
        switch (tok.id) {
            case AUT_HEADER32:
            aue = tok.tt.hdr32.e_type;
            ts = (uint64_t)tok.tt.hdr32.s * 1000000000ULL + (uint64_t)tok.tt.hdr32.ms * 1000000ULL;
            break;
            case AUT_HEADER64:
            aue = tok.tt.hdr64.e_type;
            ts = (uint64_t)tok.tt.hdr64.s * 1000000000ULL + (uint64_t)tok.tt.hdr64.ms * 1000000ULL;
            break;
            case AUT_HEADER32_EX:
            aue = tok.tt.hdr32_ex.e_type;
            ts = (uint64_t)tok.tt.hdr32_ex.s * 1000000000ULL + (uint64_t)tok.tt.hdr32_ex.ms * 1000000ULL;
            break;
            case AUT_HEADER64_EX:
            aue = tok.tt.hdr64_ex.e_type;
            ts = (uint64_t)tok.tt.hdr64_ex.s * 1000000000ULL + (uint64_t)tok.tt.hdr64_ex.ms * 1000000ULL;
            break;
            case AUT_SUBJECT32:
            pid = (pid_t)tok.tt.subj32.pid;
            uid = (uid_t)tok.tt.subj32.euid;
            break;
            case AUT_SUBJECT64:
            pid = (pid_t)tok.tt.subj64.pid;
            uid = (uid_t)tok.tt.subj64.euid;
            break;
            case AUT_SUBJECT32_EX:
            pid = (pid_t)tok.tt.subj32_ex.pid;
            uid = (uid_t)tok.tt.subj32_ex.euid;
            break;
            case AUT_SUBJECT64_EX:
            pid = (pid_t)tok.tt.subj64_ex.pid;
            uid = (uid_t)tok.tt.subj64_ex.euid;
            break;
            case AUT_PATH:
            if (tok.tt.path.name && *tok.tt.path.name)
                snprintf(subject, sizeof(subject), "%s", tok.tt.path.name);
            break;
            case AUT_TEXT:
            if (tok.tt.text.text && *tok.tt.text.text)
                snprintf(evidence, sizeof(evidence), "text=%s", tok.tt.text.text);
            break;
            default:
            break;
        }
        off += (int)tok.len;
    }
    if (aue == AUE_NULL)
        return 0;
    struct slx_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.ts_ns = ts;
    ev.pid = pid;
    ev.uid = uid;
    ev.ppid = 0;
    int score = 0;
    if (is_exec_event(aue)) {
        ev.type = ai_text(subject) ? SLX_EV_AI : SLX_EV_PROC;
        score = 20;
    } else if (is_net_event(aue)) {
        ev.type = SLX_EV_NET;
        score = 20;
    } else if (is_file_event(aue)) {
        ev.type = SLX_EV_FIM;
        score = 15;
    } else
        return 0;
    if (uid == 0)
        score += 20;
    if (ai_text(subject))
        score += 30;
    if (is_exec_event(aue))
        score += 10;
    ev.score = score;
    snprintf(ev.subject, sizeof(ev.subject), "%s", subject);
    snprintf(ev.evidence, sizeof(ev.evidence), "freebsd-audit event=%u%s%s", (unsigned)aue, evidence[0] ?
    " " : "", evidence);
    snprintf(ev.tags, sizeof(ev.tags), "kernel,auditpipe,%s,%s", is_exec_event(aue) ? "exec" :
    is_net_event(aue) ? "network" : "file", ai_text(subject) ? "ai" : "system");
    if (pid > 0) {
        pid_t ppid = 0;
        uid_t tmpuid = (uid_t) - 1;
        char comm[128] = "";
        (void)slx_proc_identity(pid, ev.proc_id, sizeof(ev.proc_id), &ppid, &tmpuid, comm, sizeof(comm));
        ev.ppid = ppid;
        if (uid == (uid_t) - 1)
            ev.uid = tmpuid;
        if (comm[0] && (!subject[0] || !strcmp(subject, "freebsd-audit")))
            snprintf(ev.subject, sizeof(ev.subject),
        "%s", comm);
    }
    freebsd_emit(&ev);
    return 1;
}
#endif
#if defined(__NetBSD__)
#include <sys/ioctl.h>
#include <filemon.h>
static int fm_fd = -1;
static int fm_pipe = -1;
static char fm_buf[16384];
static size_t fm_used;
static int ai_text(const char *s)
{
    static const char *k[] = {
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

static void netbsd_filemon_emit(char type, pid_t pid, const char *data1, const char *data2)
{
    struct slx_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.ts_ns = now_ns();
    ev.pid = pid;
    ev.type = (type == 'E' || type == 'X') ? SLX_EV_PROC : SLX_EV_FIM;
    ev.score = (type == 'W' || type == 'M' || type == 'D') ? 35 : 20;
    if (pid > 0) {
        (void)slx_proc_identity(pid, ev.proc_id, sizeof(ev.proc_id), &ev.ppid, &ev.uid, NULL, 0);
        (void)slx_proc_identity(ev.ppid, ev.parent_proc_id, sizeof(ev.parent_proc_id), NULL, NULL, NULL, 0);
    }
    if (ai_text(data1)) {
        ev.type = SLX_EV_AI;
        ev.score += 30;
    }
    snprintf(ev.subject, sizeof(ev.subject), "%s", data1 && *data1 ? data1 : "netbsd-filemon");
    if (data2 && *data2)
        snprintf(ev.evidence, sizeof(ev.evidence), "filemon=%c data2=%s", type, data2);
    else
        snprintf(ev.evidence, sizeof(ev.evidence), "filemon=%c", type);
    snprintf(ev.tags, sizeof(ev.tags), "kernel,filemon,%s,%s", type == 'E' ? "exec" : type == 'W' ||
    type == 'M' || type == 'D' ? "write" : "process", ai_text(data1) ? "ai" : "system");
    slx_corr_context(ev.proc_id, ev.parent_proc_id, type == 'E', &ev.exec_id, &ev.parent_exec_id, &ev.cause_id);
    if (slx_journal_append(&ev) == 0) {
        uint64_t id = slx_journal_last_event_id();
        slx_corr_add_for_build(ev.type == SLX_EV_FIM ? 3 : ev.type == SLX_EV_AI ? 4 : 1, ev.pid, ev.ppid, ev.uid,
        ev.score, ev.subject, ev.proc_id, ev.parent_proc_id);
        slx_corr_note_event(id, ev.pid, ev.proc_id, type == 'E');
    }
}

static void netbsd_parse_line(char *line)
{
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\0')
        return;
    char type = 0;
    long pid = 0;
    char data1[SLX_PATH_MAX] = "";
    char data2[SLX_PATH_MAX] = "";
    int n = sscanf(line, " %c %ld %4095[^\n]", &type, &pid, data1);
    if (n < 2)
        return;
    if (n >= 3) {
        char *p = data1;
        while (*p == ' ')
            p++;
        snprintf(data1, sizeof(data1), "%s", p);
    }
    if (type == 'M' || type == 'L') {
        char *q = strchr(data1, ' ');
        if (q) {
            *q = '\0';
            while (*++q == ' ') {
            }
            snprintf(data2, sizeof(data2), "%s", q);
        }
    }
    netbsd_filemon_emit(type, (pid_t)pid, data1, data2);
}
#endif
int slx_platform_init(void)
{
#if defined(__FreeBSD__)
    audit_fd = open("/dev/auditpipe", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (audit_fd < 0)
        return -1;
    audit_fp = fdopen(dup(audit_fd), "rb");
    if (!audit_fp) {
        close(audit_fd);
        audit_fd = -1;
        return -1;
    }
    (void)setvbuf(audit_fp, NULL, _IONBF, 0);
    return 0;
#elif defined(__NetBSD__)
    fm_fd = open("/dev/filemon", O_RDWR);
    if (fm_fd < 0)
        return -1;
    int p[2];
    if (pipe(p) != 0) {
        close(fm_fd);
        fm_fd = -1;
        return -1;
    }
    fm_pipe = p[0];
    int out = p[1];
    int flags = fcntl(fm_pipe, F_GETFL, 0);
    if (flags >= 0)
        (void)fcntl(fm_pipe, F_SETFL, flags | O_NONBLOCK);
    if (ioctl(fm_fd, FILEMON_SET_FD, &out) != 0) {
        close(out);
        close(fm_pipe);
        close(fm_fd);
        fm_pipe = -1;
        fm_fd = -1;
        return -1;
    }
    pid_t pid = 1;
    if (ioctl(fm_fd, FILEMON_SET_PID, &pid) != 0) {
        close(out);
        close(fm_pipe);
        close(fm_fd);
        fm_pipe = -1;
        fm_fd = -1;
        return -1;
    }
    close(out);
    return 0;
#else
    return 0;
#endif
}

void slx_platform_close(void)
{
#if defined(__FreeBSD__)
    if (audit_fp) {
        fclose(audit_fp);
        audit_fp = NULL;
    }
    if (audit_fd >= 0) {
        close(audit_fd);
        audit_fd = -1;
    }
#elif defined(__NetBSD__)
    if (fm_pipe >= 0) {
        close(fm_pipe);
        fm_pipe = -1;
    }
    if (fm_fd >= 0) {
        close(fm_fd);
        fm_fd = -1;
    }
#endif
}

int slx_platform_poll(void)
{
#if defined(__FreeBSD__)
    if (!audit_fp)
        return 0;
    int handled = 0;
    for (int i = 0; i < 64; i++) {
        u_char *buf = NULL;
        int n = au_read_rec(audit_fp, &buf);
        if (n < 0) {
            free(buf);
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            return handled ? -1 : -1;
        }
        if (n == 0) {
            free(buf);
            break;
        }
        handled += freebsd_parse_record(buf, n);
        free(buf);
    }
    return handled;
#elif defined(__NetBSD__)
    if (fm_pipe < 0)
        return 0;
    ssize_t n = read(fm_pipe, fm_buf + fm_used, sizeof(fm_buf) - fm_used - 1U);
    if (n > 0)
        fm_used += (size_t)n;
    size_t start = 0;
    for (size_t i = 0; i < fm_used; i++)
        if (fm_buf[i] == '\n') {
        fm_buf[i] = '\0';
        netbsd_parse_line(fm_buf + start);
        start = i + 1U;
    }
    if (start) {
        memmove(fm_buf, fm_buf + start, fm_used - start);
        fm_used -= start;
    }
    if (fm_used == sizeof(fm_buf) - 1U) {
        fm_used = 0;
    }
    return n > 0 ? 1 : 0;
#else
    return 0;
#endif
}
