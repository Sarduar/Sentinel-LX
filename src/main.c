#include "sentinel.h"
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#if defined(__linux__)
#include <sys/inotify.h>
#else
#include <sys/event.h>
#include <sys/time.h>
#endif
static volatile sig_atomic_t incident_requested;
static void on_incident_signal(int sig)
{
    (void)sig;
    incident_requested = 1;
}

static uint64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t) != 0)
        return 0;
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static void emit(enum slx_event_type type, int score, pid_t pid, pid_t ppid, uid_t uid, const char *
s, const char *e, const char *t)
{
    struct slx_event v;
    memset(&v, 0, sizeof(v));
    v.ts_ns = now_ns();
    v.type = type;
    v.score = score;
    v.pid = pid;
    v.ppid = ppid;
    v.uid = uid;
    if (pid > 0) {
        (void)slx_proc_identity(pid, v.proc_id, sizeof(v.proc_id), NULL, NULL, NULL, 0);
        (void)slx_proc_identity(ppid, v.parent_proc_id, sizeof(v.parent_proc_id), NULL, NULL, NULL, 0);
    }
    slx_corr_context(v.proc_id, v.parent_proc_id, 0, &v.exec_id, &v.parent_exec_id, &v.cause_id);
    (void)snprintf(v.subject, sizeof(v.subject), "%s", s);
    (void)snprintf(v.evidence, sizeof(v.evidence), "%s", e);
    (void)snprintf(v.tags, sizeof(v.tags), "%s", t);
    if (slx_journal_append(&v) == 0)
        slx_corr_note_event(slx_journal_last_event_id(), pid, v.proc_id, 0);
    printf("EVENT type=%d score=%d pid=%ld subject=%s evidence=%s\n", (int)type, score, (long)pid, s, e);
}

struct watch_ent {
    int id;
    char path[SLX_PATH_MAX];
};
static struct watch_ent *watches;
static size_t watch_count;
static size_t watch_cap;
static size_t watch_limit = 4096U;
static char **watch_roots;
static size_t root_count;
static size_t root_cap;
static int remember_root(const char *path)
{
    size_t i;
    if (path == NULL || *path == '\0')
        return -1;
    for (i = 0; i < root_count; ++i)
        if (strcmp(watch_roots[i], path) == 0)
            return 0;
    if (root_count == root_cap) {
        size_t cap = root_cap == 0U ? 8U : root_cap * 2U;
        char **v = realloc(watch_roots, cap * sizeof(*v));
        if (v == NULL)
            return -1;
        watch_roots = v;
        root_cap = cap;
    }
    watch_roots[root_count] = strdup(path);
    if (watch_roots[root_count] == NULL)
        return -1;
    ++root_count;
    return 0;
}

static int ensure_watch_capacity(void)
{
    if (watch_count < watch_cap)
        return 0;
    {
        size_t cap = watch_cap == 0U ? 256U : watch_cap * 2U;
        if (cap > watch_limit)
            cap = watch_limit;
        if (cap <= watch_cap)
            return -1;
        struct watch_ent *v = realloc(watches, cap * sizeof(*v));
        if (v == NULL)
            return -1;
        watches = v;
        watch_cap = cap;
    }
    return 0;
}

static int add_watch(int fd, const char *p)
{
    size_t i;
    for (i = 0; i < watch_count; ++i)
        if (strcmp(watches[i].path, p) == 0)
            return 0;
    if (watch_count >= watch_limit || ensure_watch_capacity() != 0) {
        errno = ENOSPC;
        return -1;
    }
#if defined(__linux__)
    {
        int wd = inotify_add_watch(fd, p, IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO |
        IN_MOVED_FROM | IN_DELETE | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF);
        if (wd < 0)
            return -1;
        watches[watch_count].id = wd;
    }
#else
    {
        int w = open(p, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (w < 0)
            return -1;
        struct kevent ev;
        EV_SET(&ev, w, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_RENAME
        | NOTE_DELETE, 0, NULL);
        if (kevent(fd, &ev, 1, NULL, 0, NULL) < 0) {
            close(w);
            return -1;
        }
        watches[watch_count].id = w;
    }
#endif
    (void)snprintf(watches[watch_count].path, sizeof(watches[watch_count].path), "%s", p);
    ++watch_count;
    return 0;
}

static const char *watch_path(int id)
{
    for (size_t i = 0; i < watch_count; i++)
        if (watches[i].id == id)
            return watches[i].path;
    return "unknown";
}

static void forget_watch(int id)
{
    size_t i;
    for (i = 0; i < watch_count; ++i) {
        if (watches[i].id == id) {
            if (i + 1U < watch_count)
                watches[i] = watches[watch_count - 1U];
            --watch_count;
            return;
        }
    }
}

static int watch_tree(int fd, const char *p)
{
    DIR *d = opendir(p);
    if (!d)
        return -1;
    if (add_watch(fd, p) != 0) {
        closedir(d);
        return -1;
    }
    struct dirent *e;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
        char c[SLX_PATH_MAX];
        struct stat st;
        int n = snprintf(c, sizeof(c), "%s/%s", p, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(c))
            continue;
        if (lstat(c, &st) == 0 && S_ISDIR(st.st_mode) && e->d_name[0] != '.')
            (void)watch_tree(fd, c);
    }
    closedir(d);
    return 0;
}

static void rescan_roots(int fd)
{
    for (size_t i = 0; i < root_count; ++i)
        (void)watch_tree(fd, watch_roots[i]);
}
#if defined(__linux__)
static void handle_fim(int fd)
{
    char b[65536];
    ssize_t n = read(fd, b, sizeof(b)), o = 0;
    while (n > 0 && o < n) {
        struct inotify_event *e = (struct inotify_event *)(void *)(b + o);
        size_t step = sizeof(*e) + (size_t)e->len;
        const char *base = watch_path(e->wd);
        if (e->mask & IN_Q_OVERFLOW) {
            emit(SLX_EV_OVERFLOW, 90, 0, 0, 0, "inotify", "kernel queue overflow; telemetry gap",
            "gap,integrity,investigate");
            rescan_roots(fd);
        } else if (e->mask & IN_IGNORED) {
            forget_watch(e->wd);
            emit(SLX_EV_OVERFLOW, 80, 0, 0, 0, base, "inotify watch removed; telemetry gap",
            "gap,integrity,fim,investigate");
            rescan_roots(fd);
        } else {
            char path[SLX_PATH_MAX];
            path[0] = '\0';
            if (base && strcmp(base, "unknown")) {
                if (e->len) {
                    size_t blen = strlen(base), nlen = strnlen(e->name, e->len);
                    if (blen + 1U + nlen < sizeof(path)) {
                        memcpy(path, base, blen);
                        path[blen] = '/';
                        memcpy(path + blen + 1U, e->name, nlen);
                        path[blen + 1U + nlen] = '\0';
                    }
                } else(void)snprintf(path, sizeof(path), "%s", base);
            } else if (e->len) {
                size_t nlen = strnlen(e->name, e->len);
                if (nlen < sizeof(path)) {
                    memcpy(path, e->name, nlen);
                    path[nlen] = '\0';
                }
            }
            if (e->mask & IN_ISDIR) {
                if ((e->mask &(IN_CREATE | IN_MOVED_TO)) && path[0] && watch_tree(fd, path) != 0)
                    emit(
                SLX_EV_OVERFLOW, 80, 0, 0, 0, path, "new directory could not be watched",
                "gap,integrity,fim,investigate");
                if (e->mask &(IN_DELETE_SELF | IN_MOVE_SELF))
                    rescan_roots(fd);
            } else if (path[0])
                emit(SLX_EV_FIM, 30, 0, 0, 0, path, "filesystem mutation", "fim,investigate");
        }
        if (step == 0U)
            break;
        o += (ssize_t)step;
    }
}
#else
static void handle_fim(int fd)
{
    struct kevent evs[64];
    struct timespec ts = {
        0,
        0
    };
    int n = kevent(fd, NULL, 0, evs, 64, &ts);
    for (int i = 0; i < n; i++) {
        const char *base = watch_path((int)evs[i].ident);
        if (base && strcmp(base, "unknown")) {
            emit(SLX_EV_FIM, 30, 0, 0, 0, base, "kqueue vnode mutation", "fim,kqueue,investigate");
            rescan_roots(fd);
        }
    }
}
#endif
int main(int argc, char **argv)
{
    if (slx_self_harden() != 0) {
        perror("self-hardening");
        return 1;
    }
    if (argc >= 2 && !strcmp(argv[1], "--explain")) {
        int seconds = 300;
        if (argc >= 3) {
            char *end = NULL;
            long v = strtol(argv[2], &end, 10);
            if (end != argv[2] && *end == 0 && v > 0 && v <= 86400)
                seconds = (int)v;
        }
        return slx_explain(seconds);
    }
    if (argc >= 2 && !strcmp(argv[1], "--report")) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s --report <capsule> [output]\n", argv[0]);
            return 2;
        }
        return slx_incident_report(argv[2], argc >= 4 ? argv[3] : NULL) == 0 ? 0 : 1;
    }
    if (argc >= 2 && !strcmp(argv[1], "--verify-incident")) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s --verify-incident <capsule>\n", argv[0]);
            return 2;
        }
        return slx_incident_verify(argv[2]) == 0 ? 0 : 1;
    }
    if (argc >= 2 && !strcmp(argv[1], "--verify-journal")) {
        const char *path = argc >= 3 ? argv[2] : slx_journal_path();
        return slx_journal_verify(path) == 0 ? 0 : 1;
    }
    if (argc >= 2 && !strcmp(argv[1], "--ship")) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s --ship <capsule>\n", argv[0]);
            return 2;
        }
        return slx_ship_file(argv[2]) == 0 ? 0 : 1;
    }
    if (argc >= 2 && !strcmp(argv[1], "--receive")) {
        return slx_receive_server() == 0 ? 0 : 1;
    }
    if (argc >= 2 && !strcmp(argv[1], "--scan-audit")) {
        if (slx_journal_init() != 0) {
            perror("journal");
            return 1;
        }
        slx_ring_init();
        int rc = slx_scan_audit();
        slx_journal_close();
        return rc == 0 ? 0 : 1;
    }
    if (slx_journal_init() != 0) {
        perror("journal");
        return 1;
    }
    slx_ring_init();
    (void)signal(SIGUSR1, on_incident_signal);
    if (slx_platform_init() != 0)
        fprintf(stderr,
    "warning: native platform collector unavailable on this host\n");
#if defined(__linux__)
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) {
        perror("inotify");
        slx_platform_close();
        return 1;
    }
#else
    int fd = kqueue();
    if (fd < 0) {
        perror("kqueue");
        slx_platform_close();
        return 1;
    }
#endif
    {
        const char *lim = getenv("SLX_MAX_WATCHES");
        if (lim && *lim) {
            char *end = NULL;
            unsigned long v = strtoul(lim, &end, 10);
            if (end != lim && *end == '\0' && v >= 1UL && v <= 1048576UL)
                watch_limit = (size_t)v;
        }
    }
    if (argc < 2) {
        (void)remember_root("/etc");
        (void)remember_root("/usr/local/bin");
        (void)remember_root("/usr/local/sbin");
        (void)remember_root("/opt");
    } else for (int i = 1; i < argc; i++)
        (void)remember_root(argv[i]);
    for (size_t i = 0; i < root_count; i++)
        if (watch_tree(fd, watch_roots[i]) != 0)
            emit(
    SLX_EV_OVERFLOW, 80, 0, 0, 0, watch_roots[i], "root could not be watched",
    "gap,integrity,fim,investigate");
    emit(SLX_EV_PROC, 0, getpid(), getppid(), getuid(), "sentinel-lx", "sensor started",
    "sensor,audit,network");
    (void)slx_scan_audit();
#if defined(__linux__)
    struct pollfd p = {
        fd,
        POLLIN,
        0
    };
#endif
    unsigned tick = 0;
    for (; ; ) {
        if (incident_requested) {
            incident_requested = 0;
            slx_ring_request_trigger("SIGUSR1-manual");
        }
#if defined(__linux__)
        int r = poll(&p, 1, 1000);
        if (r > 0 && (p.revents & POLLIN))
            handle_fim(fd);
#else
        struct timespec ts = {
            1,
            0
        };
        int r = kevent(fd, NULL, 0, NULL, 0, &ts);
        (void)r;
        handle_fim(fd);
#endif
        (void)slx_platform_poll();
        if (++tick % 2U == 0) {
            (void)slx_scan_audit();
            slx_correlation_tick();
        }
        if (tick % 5U == 0) {
            (void)slx_collect_network();
            slx_correlation_tick();
        }
        slx_ring_tick();
    }
}
