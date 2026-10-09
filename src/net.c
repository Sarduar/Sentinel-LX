#include "sentinel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }

    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int ai_name(const char *name)
{
    static const char *const names[] = {
        "python",
        "node",
        "ollama",
        "llama",
        "vllm",
        "mcp",
        "agent",
        "langchain",
        "openclaw",
    };

    if (name == NULL) {
        return 0;
    }

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (strstr(name, names[i]) != NULL) {
            return 1;
        }
    }

    return 0;
}

#if !defined(__linux__)

static int seen_recent(const char *key, uint64_t now)
{
    static char seen[4096][160];
    static uint64_t timestamps[4096];
    static size_t count;

    for (size_t i = 0; i < count; i++) {
        if (timestamps[i] != 0 && now - timestamps[i] > 30ULL * 1000000000ULL) {
            timestamps[i] = 0;
        }

        if (timestamps[i] != 0 && strcmp(seen[i], key) == 0) {
            timestamps[i] = now;
            return 1;
        }
    }

    for (size_t i = 0; i < count; i++) {
        if (timestamps[i] != 0) {
            continue;
        }

        (void)snprintf(seen[i], sizeof(seen[i]), "%s", key);
        timestamps[i] = now;
        return 0;
    }

    if (count < 4096) {
        (void)snprintf(seen[count], sizeof(seen[count]), "%s", key);
        timestamps[count] = now;
        count++;
    }

    return 0;
}

int slx_collect_network(void)
{
    FILE *f = popen("sockstat -46cn 2>/dev/null", "r");
    char line[1024];
    uint64_t now;

    if (f == NULL) {
        return -1;
    }

    (void)fgets(line, sizeof(line), f);
    now = now_ns();

    while (fgets(line, sizeof(line), f) != NULL) {
        char user[64];
        char command[128];
        char protocol[32];
        char local[192];
        char remote[192];
        char key[512];
        long pid = 0;
        int fields;
        int is_ai;
        struct slx_event ev;

        fields = sscanf(line, "%63s %127s %ld %*s %31s %191s %191s",
                        user, command, &pid, protocol, local, remote);
        if (fields < 6 || pid <= 0) {
            continue;
        }

        if (strcmp(remote, "-") == 0 || strcmp(remote, "*") == 0) {
            continue;
        }

        (void)snprintf(key, sizeof(key), "%ld:%s:%s:%s",
                       pid, protocol, local, remote);
        if (seen_recent(key, now)) {
            continue;
        }

        is_ai = ai_name(command);
        memset(&ev, 0, sizeof(ev));
        ev.ts_ns = now;
        ev.type = SLX_EV_NET;
        ev.pid = (pid_t)pid;
        ev.score = 10;
        (void)snprintf(ev.subject, sizeof(ev.subject), "%s:%s", protocol, remote);
        (void)snprintf(ev.evidence, sizeof(ev.evidence),
                       "kernel-snapshot=sockstat command=%s local=%s remote=%s",
                       command, local, remote);
        (void)snprintf(ev.tags, sizeof(ev.tags), "network,sockstat,%s",
                       is_ai ? "ai" : "system");

        (void)slx_proc_identity(ev.pid, ev.proc_id, sizeof(ev.proc_id),
                                &ev.ppid, &ev.uid, NULL, 0);
        (void)slx_proc_identity(ev.ppid, ev.parent_proc_id, sizeof(ev.parent_proc_id),
                                NULL, NULL, NULL, 0);

        if (ev.uid == 0) {
            ev.score += 20;
        }
        if (is_ai) {
            ev.score += 25;
        }

        slx_corr_context(ev.proc_id, ev.parent_proc_id, 0,
                         &ev.exec_id, &ev.parent_exec_id, &ev.cause_id);

        if (slx_journal_append(&ev) == 0) {
            uint64_t id = slx_journal_last_event_id();

            slx_corr_add_for_build(2, ev.pid, ev.ppid, ev.uid, ev.score,
                                   ev.subject, ev.proc_id, ev.parent_proc_id);
            slx_corr_note_event(id, ev.pid, ev.proc_id, 0);
        }

        printf("NET snapshot score=%d pid=%ld %s owner=%s\n",
               ev.score, pid, ev.subject, command);
    }

    (void)pclose(f);
    return 0;
}

#else

#include <dirent.h>

struct sock_owner {
    unsigned long inode;
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    char comm[64];
    char proc_id[SLX_ID_MAX];
    char parent_proc_id[SLX_ID_MAX];
};

struct seen_sock {
    unsigned long inode;
    char remote[64];
    uint64_t last_ns;
};

static struct sock_owner owners[8192];
static size_t owner_count;
static struct seen_sock seen[8192];
static size_t seen_count;

static int parse_inode(const char *target, unsigned long *inode)
{
    return sscanf(target, "socket:[%lu]", inode) == 1 ? 0 : -1;
}

static void collect_owners(void)
{
    DIR *proc_dir = opendir("/proc");
    struct dirent *process_entry;

    if (proc_dir == NULL) {
        return;
    }

    owner_count = 0;
    while ((process_entry = readdir(proc_dir)) != NULL && owner_count < 8192) {
        char *end;
        long pid_value = strtol(process_entry->d_name, &end, 10);
        char fd_path[128];
        char comm[64] = "unknown";
        DIR *fd_dir;
        pid_t ppid = 0;
        uid_t uid = (uid_t)-1;
        char proc_id[SLX_ID_MAX] = "";
        char parent_proc_id[SLX_ID_MAX] = "";

        if (*end != '\0' || pid_value <= 0) {
            continue;
        }

        (void)snprintf(fd_path, sizeof(fd_path), "/proc/%ld/fd", pid_value);
        fd_dir = opendir(fd_path);
        if (fd_dir == NULL) {
            continue;
        }

        (void)slx_proc_identity((pid_t)pid_value, proc_id, sizeof(proc_id),
                                &ppid, &uid, comm, sizeof(comm));
        (void)slx_proc_identity(ppid, parent_proc_id, sizeof(parent_proc_id),
                                NULL, NULL, NULL, 0);

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir)) != NULL && owner_count < 8192) {
            char target_path[512];
            char target[128];
            ssize_t length;
            unsigned long inode = 0;

            if (fd_entry->d_name[0] == '.') {
                continue;
            }

            (void)snprintf(target_path, sizeof(target_path), "%s/%s",
                           fd_path, fd_entry->d_name);
            length = readlink(target_path, target, sizeof(target) - 1);
            if (length < 0) {
                continue;
            }
            target[length] = '\0';

            if (parse_inode(target, &inode) != 0) {
                continue;
            }

            owners[owner_count].inode = inode;
            owners[owner_count].pid = (pid_t)pid_value;
            owners[owner_count].ppid = ppid;
            owners[owner_count].uid = uid;
            (void)snprintf(owners[owner_count].comm,
                           sizeof(owners[owner_count].comm), "%s", comm);
            (void)snprintf(owners[owner_count].proc_id,
                           sizeof(owners[owner_count].proc_id), "%s", proc_id);
            (void)snprintf(owners[owner_count].parent_proc_id,
                           sizeof(owners[owner_count].parent_proc_id), "%s",
                           parent_proc_id);
            owner_count++;
        }

        closedir(fd_dir);
    }

    closedir(proc_dir);
}

static int seen_before(unsigned long inode, const char *remote, uint64_t now)
{
    for (size_t i = 0; i < seen_count; i++) {
        if (seen[i].inode == inode && strcmp(seen[i].remote, remote) == 0) {
            seen[i].last_ns = now;
            return 1;
        }
    }

    if (seen_count < 8192) {
        seen[seen_count].inode = inode;
        (void)snprintf(seen[seen_count].remote, sizeof(seen[seen_count].remote),
                       "%s", remote);
        seen_count++;
    }

    return 0;
}

static void prune_seen(uint64_t now)
{
    size_t write_index = 0;

    for (size_t i = 0; i < seen_count; i++) {
        if (now - seen[i].last_ns <= 30ULL * 1000000000ULL) {
            seen[write_index++] = seen[i];
        }
    }

    seen_count = write_index;
}

static void scan_table(const char *path, const char *protocol)
{
    FILE *f = fopen(path, "r");
    char line[512];
    uint64_t now;

    if (f == NULL) {
        return;
    }

    (void)fgets(line, sizeof(line), f);
    now = now_ns();

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long inode = 0;
        char local[64];
        char remote[64];
        char state[8];
        unsigned int sl;
        int fields;

        fields = sscanf(line, "%*d: %63s %63s %2s %*s %*s %*s %*s %*s %u",
                        local, remote, state, &sl);
        if (fields < 4) {
            continue;
        }

        if (sscanf(line, "%*d: %*s %*s %*s %*s %*s %*s %*s %*s %lu", &inode) != 1) {
            continue;
        }
        if (strcmp(state, "01") != 0) {
            continue;
        }
        if (seen_before(inode, remote, now)) {
            continue;
        }

        for (size_t i = 0; i < owner_count; i++) {
            struct sock_owner *owner = &owners[i];
            struct slx_event ev;
            int is_ai;
            int score = 10;

            if (owner->inode != inode) {
                continue;
            }

            is_ai = ai_name(owner->comm);
            if (owner->uid == 0) {
                score += 20;
            }
            if (is_ai) {
                score += 25;
            }

            memset(&ev, 0, sizeof(ev));
            ev.ts_ns = now;
            ev.type = SLX_EV_NET;
            ev.score = score;
            ev.pid = owner->pid;
            ev.ppid = owner->ppid;
            ev.uid = owner->uid;
            (void)snprintf(ev.proc_id, sizeof(ev.proc_id), "%s", owner->proc_id);
            (void)snprintf(ev.parent_proc_id, sizeof(ev.parent_proc_id), "%s",
                           owner->parent_proc_id);
            slx_corr_context(ev.proc_id, ev.parent_proc_id, 0,
                             &ev.exec_id, &ev.parent_exec_id, &ev.cause_id);
            (void)snprintf(ev.subject, sizeof(ev.subject), "%s:%s", protocol, remote);
            (void)snprintf(ev.evidence, sizeof(ev.evidence),
                           "socket_inode=%lu owner=%s local=%s state=ESTABLISHED",
                           inode, owner->comm, local);
            (void)snprintf(ev.tags, sizeof(ev.tags), "%s%s,network,attribution",
                           is_ai ? "ai," : "", owner->uid == 0 ? "root" : "user");

            if (slx_journal_append(&ev) == 0) {
                uint64_t id = slx_journal_last_event_id();

                slx_corr_add_for_build(2, ev.pid, ev.ppid, ev.uid, score,
                                       ev.subject, ev.proc_id, ev.parent_proc_id);
                slx_corr_note_event(id, ev.pid, ev.proc_id, 0);
            }

            printf("NET score=%d pid=%ld uid=%ld %s owner=%s\n",
                   score, (long)ev.pid, (long)ev.uid, ev.subject, owner->comm);
            break;
        }
    }

    fclose(f);
    prune_seen(now);
}

int slx_collect_network(void)
{
    collect_owners();
    scan_table("/proc/net/tcp", "tcp4");
    scan_table("/proc/net/tcp6", "tcp6");
    return 0;
}

#endif
