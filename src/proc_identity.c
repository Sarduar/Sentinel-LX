#include "sentinel.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__FreeBSD__)
#include <libutil.h>
#include <sys/user.h>
#elif defined(__OpenBSD__)
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#elif defined(__NetBSD__)
#include <sys/sysctl.h>
#endif
#if defined(__linux__)
static char boot_id[SLX_ID_MAX];
static int boot_id_ready;
static int linux_boot_id(void)
{
    if (boot_id_ready)
        return boot_id[0] ? 0 : -1;
    boot_id_ready = 1;
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!f)
        return -1;
    if (!fgets(boot_id, sizeof(boot_id), f)) {
        fclose(f);
        boot_id[0] = 0;
        return -1;
    }
    fclose(f);
    boot_id[strcspn(boot_id, "\r\n")] = 0;
    return boot_id[0] ? 0 : -1;
}

static int linux_identity(pid_t pid, char *proc_id, size_t proc_cap, pid_t *ppid, uid_t *uid, char *
comm, size_t comm_cap)
{
    char path[128], line[4096], *closep, *save = NULL, *tok;
    unsigned long long start_ticks = 0ULL;
    long parent = 0;
    if (pid <= 0)
        return -1;
    (void)snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    closep = strrchr(line, ')');
    if (!closep || closep[1] != ' ')
        return -1;
    tok = strtok_r(closep + 2, " ", &save);
    for (int idx = 1; tok; idx++, tok = strtok_r(NULL, " ", &save)) {
        if (idx == 2) {
            char *e = NULL;
            parent = strtol(tok, &e, 10);
            if (!e || *e)
                return -1;
        }
        if (idx == 20) {
            char *e = NULL;
            start_ticks = strtoull(tok, &e, 10);
            if (!e || *e)
                return -1;
            break;
        }
    }
    if (start_ticks == 0ULL)
        return -1;
    if (ppid)
        *ppid = (pid_t)(parent > 0 ? parent : 0);
    if (uid) {
        *uid = (uid_t) - 1;
        (void)snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
        f = fopen(path, "r");
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                unsigned long u = 0UL;
                if (!strncmp(line, "Uid:", 4)) {
                    if (sscanf(line + 4, "%lu", &u) == 1)
                        *uid = (uid_t)u;
                    break;
                }
            }
            fclose(f);
        }
    }
    if (comm && comm_cap) {
        comm[0] = 0;
        (void)snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
        f = fopen(path, "r");
        if (f) {
            if (fgets(comm, (int)comm_cap, f))
                comm[strcspn(comm, "\r\n")] = 0;
            fclose(f);
        }
    }
    const char *b = (linux_boot_id() == 0) ? boot_id : "unknownboot";
    return snprintf(proc_id, proc_cap, "linux:%s:%ld:%llu", b, (long)pid, start_ticks) >= 0 ? 0 : -1;
}
#endif
#if defined(__FreeBSD__)
static int freebsd_identity(pid_t pid, char *proc_id, size_t proc_cap, pid_t *ppid, uid_t *uid, char
*comm, size_t comm_cap)
{
    struct kinfo_proc *kp = kinfo_getproc(pid);
    if (!kp)
        return -1;
    if (ppid)
        *ppid = kp->ki_ppid;
    if (uid)
        *uid = kp->ki_uid;
    if (comm && comm_cap)
        snprintf(comm, comm_cap, "%s", kp->ki_comm);
    int rc = snprintf(proc_id, proc_cap, "freebsd:%lld:%ld:%ld", (long long)kp->ki_start.tv_sec, (long)kp->ki_start.tv_usec,
    (long)pid) >= 0 ? 0 : -1;
    free(kp);
    return rc;
}
#endif
#if defined(__OpenBSD__)
static int openbsd_identity(pid_t pid, char *proc_id, size_t proc_cap, pid_t *ppid, uid_t *uid, char
*comm, size_t comm_cap)
{
    int mib[4] = {
        CTL_KERN,
        KERN_PROC,
        KERN_PROC_PID,
        pid
    };
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    memset(&kp, 0, sizeof(kp));
    if (sysctl(mib, 4, &kp, &len, NULL, 0) < 0 || len < sizeof(kp))
        return -1;
    if (ppid)
        *ppid = (pid_t)kp.p_ppid;
    if (uid)
        *uid = (uid_t)kp.p_uid;
    if (comm && comm_cap)
        snprintf(comm, comm_cap, "%s", kp.p_comm);
    int rc = snprintf(proc_id, proc_cap, "openbsd:%lu:%u:%ld", (unsigned long)kp.p_ustart_sec, (unsigned
    int)kp.p_ustart_usec, (long)pid) >= 0 ? 0 : -1;
    return rc;
}
#endif
#if defined(__NetBSD__)
static int netbsd_identity(pid_t pid, char *proc_id, size_t proc_cap, pid_t *ppid, uid_t *uid, char
*comm, size_t comm_cap)
{
    int mib[6] = {
        CTL_KERN,
        KERN_PROC2,
        KERN_PROC_PID,
        pid,
        (int)sizeof(struct kinfo_proc2),
        1
    };
    struct kinfo_proc2 kp;
    size_t len = sizeof(kp);
    memset(&kp, 0, sizeof(kp));
    if (pid <= 0 || sysctl(mib, 6, &kp, &len, NULL, 0) < 0 || len < sizeof(kp))
        return -1;
    if (ppid)
        *ppid = (pid_t)kp.p_ppid;
    if (uid)
        *uid = (uid_t)kp.p_uid;
    if (comm && comm_cap) {
        snprintf(comm, comm_cap, "%s", kp.p_comm);
        comm[comm_cap - 1] = 0;
    }
    if (kp.p_ustart_sec == 0U && kp.p_ustart_usec == 0U)
        return -1;
    return snprintf(proc_id, proc_cap, "netbsd:%lu:%u:%ld", (unsigned long)kp.p_ustart_sec, (unsigned int)
    kp.p_ustart_usec, (long)pid) >= 0 ? 0 : -1;
}
#endif
int slx_proc_identity(pid_t pid, char *proc_id, size_t proc_cap, pid_t *ppid, uid_t *uid, char *comm,
size_t comm_cap)
{
    if (proc_id && proc_cap)
        proc_id[0] = 0;
    if (ppid)
        *ppid = 0;
    if (uid)
        *uid = (uid_t) - 1;
    if (comm && comm_cap)
        comm[0] = 0;
#if defined(__linux__)
    return linux_identity(pid, proc_id, proc_cap, ppid, uid, comm, comm_cap);
#elif defined(__FreeBSD__)
    return freebsd_identity(pid, proc_id, proc_cap, ppid, uid, comm, comm_cap);
#elif defined(__OpenBSD__)
    return openbsd_identity(pid, proc_id, proc_cap, ppid, uid, comm, comm_cap);
#elif defined(__NetBSD__)
    return netbsd_identity(pid, proc_id, proc_cap, ppid, uid, comm, comm_cap);
#else
    (void)pid;
    (void)proc_id;
    (void)proc_cap;
    (void)ppid;
    (void)uid;
    (void)comm;
    (void)comm_cap;
    return -1;
#endif
}
