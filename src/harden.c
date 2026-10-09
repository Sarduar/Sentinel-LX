#include "sentinel.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
static int limit_nofile(void)
{
    struct rlimit r;
    if (getrlimit(RLIMIT_NOFILE, &r) != 0)
        return -1;
    if (r.rlim_cur < 1024U) {
        r.rlim_cur = r.rlim_max >= 1024U ? 1024U : r.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &r) != 0)
            return -1;
    }
    return 0;
}

int slx_self_harden(void)
{
    (void)umask(077);
    if (limit_nofile() != 0)
        return -1;
    {
        struct rlimit r;
        if (getrlimit(RLIMIT_CORE, &r) != 0)
            return -1;
        r.rlim_cur = 0;
        if (setrlimit(RLIMIT_CORE, &r) != 0)
            return -1;
    }
#if defined(__linux__)
    if (prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) != 0)
        return -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0)
        return -1;
#endif
    return 0;
}
