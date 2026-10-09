#include "sentinel.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#define CORR_MAX 512
struct corr {
    uint64_t ts;
    pid_t pid, ppid;
    uid_t uid;
    int score;
    int ai;
    int exec;
    int net;
    int fim;
    char proc_id[SLX_ID_MAX];
    char parent_proc_id[SLX_ID_MAX];
    char subject[128];
    uint64_t last_event_id;
    uint64_t current_exec_id;
};
static struct corr ring[CORR_MAX];
static size_t count;
static uint64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t) != 0)
        return 0;
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static void prune(uint64_t now)
{
    size_t i = 0;
    while (i < count && now - ring[i].ts > 120ULL * 1000000000ULL)
        i++;
    if (i) {
        memmove(ring, ring + i, (count - i) * sizeof(ring[0]));
        count -= i;
    }
}

static size_t find_proc(const char *proc_id, pid_t pid)
{
    if (proc_id && *proc_id) {
        for (size_t i = 0; i < count; i++)
            if (!strcmp(ring[i].proc_id, proc_id))
                return i;
    }
    if (pid > 0) {
        for (size_t i = 0; i < count; i++)
            if (ring[i].pid == pid)
                return i;
    }
    return count;
}

static void add(int kind, pid_t pid, pid_t ppid, uid_t uid, int score, const char *s, const char *
proc_id, const char *parent_proc_id)
{
    uint64_t now = now_ns();
    prune(now);
    size_t i = find_proc(proc_id, pid);
    if (i < count) {
        ring[i].ts = now;
        ring[i].ppid = ppid;
        ring[i].uid = uid;
        ring[i].score += score;
        if (parent_proc_id && *parent_proc_id)
            snprintf(ring[i].parent_proc_id, sizeof(ring[i].parent_proc_id),
        "%s", parent_proc_id);
        if (kind == 1)
            ring[i].exec = 1;
        if (kind == 2)
            ring[i].net = 1;
        if (kind == 3)
            ring[i].fim = 1;
        if (kind == 4)
            ring[i].ai = 1;
        if (s)
            snprintf(ring[i].subject, sizeof(ring[i].subject), "%s", s);
        return;
    }
    if (count < CORR_MAX) {
        struct corr *c = &ring[count++];
        memset(c, 0, sizeof(*c));
        c->ts = now;
        c->pid = pid;
        c->ppid = ppid;
        c->uid = uid;
        c->score = score;
        if (proc_id)
            snprintf(c->proc_id, sizeof(c->proc_id), "%s", proc_id);
        if (parent_proc_id)
            snprintf(c->parent_proc_id, sizeof(c->parent_proc_id), "%s", parent_proc_id);
        if (kind == 1)
            c->exec = 1;
        if (kind == 2)
            c->net = 1;
        if (kind == 3)
            c->fim = 1;
        if (kind == 4)
            c->ai = 1;
        if (s)
            snprintf(c->subject, sizeof(c->subject), "%s", s);
    }
}

void slx_corr_context(const char *proc_id, const char *parent_proc_id, int is_exec, uint64_t *
exec_id, uint64_t *parent_exec_id, uint64_t *cause_id)
{
    uint64_t now = now_ns();
    prune(now);
    size_t i = find_proc(proc_id, 0), p = find_proc(parent_proc_id, 0);
    uint64_t cur = i < count ? ring[i].current_exec_id : 0;
    uint64_t par = p < count ? ring[p].current_exec_id : 0;
    if (exec_id)
        *exec_id = is_exec ? slx_journal_next_event_id() : cur;
    if (parent_exec_id)
        *parent_exec_id = par;
    if (cause_id)
        *cause_id = is_exec ? (par ? par : 0) :(cur ? cur : par);
}

uint64_t slx_corr_cause_for(pid_t pid, pid_t ppid, const char *proc_id, const char *parent_proc_id,
int is_exec)
{
    uint64_t exec_id = 0, parent_exec_id = 0, cause_id = 0;
    (void)pid;
    (void)ppid;
    slx_corr_context(proc_id, parent_proc_id, is_exec, &exec_id, &parent_exec_id, &cause_id);
    return cause_id;
}

void slx_corr_note_event(uint64_t event_id, pid_t pid, const char *proc_id, int is_exec)
{
    if (!event_id || pid <= 0)
        return;
    uint64_t now = now_ns();
    prune(now);
    size_t i = find_proc(proc_id, pid);
    if (i >= count)
        return;
    ring[i].last_event_id = event_id;
    if (is_exec)
        ring[i].current_exec_id = event_id;
}

static void correlate(void)
{
    uint64_t now = now_ns();
    prune(now);
    for (size_t i = 0; i < count; i++) {
        struct corr *c = &ring[i];
        int score = c->score;
        if (c->exec && c->net)
            score += 25;
        if (c->ai && c->net)
            score += 25;
        if (c->uid == 0 && c->exec)
            score += 20;
        if (c->fim && c->net)
            score += 15;
        if (score >= 70 && (c->exec && c->net)) {
            struct slx_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.ts_ns = now;
            ev.type = c->ai ? SLX_EV_AI : SLX_EV_PROC;
            ev.score = score;
            ev.pid = c->pid;
            ev.ppid = c->ppid;
            ev.uid = c->uid;
            snprintf(ev.proc_id, sizeof(ev.proc_id), "%s", c->proc_id);
            snprintf(ev.parent_proc_id, sizeof(ev.parent_proc_id), "%s", c->parent_proc_id);
            slx_corr_context(ev.proc_id, ev.parent_proc_id, 0, &ev.exec_id, &ev.parent_exec_id, &ev.cause_id);
            snprintf(ev.subject, sizeof(ev.subject), "%s", c->subject[0] ? c->subject : "correlated-process");
            snprintf(ev.evidence, sizeof(ev.evidence), "120s correlation exec=%d ai=%d net=%d fim=%d score=%d",
            c->exec, c->ai, c->net, c->fim, score);
            snprintf(ev.tags, sizeof(ev.tags), "%s%s,correlation,investigate", c->ai ? "ai," : "", c->uid == 0 ?
            "root," : "");
            if (slx_journal_append(&ev) == 0)
                slx_corr_note_event(slx_journal_last_event_id(), ev.pid, ev.proc_id,
            0);
            printf("CORRELATION score=%d pid=%ld exec=%d ai=%d net=%d fim=%d\n", score, (long)c->pid, c->exec, c->ai,
            c->net, c->fim);
            c->score = 0;
        }
    }
}

void slx_corr_add_for_build(int kind, pid_t pid, pid_t ppid, uid_t uid, int score, const char *s,
const char *proc_id, const char *parent_proc_id)
{
    add(kind, pid, ppid, uid, score, s, proc_id, parent_proc_id);
}

void slx_correlation_tick(void)
{
    correlate();
}
