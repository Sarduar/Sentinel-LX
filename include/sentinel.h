#ifndef SENTINEL_H
#define SENTINEL_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#define SLX_PATH_MAX 4096
#define SLX_NAME_MAX 256
#define SLX_HASH_HEX 65
#define SLX_ID_MAX 128
#define SLX_JOURNAL_DEFAULT "/var/log/sentinel-lx/events.jsonl"
enum slx_event_type {
    SLX_EV_FIM = 1,
    SLX_EV_PROC = 2,
    SLX_EV_NET = 3,
    SLX_EV_AI = 4,
    SLX_EV_OVERFLOW = 5
};
struct slx_event {
    uint64_t ts_ns;
    enum slx_event_type type;
    int score;
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    uint64_t event_id;
    uint64_t cause_id;
    uint64_t exec_id;
    uint64_t parent_exec_id;
    char proc_id[SLX_ID_MAX];
    char parent_proc_id[SLX_ID_MAX];
    char subject[SLX_PATH_MAX];
    char evidence[512];
    char tags[256];
};
struct slx_sha256 {
    uint32_t h[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
};
void slx_sha256_init(struct slx_sha256 *context);
void slx_sha256_update(struct slx_sha256 *context, const void *data, size_t length);
void slx_sha256_final(struct slx_sha256 *context, uint8_t output[32]);
void slx_sha256_file(const char *path, char output_hex[SLX_HASH_HEX]);
int slx_journal_append(const struct slx_event *event);
int slx_json_event(const struct slx_event *event, char *output, size_t capacity);
int slx_journal_init(void);
void slx_journal_close(void);
const char *slx_journal_path(void);
uint64_t slx_journal_last_event_id(void);
uint64_t slx_journal_next_event_id(void);
int slx_journal_verify(const char *path);
int slx_collect_network(void);
int slx_scan_audit(void);
int slx_platform_init(void);
int slx_platform_poll(void);
void slx_platform_close(void);
void slx_correlation_tick(void);
uint64_t slx_corr_cause_for(pid_t pid, pid_t ppid, const char *proc_id, const char *parent_proc_id,
int is_exec);
void slx_corr_note_event(uint64_t event_id, pid_t pid, const char *proc_id, int is_exec);
void slx_corr_add_for_build(int kind, pid_t pid, pid_t ppid, uid_t uid, int score, const char *
subject, const char *proc_id, const char *parent_proc_id);
void slx_corr_context(const char *proc_id, const char *parent_proc_id, int is_exec, uint64_t *
exec_id, uint64_t *parent_exec_id, uint64_t *cause_id);
int slx_proc_identity(pid_t pid, char *proc_id, size_t proc_capacity, pid_t *ppid, uid_t *uid, char
*comm, size_t comm_capacity);
int slx_explain(int seconds);
void slx_ring_init(void);
void slx_ring_push(const struct slx_event *event);
void slx_ring_request_trigger(const char *reason);
void slx_ring_tick(void);
int slx_incident_chain_verify(const char *path);
int slx_incident_verify(const char *path);
int slx_incident_report(const char *path, const char *output_path);
int slx_sign_artifact(const char *path);
int slx_verify_artifact(const char *path);
int slx_self_harden(void);
int slx_ship_file(const char *path);
int slx_receive_server(void);
#endif
