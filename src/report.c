#include "sentinel.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#define REPORT_MAX_EVENTS 4096U
#define REPORT_LINE_MAX 16384U
#define REPORT_TEXT_MAX 256U
#define REPORT_CHAIN_MAX 32U
struct report_event {
    uint64_t event_id;
    uint64_t cause_id;
    uint64_t exec_id;
    uint64_t parent_exec_id;
    uint64_t ts_ns;
    int score;
    long pid;
    long ppid;
    long uid;
    char type[32];
    char proc_id[SLX_ID_MAX];
    char parent_proc_id[SLX_ID_MAX];
    char subject[SLX_PATH_MAX];
    char evidence[512];
    char tags[256];
};
struct capsule_metadata {
    int present;
    uint64_t trigger_event_id;
    uint64_t first_event_id;
    uint64_t last_event_id;
    uint64_t trigger_ts_ns;
    uint64_t begin_ts_ns;
    uint64_t end_ts_ns;
    char reason[REPORT_TEXT_MAX];
};
struct load_stats {
    size_t malformed_lines;
    size_t discarded_events;
};
struct report_stats {
    size_t high_signal_events;
    size_t overflow_events;
    size_t events_without_pid;
    size_t unresolved_causes;
    size_t missing_process_ids;
    size_t timestamp_reversals;
    size_t id_discontinuities;
    size_t id_order_issues;
    uint64_t skipped_event_ids;
    size_t resolved_causes;
    size_t events_without_causes;
};
static int find_value(const char *line, const char *key, const char **value)
{
    const char *found = strstr(line, key);
    if (found == NULL)
        return -1;
    *value = found + strlen(key);
    return 0;
}

static int get_u64(const char *line, const char *key, uint64_t *out)
{
    const char *start;
    char *end = NULL;
    unsigned long long value;
    if (find_value(line, key, &start) != 0 || *start == '-')
        return -1;
    errno = 0;
    value = strtoull(start, &end, 10);
    if (errno != 0 || end == start)
        return -1;
    *out = (uint64_t)value;
    return 0;
}

static int get_long(const char *line, const char *key, long *out)
{
    const char *start;
    char *end = NULL;
    long value;
    if (find_value(line, key, &start) != 0)
        return -1;
    errno = 0;
    value = strtol(start, &end, 10);
    if (errno != 0 || end == start)
        return -1;
    *out = value;
    return 0;
}

static int get_string(const char *line, const char *key, char *out, size_t capacity)
{
    const char *start;
    size_t source_len = 0U;
    size_t source_pos = 0U;
    size_t dest_pos = 0U;
    if (capacity == 0U || find_value(line, key, &start) != 0)
        return -1;
    while (start[source_len] != '\0' && start[source_len] != '"') {
        if (start[source_len] == '\\' && start[source_len + 1U] != '\0')
            source_len += 2U;
        else++source_len;
    }
    if (start[source_len] != '"')
        return -1;
    while (source_pos < source_len && dest_pos + 1U < capacity) {
        if (start[source_pos] == '\\' && source_pos + 1U < source_len) {
            ++source_pos;
            switch (start[source_pos]) {
                case 'n':
                out[dest_pos++] = ' ';
                break;
                case 'r':
                out[dest_pos++] = ' ';
                break;
                case 't':
                out[dest_pos++] = ' ';
                break;
                case '"':
                out[dest_pos++] = '"';
                break;
                case '\\':
                out[dest_pos++] = '\\';
                break;
                default:
                out[dest_pos++] = '?';
                break;
            }
            ++source_pos;
        } else {
            out[dest_pos++] = start[source_pos++];
        }
    }
    if (source_pos != source_len)
        return -1;
    out[dest_pos] = '\0';
    return 0;
}

static int parse_event(const char *line, struct report_event *event)
{
    long number = 0L;
    memset(event, 0, sizeof(*event));
    if (get_u64(line, "\"event_id\":", &event->event_id) != 0 || get_u64(line, "\"ts_ns\":", &event->ts_ns)
    != 0 || get_string(line, "\"type\":\"", event->type, sizeof(event->type)) != 0 || event->event_id ==
    0U || event->ts_ns == 0U || event->type[0] == '\0') return -1;
    (void)get_u64(line, "\"cause_id\":", &event->cause_id);
    (void)get_u64(line, "\"exec_id\":", &event->exec_id);
    (void)get_u64(line, "\"parent_exec_id\":", &event->parent_exec_id);
    if (get_long(line, "\"score\":", &number) == 0)
        event->score = (int)number;
    (void)get_long(line, "\"pid\":", &event->pid);
    (void)get_long(line, "\"ppid\":", &event->ppid);
    (void)get_long(line, "\"uid\":", &event->uid);
    (void)get_string(line, "\"proc_id\":\"", event->proc_id, sizeof(event->proc_id));
    (void)get_string(line, "\"parent_proc_id\":\"", event->parent_proc_id, sizeof(event->parent_proc_id));
    (void)get_string(line, "\"subject\":\"", event->subject, sizeof(event->subject));
    (void)get_string(line, "\"evidence\":\"", event->evidence, sizeof(event->evidence));
    (void)get_string(line, "\"tags\":\"", event->tags, sizeof(event->tags));
    return 0;
}

static void parse_capsule_metadata(const char *line, struct capsule_metadata *metadata)
{
    if (strstr(line, "\"format\":\"slx-incident-v1\"") == NULL)
        return;
    metadata->present = 1;
    (void)get_u64(line, "\"trigger_event_id\":", &metadata->trigger_event_id);
    (void)get_u64(line, "\"first_event_id\":", &metadata->first_event_id);
    (void)get_u64(line, "\"last_event_id\":", &metadata->last_event_id);
    (void)get_u64(line, "\"trigger_ts_ns\":", &metadata->trigger_ts_ns);
    (void)get_u64(line, "\"begin_ts_ns\":", &metadata->begin_ts_ns);
    (void)get_u64(line, "\"end_ts_ns\":", &metadata->end_ts_ns);
    (void)get_string(line, "\"reason\":\"", metadata->reason, sizeof(metadata->reason));
}

static int load_events(const char *path, struct report_event * *events, size_t *event_count, struct
capsule_metadata *metadata, struct load_stats *stats)
{
    FILE *file;
    struct report_event *items;
    size_t count = 0U;
    char line[REPORT_LINE_MAX];
    if (path == NULL || *path == '\0' || events == NULL || event_count == NULL)
        return -1;
    file = fopen(path, "r");
    if (file == NULL)
        return -1;
    items = calloc(REPORT_MAX_EVENTS, sizeof(*items));
    if (items == NULL) {
        (void)fclose(file);
        return -1;
    }
    if (metadata != NULL)
        memset(metadata, 0, sizeof(*metadata));
    if (stats != NULL)
        memset(stats, 0, sizeof(*stats));
    while (fgets(line, sizeof(line), file) != NULL) {
        struct report_event event;
        size_t length = strlen(line);
        if (metadata != NULL && !metadata->present)
            parse_capsule_metadata(line, metadata);
        if (length == sizeof(line) - 1U && line[length - 1U] != '\n' && !feof(file)) {
            int ch;
            while ((ch = fgetc(file)) != '\n' && ch != EOF);
            if (stats != NULL)
                ++stats->malformed_lines;
            continue;
        }
        if (parse_event(line, &event) != 0) {
            if (metadata != NULL && metadata->present && count == 0U && strstr(line,
            "\"format\":\"slx-incident-v1\"") != NULL) continue;
            if (stats != NULL)
                ++stats->malformed_lines;
            continue;
        }
        if (count < REPORT_MAX_EVENTS) {
            items[count++] = event;
        } else {
            memmove(items, items + 1U, (REPORT_MAX_EVENTS - 1U) * sizeof(items[0]));
            items[REPORT_MAX_EVENTS - 1U] = event;
            if (stats != NULL)
                ++stats->discarded_events;
        }
    }
    if (ferror(file)) {
        free(items);
        (void)fclose(file);
        return -1;
    }
    if (fclose(file) != 0) {
        free(items);
        return -1;
    }
    *events = items;
    *event_count = count;
    return count > 0U ? 0 : -1;
}

static void format_time(uint64_t timestamp_ns, char output[32])
{
    time_t seconds = (time_t)(timestamp_ns / 1000000000ULL);
    struct tm local_time;
    if (localtime_r(&seconds, &local_time) == NULL) {
        (void)snprintf(output, 32U, "unknown-time");
        return;
    }
    if (strftime(output, 32U, "%Y-%m-%d %H:%M:%S", &local_time) == 0U)
        (void)snprintf(output, 32U,
    "unknown-time");
}

static ssize_t find_event(const struct report_event *events, size_t count, uint64_t event_id)
{
    size_t i;
    if (event_id == 0U)
        return -1;
    for (i = 0U; i < count; ++i) {
        if (events[i].event_id == event_id)
            return (ssize_t)i;
    }
    return -1;
}

static void print_relationship_trace(FILE *out, const struct report_event *events, size_t count,
size_t start)
{
    size_t index = start;
    size_t depth;
    for (depth = 0U; depth < REPORT_CHAIN_MAX; ++depth) {
        const struct report_event *event = &events[index];
        ssize_t parent;
        (void)fprintf(out, "  #%" PRIu64 " type=%s score=%d", event->event_id, event->type, event->score);
        if (event->pid != 0L)
            (void)fprintf(out, " pid=%ld", event->pid);
        if (event->subject[0] != '\0')
            (void)fprintf(out, " subject=%s", event->subject);
        (void)fputc('\n', out);
        if (event->cause_id == 0U)
            return;
        parent = find_event(events, count, event->cause_id);
        if (parent < 0) {
            (void)fprintf(out, "  cause reference #%" PRIu64 " is outside this capsule\n", event->cause_id);
            return;
        }
        index = (size_t)parent;
    }
    (void)fprintf(out, "  trace stopped at %u links to prevent an endless loop\n", REPORT_CHAIN_MAX);
}

static void collect_report_stats(const struct report_event *events, size_t count, struct
report_stats *stats)
{
    size_t i;
    memset(stats, 0, sizeof(*stats));
    for (i = 0U; i < count; ++i) {
        const struct report_event *event = &events[i];
        if (event->score >= 70)
            ++stats->high_signal_events;
        if (strcmp(event->type, "overflow") == 0)
            ++stats->overflow_events;
        if (event->pid <= 0L)
            ++stats->events_without_pid;
        if (event->pid > 0L && event->proc_id[0] == '\0')
            ++stats->missing_process_ids;
        if (event->cause_id == 0U) {
            ++stats->events_without_causes;
        } else if (find_event(events, count, event->cause_id) < 0) {
            ++stats->unresolved_causes;
        } else {
            ++stats->resolved_causes;
        }
        if (i > 0U) {
            if (event->ts_ns < events[i - 1U].ts_ns)
                ++stats->timestamp_reversals;
            if (event->event_id <= events[i - 1U].event_id) {
                ++stats->id_order_issues;
            } else if (events[i - 1U].event_id != UINT64_MAX && event->event_id > events[i - 1U].event_id + 1U) {
                ++stats->id_discontinuities;
                stats->skipped_event_ids += event->event_id - events[i - 1U].event_id - 1U;
            }
        }
    }
}

static int signature_file_exists(const char *path)
{
    char signature_path[SLX_PATH_MAX];
    struct stat status;
    int length = snprintf(signature_path, sizeof(signature_path), "%s.sig", path);
    if (length < 0 || (size_t)length >= sizeof(signature_path))
        return 0;
    return stat(signature_path, &status) == 0 && S_ISREG(status.st_mode);
}

static void print_timeline(FILE *out, const struct report_event *events, size_t count)
{
    size_t i;
    (void)fprintf(out, "Observed facts\n--------------\n");
    (void)fprintf(out, "Records in capsule: %zu\n", count);
    (void)fprintf(out, "Time values below use the local timezone.\n\n");
    for (i = 0U; i < count; ++i) {
        const struct report_event *event = &events[i];
        char timestamp[32];
        format_time(event->ts_ns, timestamp);
        (void)fprintf(out, "%s  #%" PRIu64 "  type=%s score=%d pid=%ld ppid=%ld uid=%ld\n", timestamp, event->event_id,
        event->type, event->score, event->pid, event->ppid, event->uid);
        (void)fprintf(out, "  subject: %s\n", event->subject[0] ? event->subject : "(not recorded)");
        (void)fprintf(out, "  proc_id: %s  parent_proc_id: %s\n", event->proc_id[0] ? event->proc_id :
        "(not recorded)", event->parent_proc_id[0] ? event->parent_proc_id : "(not recorded)");
        (void)fprintf(out, "  cause_id: #%" PRIu64 "  exec_id: #%" PRIu64 "  parent_exec_id: #%" PRIu64 "\n",
        event->cause_id, event->exec_id, event->parent_exec_id);
        if (event->evidence[0] != '\0')
            (void)fprintf(out, "  evidence: %s\n", event->evidence);
        if (event->tags[0] != '\0')
            (void)fprintf(out, "  tags: %s\n", event->tags);
    }
    (void)fputc('\n', out);
}

static void print_unknowns(FILE *out, const struct report_event *events, size_t count, const struct
load_stats *load, const struct report_stats *stats, const struct capsule_metadata *metadata, int
metadata_range_mismatch, int chain_valid, int signature_present, int signature_checked, int
signature_valid)
{
    size_t i;
    size_t shown;
    (void)fprintf(out, "Unknowns and coverage limits\n----------------------------\n");
    if (!chain_valid)
        (void)fprintf(out,
    "- The capsule hash chain failed verification. Do not rely on its integrity.\n");
    if (load->malformed_lines > 0U)
        (void)fprintf(out,
    "- %zu line(s) could not be parsed and are absent from the timeline.\n", load->malformed_lines);
    if (load->discarded_events > 0U)
        (void)fprintf(out,
    "- %zu event(s) were omitted because the report limit is %u events.\n", load->discarded_events,
    REPORT_MAX_EVENTS);
    if (metadata_range_mismatch)
        (void)fprintf(out, "- The capsule header declares #%" PRIu64 "..#%"
    PRIu64 ", but parsed records run from #%" PRIu64 " to #%" PRIu64
    ". The declared capture range and parsed content disagree.\n", metadata->first_event_id, metadata->last_event_id,
    events[0].event_id, events[count - 1U].event_id);
    if (stats->overflow_events > 0U)
        (void)fprintf(out,
    "- %zu explicit overflow event(s) indicate a recorded telemetry or internal-processing problem.\n",
    stats->overflow_events);
    else(void)fprintf(out,
    "- No explicit overflow event is present; this does not prove that telemetry was complete.\n");
    if (stats->id_discontinuities > 0U)
        (void)fprintf(out,
    "- %zu event-ID discontinuity/discontinuities skip %" PRIu64
    " ID(s) inside the capsule. Selection or timestamp effects may explain this; it is not proof of telemetry loss.\n",
    stats->id_discontinuities, stats->skipped_event_ids);
    if (stats->id_order_issues > 0U)
        (void)fprintf(out,
    "- %zu event-ID ordering issue(s) occur; duplicate or reversed IDs make record ordering ambiguous.\n",
    stats->id_order_issues);
    if (stats->timestamp_reversals > 0U)
        (void)fprintf(out,
    "- %zu timestamp reversal(s) occur in stored record order; exact chronology may be uncertain.\n",
    stats->timestamp_reversals);
    if (stats->unresolved_causes > 0U)
        (void)fprintf(out,
    "- %zu cause reference(s) point outside this capsule. Their parent events cannot be inspected here.\n",
    stats->unresolved_causes);
    if (stats->events_without_pid > 0U)
        (void)fprintf(out,
    "- %zu event(s) have no usable PID; their originating process cannot be identified from these records.\n",
    stats->events_without_pid);
    if (stats->events_without_causes > 0U)
        (void)fprintf(out,
    "- %zu event(s) have no cause_id; no parent-event relationship was recorded for them.\n", stats->events_without_causes);
    if (stats->missing_process_ids > 0U) {
        (void)fprintf(out,
        "- %zu event(s) have a PID but no proc_id; stable process attribution is unavailable for those events:",
        stats->missing_process_ids);
        shown = 0U;
        for (i = 0U; i < count && shown < 8U; ++i) {
            if (events[i].pid > 0L && events[i].proc_id[0] == '\0') {
                (void)fprintf(out, " #%" PRIu64, events[i].event_id);
                ++shown;
            }
        }
        if (shown < stats->missing_process_ids)
            (void)fprintf(out, " (first %zu shown)", shown);
        (void)fputc('\n', out);
    }
    if (!signature_present) {
        (void)fprintf(out,
        "- No signature sidecar is present; the hash chain alone does not establish who created the capsule.\n");
    } else if (!signature_checked) {
        (void)fprintf(out,
        "- A signature sidecar is present but was not verified because SLX_VERIFY_KEY is not set.\n");
    } else if (!signature_valid) {
        (void)fprintf(out, "- Signature verification failed; signer authenticity is not established.\n");
    }
    (void)fprintf(out, "Limitations\n-----------\n");
    (void)fprintf(out,
    "This report summarizes available telemetry. Missing events, limited sensor coverage, clock changes, or host compromise can invalidate conclusions.\n");
    (void)fprintf(out,
    "Hash-chain verification detects changes to chained records; a verified signature additionally depends on trusting the signing key and the collection environment.\n");
}

int slx_explain(int seconds)
{
    const char *journal_path = slx_journal_path();
    struct report_event *events = NULL;
    struct capsule_metadata metadata;
    struct load_stats load;
    size_t count = 0U;
    size_t first = 0U;
    size_t root = 0U;
    size_t overflow_count = 0U;
    size_t high_signal_count = 0U;
    int max_score = -1;
    int integrity;
    uint64_t latest;
    uint64_t window_ns;
    uint64_t begin;
    size_t i;
    if (seconds <= 0)
        seconds = 300;
    if (load_events(journal_path, &events, &count, &metadata, &load) != 0) {
        (void)printf("SENTINEL-LX BLACKBOX\nno events\n");
        return 0;
    }
    latest = events[count - 1U].ts_ns;
    window_ns = (uint64_t)(unsigned int)seconds * 1000000000ULL;
    begin = latest > window_ns ? latest - window_ns : 0U;
    while (first < count && events[first].ts_ns < begin)
        ++first;
    root = first;
    for (i = first; i < count; ++i) {
        if (strcmp(events[i].type, "overflow") == 0)
            ++overflow_count;
        if (events[i].score >= 70)
            ++high_signal_count;
        if (events[i].score > max_score) {
            max_score = events[i].score;
            root = i;
        }
    }
    integrity = slx_journal_verify(journal_path) == 0;
    (void)printf("SENTINEL-LX BLACKBOX\nwindow=%ds events=%zu high_signal=%zu telemetry_gaps=%zu\n",
    seconds, count - first, high_signal_count, overflow_count);
    (void)printf("EVIDENCE integrity=%s\n", integrity ? "verified" : "broken-or-unverified");
    (void)printf("TIMELINE\n");
    for (i = first; i < count; ++i) {
        char timestamp[32];
        format_time(events[i].ts_ns, timestamp);
        (void)printf("%s  #%" PRIu64 "  score=%d  %-8s pid=%ld ppid=%ld uid=%ld  %s", timestamp, events[i].event_id,
        events[i].score, events[i].type, events[i].pid, events[i].ppid, events[i].uid, events[i].subject);
        if (events[i].proc_id[0] != '\0')
            (void)printf("  proc=%s", events[i].proc_id);
        if (events[i].cause_id != 0U)
            (void)printf("  <- #%" PRIu64, events[i].cause_id);
        (void)putchar('\n');
    }
    (void)printf("CHAIN\nRecorded cause_id references are not proof of causality.\n");
    print_relationship_trace(stdout, events, count, root);
    free(events);
    return 0;
}

int slx_incident_report(const char *path, const char *out_path)
{
    struct report_event *events = NULL;
    struct capsule_metadata metadata;
    struct load_stats load;
    struct report_stats stats;
    size_t count = 0U;
    size_t lead = 0U;
    size_t i;
    int max_score = -1;
    int chain_valid;
    int signature_present;
    int signature_checked;
    int signature_valid = 0;
    int metadata_range_mismatch;
    const char *verify_key = getenv("SLX_VERIFY_KEY");
    FILE *out = stdout;
    int close_out = 0;
    int result = -1;
    if (load_events(path, &events, &count, &metadata, &load) != 0)
        return -1;
    if (out_path != NULL && *out_path != '\0') {
        out = fopen(out_path, "w");
        if (out == NULL) {
            free(events);
            return -1;
        }
        close_out = 1;
    }
    for (i = 0U; i < count; ++i) {
        if (events[i].score > max_score) {
            max_score = events[i].score;
            lead = i;
        }
    }
    collect_report_stats(events, count, &stats);
    metadata_range_mismatch = metadata.present && (metadata.first_event_id != events[0].event_id ||
    metadata.last_event_id != events[count - 1U].event_id);
    chain_valid = slx_incident_chain_verify(path) == 0;
    signature_present = signature_file_exists(path);
    signature_checked = verify_key != NULL && *verify_key != '\0';
    if (signature_present && signature_checked)
        signature_valid = slx_verify_artifact(path) == 0;
    (void)fprintf(out, "Sentinel-LX Incident Report\n");
    (void)fprintf(out, "===========================\n\n");
    (void)fprintf(out, "Capsule: %s\n", path);
    if (metadata.present) {
        char trigger_time[32];
        format_time(metadata.trigger_ts_ns, trigger_time);
        (void)fprintf(out, "Trigger event: #%" PRIu64 " (%s)\n", metadata.trigger_event_id, trigger_time);
        (void)fprintf(out, "Capture reason: %s\n", metadata.reason[0] ? metadata.reason : "(not recorded)");
        (void)fprintf(out, "Declared ID range: #%" PRIu64 "..#%" PRIu64 "\n", metadata.first_event_id,
        metadata.last_event_id);
    }
    (void)fprintf(out, "Records parsed: %zu\n", count);
    (void)fprintf(out, "High-signal events (score >= 70): %zu\n", stats.high_signal_events);
    (void)fprintf(out, "Explicit overflow events: %zu\n\n", stats.overflow_events);
    (void)fprintf(out, "Evidence integrity\n------------------\n");
    (void)fprintf(out, "Hash chain: %s\n", chain_valid ? "VERIFIED" : "FAILED");
    if (!signature_present) {
        (void)fprintf(out, "Signature: NOT PRESENT\n");
    } else if (!signature_checked) {
        (void)fprintf(out, "Signature: PRESENT, NOT VERIFIED (SLX_VERIFY_KEY is unset)\n");
    } else {
        (void)fprintf(out, "Signature: %s\n", signature_valid ? "VERIFIED" : "FAILED");
    }
    (void)fprintf(out, "Parser: %zu malformed line(s), %zu event(s) beyond report limit\n\n", load.malformed_lines,
    load.discarded_events);
    print_timeline(out, events, count);
    (void)fprintf(out, "Lead event (highest recorded score)\n-----------------------------------\n");
    {
        char timestamp[32];
        const struct report_event *event = &events[lead];
        format_time(event->ts_ns, timestamp);
        (void)fprintf(out, "%s  #%" PRIu64 " score=%d type=%s pid=%ld subject=%s\n", timestamp, event->event_id,
        event->score, event->type, event->pid, event->subject[0] ? event->subject : "(not recorded)");
        (void)fprintf(out, "proc_id=%s exec_id=#%" PRIu64 " parent_exec_id=#%" PRIu64 "\n\n", event->proc_id
        [0] ? event->proc_id : "(not recorded)", event->exec_id, event->parent_exec_id);
    }
    (void)fprintf(out, "Recorded relationship trace\n---------------------------\n");
    print_relationship_trace(out, events, count, lead);
    (void)fputc('\n', out);
    (void)fprintf(out, "Derived relationships\n---------------------\n");
    (void)fprintf(out,
    "cause_id links resolved inside capsule: %zu; links outside capsule: %zu; events without cause_id: %zu\n",
    stats.resolved_causes, stats.unresolved_causes, stats.events_without_causes);
    (void)fprintf(out,
    "A cause_id link is a recorded relationship, not proof that one event caused another.\n\n");
    print_unknowns(out, events, count, &load, &stats, &metadata, metadata_range_mismatch, chain_valid,
    signature_present, signature_checked, signature_valid);
    if (ferror(out))
        goto cleanup;
    result = 0;
    cleanup:
        if (close_out && fclose(out) != 0)
            result = -1;
    free(events);
    return result;
}
