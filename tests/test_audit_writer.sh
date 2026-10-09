#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/sentinel-lx-audit.XXXXXX)
JOURNAL="$TMP/events.jsonl"
AUDIT="$TMP/audit.log"
trap 'rm -rf "$TMP"' EXIT INT TERM
cat >"$AUDIT" <<'LOG'
type=SYSCALL msg=audit(1.0:10): arch=c000003e syscall=257 success=yes exit=3 a0=3 a1=140737488 a2=577 a3=0 items=1 ppid=100 pid=123 uid=1000 gid=1000 comm="python" exe="/usr/bin/python3"
type=PATH msg=audit(1.0:10): item=0 name="/tmp/written.txt" inode=1 dev=00:00 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL
type=SYSCALL msg=audit(1.0:11): arch=c000003e syscall=257 success=yes exit=3 a0=3 a1=140737488 a2=64 a3=0644 items=1 ppid=100 pid=124 uid=0 gid=0 comm="sh" exe="/bin/sh"
type=PATH msg=audit(1.0:11): item=0 name="/tmp/created.txt" inode=2 dev=00:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE
LOG
make -C "$ROOT" >/dev/null
SLX_JOURNAL="$JOURNAL" SLX_AUDIT_PATH="$AUDIT" "$ROOT/sentinel-lx" --scan-audit >/dev/null
grep -q 'writer-pid' "$JOURNAL"
grep -q 'written.txt' "$JOURNAL"
grep -q 'created.txt' "$JOURNAL"
echo 'test_audit_writer: PASS'
