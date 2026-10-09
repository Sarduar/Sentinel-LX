#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/sentinel-lx-ring.XXXXXX)
JOURNAL="$TMP/events.jsonl"
WATCH="$TMP/watch"
mkdir -p "$WATCH"
cleanup(){ if [ -n "${PID:-}" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT INT TERM
SLX_JOURNAL="$JOURNAL" SLX_RING_SECONDS=5 SLX_INCIDENT_POST_SECONDS=2 SLX_INCIDENT_THRESHOLD=70 "$ROOT/sentinel-lx" "$WATCH" >"$TMP/out" 2>&1 & PID=$!
sleep 1
kill -USR1 "$PID"
printf 'before-after\n' >"$WATCH/ring.txt"
sleep 4
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
CAP=$(find "$TMP" -name 'events.jsonl.incident-*.jsonl' -type f | head -1)
[ -n "$CAP" ]
[ -s "$CAP" ]
grep -q 'ring.txt' "$CAP"
SLX_JOURNAL="$JOURNAL" "$ROOT/sentinel-lx" --verify-incident "$CAP" >/dev/null
echo 'test_ring: PASS'
