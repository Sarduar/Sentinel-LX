#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/sentinel-lx-journal.XXXXXX)
WATCH="$TMP/watch"
mkdir -p "$WATCH"
trap 'if [ -n "${PID:-}" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"' EXIT INT TERM
J="$TMP/events.jsonl"
SLX_JOURNAL="$J" SLX_RING_SECONDS=1 SLX_INCIDENT_POST_SECONDS=1 "$ROOT/sentinel-lx" "$WATCH" >/dev/null 2>&1 & PID=$!
sleep 1
if SLX_JOURNAL="$J" "$ROOT/sentinel-lx" --scan-audit >/dev/null 2>&1; then
    echo 'test_journal_verify: FAIL (second writer acquired journal)'
    exit 1
fi
printf 'journal
' > "$WATCH/file"
sleep 1
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
"$ROOT/sentinel-lx" --verify-journal "$J"
printf 'tamper
' >> "$J"
if "$ROOT/sentinel-lx" --verify-journal "$J" >/dev/null 2>&1; then
    echo 'test_journal_verify: FAIL'
    exit 1
fi
echo 'test_journal_verify: PASS'
