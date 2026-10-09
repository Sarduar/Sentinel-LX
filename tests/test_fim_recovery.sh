#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/sentinel-lx-fim.XXXXXX)
WATCH="$TMP/watch"
J="$TMP/events.jsonl"
trap 'if [ -n "${PID:-}" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$WATCH"
SLX_JOURNAL="$J" "$ROOT/sentinel-lx" "$WATCH" >"$TMP/out" 2>&1 & PID=$!
sleep 1
mkdir -p "$WATCH/new/sub"
printf 'nested\n' > "$WATCH/new/sub/file"
sleep 1
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
grep -q 'new/sub/file' "$J"
echo 'test_fim_recovery: PASS'
