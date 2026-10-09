#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/sentinel-lx-explain.XXXXXX)
JOURNAL="$TMP/events.jsonl"
WATCH="$TMP/watch"
mkdir -p "$WATCH"
cleanup(){ if [ -n "${PID:-}" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT INT TERM
SLX_JOURNAL="$JOURNAL" "$ROOT/sentinel-lx" "$WATCH" >"$TMP/sensor.out" 2>&1 & PID=$!
sleep 1
printf 'blackbox\n' >"$WATCH/file.txt"
sleep 1
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
SLX_JOURNAL="$JOURNAL" "$ROOT/sentinel-lx" --explain 300 >"$TMP/report.txt"
grep -q '^SENTINEL-LX BLACKBOX$' "$TMP/report.txt"
grep -q '^TIMELINE$' "$TMP/report.txt"
grep -q '^CHAIN$' "$TMP/report.txt"
grep -q 'file.txt' "$TMP/report.txt"
echo 'test_explain: PASS'
