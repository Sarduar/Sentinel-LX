#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/sentinel-lx-scenario.XXXXXX)
JOURNAL="$TMP/events.jsonl"
WATCH="$TMP/watch"
mkdir -p "$WATCH"
cleanup(){ if [ -n "${PID:-}" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT INT TERM
SLX_JOURNAL="$JOURNAL" "$ROOT/sentinel-lx" "$WATCH" >"$TMP/sensor.out" 2>&1 & PID=$!
sleep 1
printf 'scenario benign file mutation\n' >"$WATCH/benign.txt"
/bin/sh -c 'sleep 1' >/dev/null 2>&1 & SPID=$!
wait "$SPID"
sleep 1
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
[ -s "$JOURNAL" ]
grep -q '"type":"fim"' "$JOURNAL"
grep -q '"subject":"'$WATCH'/benign.txt"' "$JOURNAL"
cp "$JOURNAL" "$TMP/first.jsonl"
SLX_JOURNAL="$JOURNAL" "$ROOT/sentinel-lx" "$WATCH" >"$TMP/sensor2.out" 2>&1 & PID=$!
sleep 1
printf 'restart continuity\n' >>"$WATCH/benign.txt"
sleep 1
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
awk 'BEGIN{ok=0} /"event_hash"/{h=$0; sub(/^.*"event_hash":"/,"",h); sub(/".*$/,"",h); if(prev!="" && $0 ~ ("\"prev_hash\":\"" prev "\"")) ok=1; prev=h} END{exit ok?0:1}' "$JOURNAL"
echo 'scenario_local: PASS'
