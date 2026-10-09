#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/sentinel-lx-report.XXXXXX)
WATCH="$TMP/watch"
JOURNAL="$TMP/events.jsonl"
PID=

cleanup()
{
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

mkdir -p "$WATCH"
openssl genpkey -algorithm ED25519 -out "$TMP/signing.pem" >/dev/null 2>&1
openssl pkey -in "$TMP/signing.pem" -pubout -out "$TMP/verify.pem" >/dev/null 2>&1

SLX_JOURNAL="$JOURNAL" \
SLX_SIGNING_KEY="$TMP/signing.pem" \
SLX_RING_SECONDS=1 \
SLX_INCIDENT_POST_SECONDS=1 \
SLX_INCIDENT_THRESHOLD=70 \
    "$ROOT/sentinel-lx" "$WATCH" >"$TMP/sensor.out" 2>&1 &
PID=$!
sleep 1
kill -USR1 "$PID" 2>/dev/null || true
printf 'report test\n' > "$WATCH/evidence.txt"
sleep 3
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=

CAP=$(find "$TMP" -name 'events.jsonl.incident-*.jsonl' -type f | head -1)
[ -n "$CAP" ]
[ -s "$CAP.sig" ]

SLX_VERIFY_KEY="$TMP/verify.pem" \
    "$ROOT/sentinel-lx" --report "$CAP" "$TMP/report.txt"
grep -q '^Evidence integrity$' "$TMP/report.txt"
grep -q '^Hash chain: VERIFIED$' "$TMP/report.txt"
grep -q '^Signature: VERIFIED$' "$TMP/report.txt"
grep -q '^Observed facts$' "$TMP/report.txt"
grep -q '^Derived relationships$' "$TMP/report.txt"
grep -q '^Unknowns and coverage limits$' "$TMP/report.txt"
grep -q 'limited sensor coverage' "$TMP/report.txt"
grep -q 'no usable PID' "$TMP/report.txt"
grep -q 'evidence.txt' "$TMP/report.txt"
FACTS_LINE=$(grep -n '^Observed facts$' "$TMP/report.txt" | cut -d: -f1)
RELATIONS_LINE=$(grep -n '^Derived relationships$' "$TMP/report.txt" | cut -d: -f1)
UNKNOWNS_LINE=$(grep -n '^Unknowns and coverage limits$' "$TMP/report.txt" | cut -d: -f1)
[ "$FACTS_LINE" -lt "$RELATIONS_LINE" ]
[ "$RELATIONS_LINE" -lt "$UNKNOWNS_LINE" ]

cp "$CAP" "$TMP/tampered.jsonl"
printf 'tamper\n' >> "$TMP/tampered.jsonl"
"$ROOT/sentinel-lx" --report "$TMP/tampered.jsonl" "$TMP/tampered-report.txt"
grep -q '^Hash chain: FAILED$' "$TMP/tampered-report.txt"
grep -q 'hash chain failed verification' "$TMP/tampered-report.txt"

echo 'test_report_evidence: PASS'
