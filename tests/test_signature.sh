#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/sentinel-lx-signature.XXXXXX)
WATCH="$TMP/watch"
J="$TMP/events.jsonl"
trap 'if [ -n "${PID:-}" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$WATCH"
openssl genpkey -algorithm ED25519 -out "$TMP/signing.pem" >/dev/null 2>&1
openssl pkey -in "$TMP/signing.pem" -pubout -out "$TMP/verify.pem" >/dev/null 2>&1
SLX_JOURNAL="$J" SLX_SIGNING_KEY="$TMP/signing.pem" SLX_RING_SECONDS=1 SLX_INCIDENT_POST_SECONDS=1 SLX_INCIDENT_THRESHOLD=70 "$ROOT/sentinel-lx" "$WATCH" >"$TMP/out" 2>&1 & PID=$!
sleep 1
kill -USR1 "$PID"
printf 'signed\n' > "$WATCH/file"
sleep 3
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
CAP=$(find "$TMP" -name 'events.jsonl.incident-*.jsonl' -type f | head -1)
[ -n "$CAP" ]
[ -s "$CAP.sig" ]
SLX_VERIFY_KEY="$TMP/verify.pem" "$ROOT/sentinel-lx" --verify-incident "$CAP" >/dev/null
printf 'tamper\n' >> "$CAP"
if SLX_VERIFY_KEY="$TMP/verify.pem" "$ROOT/sentinel-lx" --verify-incident "$CAP" >/dev/null 2>&1; then exit 1; fi
echo 'test_signature: PASS'
