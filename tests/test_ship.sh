#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/sentinel-lx-ship.XXXXXX)
cleanup(){ if [ -n "${RPID:-}" ]; then kill "$RPID" 2>/dev/null || true; wait "$RPID" 2>/dev/null || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT INT TERM
mkdir -p "$TMP/ca" "$TMP/store"
chmod 700 "$TMP/store"
cd "$TMP"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -subj '/CN=SLX Test CA' -days 1 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj '/CN=localhost' >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 1 -sha256 -extfile server.ext >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj '/CN=slx-client' >/dev/null 2>&1
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 1 -sha256 >/dev/null 2>&1
CLIENT_SHA256=$(openssl x509 -in client.crt -outform DER | openssl dgst -sha256 -hex | awk '{print $NF}')
WATCH="$TMP/watch"; mkdir -p "$WATCH"
openssl genpkey -algorithm ED25519 -out "$TMP/signing.pem" >/dev/null 2>&1
openssl pkey -in "$TMP/signing.pem" -pubout -out "$TMP/verify.pem" >/dev/null 2>&1
JOURNAL="$TMP/events.jsonl"
SLX_JOURNAL="$JOURNAL" SLX_SIGNING_KEY="$TMP/signing.pem" SLX_RING_SECONDS=5 SLX_INCIDENT_POST_SECONDS=2 SLX_INCIDENT_THRESHOLD=70 "$ROOT/sentinel-lx" "$WATCH" >"$TMP/sensor.out" 2>&1 & SPID=$!
sleep 1
kill -USR1 "$SPID"
printf 'ship-test\n' > "$WATCH/file"
sleep 3
kill "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true
CAP=""
for _ in 1 2 3 4 5 6; do
    CAP=$(find "$TMP" -name 'events.jsonl.incident-*.jsonl' -type f | head -1)
    [ -n "$CAP" ] && break
    sleep 1
done
[ -n "$CAP" ]
SLX_JOURNAL="$JOURNAL" "$ROOT/sentinel-lx" --verify-incident "$CAP" >/dev/null
SLX_RECEIVE_BIND=127.0.0.1 SLX_RECEIVE_PORT=24444 SLX_RECEIVE_CA="$TMP/ca.crt" SLX_RECEIVE_CERT="$TMP/server.crt" SLX_RECEIVE_KEY="$TMP/server.key" SLX_RECEIVE_STORE="$TMP/store" SLX_RECEIVE_TMP="$TMP/store" SLX_RECEIVE_CLIENT_SHA256="$CLIENT_SHA256" SLX_VERIFY_KEY="$TMP/verify.pem" "$ROOT/sentinel-lx" --receive >"$TMP/receiver.out" 2>&1 & RPID=$!
sleep 1
SLX_SHIP_HOST=127.0.0.1 SLX_SHIP_PORT=24444 SLX_SHIP_CA="$TMP/ca.crt" SLX_SHIP_CERT="$TMP/client.crt" SLX_SHIP_KEY="$TMP/client.key" SLX_SHIP_SERVER_NAME=localhost SLX_VERIFY_KEY="$TMP/verify.pem" SLX_SHIP_REQUIRE_SIGNATURE=1 "$ROOT/sentinel-lx" --ship "$CAP" >"$TMP/ship.out"
kill "$RPID" 2>/dev/null || true
wait "$RPID" 2>/dev/null || true
grep -q '^shipped capsule=' "$TMP/ship.out"
find "$TMP/store" -name '*.jsonl' -type f | grep -q .
STORED=$(find "$TMP/store" -name '*.jsonl' -type f | head -1)
[ -s "$STORED.sig" ]
SLX_VERIFY_KEY="$TMP/verify.pem" "$ROOT/sentinel-lx" --verify-incident "$STORED" >/dev/null
echo 'test_ship: PASS'
