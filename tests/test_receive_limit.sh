#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/sentinel-lx-recv-limit.XXXXXX)
trap 'if [ -n "${RPID:-}" ]; then kill "$RPID" 2>/dev/null || true; wait "$RPID" 2>/dev/null || true; fi; rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/store"
chmod 700 "$TMP/store"
cd "$TMP"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -subj '/CN=SLX Test CA' -days 1 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj '/CN=localhost' >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 1 -sha256 -extfile server.ext >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj '/CN=slx-client' >/dev/null 2>&1
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 1 -sha256 >/dev/null 2>&1
CLIENT_SHA256=$(openssl x509 -in client.crt -outform DER | openssl dgst -sha256 -hex | awk '{print $NF}')
SLX_RECEIVE_BIND=127.0.0.1 SLX_RECEIVE_PORT=24445 SLX_RECEIVE_CA="$TMP/ca.crt" SLX_RECEIVE_CERT="$TMP/server.crt" SLX_RECEIVE_KEY="$TMP/server.key" SLX_RECEIVE_STORE="$TMP/store" SLX_RECEIVE_TMP="$TMP/store" SLX_RECEIVE_CLIENT_SHA256="$CLIENT_SHA256" "$ROOT/sentinel-lx" --receive >"$TMP/out" 2>&1 & RPID=$!
sleep 1
python3 - <<'PY'
import socket, time
s=[]
for _ in range(16):
    s.append(socket.create_connection(('127.0.0.1',24445), timeout=2))
x=socket.create_connection(('127.0.0.1',24445), timeout=2)
x.settimeout(2)
msg=x.recv(16)
if msg != b'BUSY\n':
    raise SystemExit(f'unexpected reply: {msg!r}')
x.close()
time.sleep(1)
for x in s:
    x.close()
PY
kill "$RPID" 2>/dev/null || true
wait "$RPID" 2>/dev/null || true
grep -q 'max_clients=16' "$TMP/out"
echo 'test_receive_limit: PASS'
