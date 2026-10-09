#!/bin/sh
set -eu
make clean >/dev/null 2>&1 || true
make >/dev/null
./sentinel-lx --explain 1 >/dev/null || true
printf 'platform build PASS\n'
