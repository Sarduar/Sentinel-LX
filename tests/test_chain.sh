#!/bin/sh
set -eu
J=${SLX_JOURNAL:-/var/log/sentinel-lx/events.jsonl}
[ -f "$J" ] || { echo "journal not found: $J" >&2; exit 1; }
awk 'BEGIN{prev="0000000000000000000000000000000000000000000000000000000000000000"; n=0; ok=1}
/"prev_hash":"/{p=$0; sub(/^.*"prev_hash":"/,"",p); sub(/".*$/,"",p); if(p!=prev && n>0) ok=0}
/"event_hash":"/{h=$0; sub(/^.*"event_hash":"/,"",h); sub(/".*$/,"",h); prev=h; n++}
END{if(n==0||!ok) exit 1; print "chain records=" n; exit 0}' "$J"
