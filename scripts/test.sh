#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://localhost:8080/webhook}"
SECRET="${PROVIDER_SECRET:-replace-me}"

BODY='{"event_type":"example.created","message":"hello"}'
SIGNATURE="$(
  printf '%s' "$BODY" |
    openssl dgst -sha256 -hmac "$SECRET" -hex |
    awk '{print $2}'
)"

curl -fsS -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -H "X-Provider-Signature: $SIGNATURE" \
  --data "$BODY"

printf '\n'
