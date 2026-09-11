#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${REPO_DIR}/.env" ]]; then
    set -a
    source "${REPO_DIR}/.env"
    set +a
fi

URL="${1:-http://localhost:8080/webhook}"
SECRET="${PROVIDER_SECRET:?PROVIDER_SECRET is required}"
SIGNATURE_HEADER="${PROVIDER_SIGNATURE_HEADER:?PROVIDER_SIGNATURE_HEADER is required}"

BODY='{"event_type":"task.created","message":"hello"}'

SIGNATURE="$(
    printf '%s' "$BODY" |
        openssl dgst -sha256 -hmac "$SECRET" -hex |
        awk '{print $2}'
)"

echo "Sending to: ${URL}"
echo "Signature header: ${SIGNATURE_HEADER}"

curl -fsS -X POST "$URL" \
    -H 'Content-Type: application/json' \
    -H "${SIGNATURE_HEADER}: ${SIGNATURE}" \
    --data "$BODY"

printf '\n'