# hermes-webhook-relay

A tiny webhook relay that adapts a provider's HMAC-SHA256 signature to the signature format accepted by Hermes Agent.

## What it does

1. Receive a provider webhook.
2. Verify its HMAC-SHA256 signature.
3. Keep the request body unchanged.
4. Generate a Hermes-compatible HMAC-SHA256 signature.
5. Replace the provider signature header with `X-Webhook-Signature`.
6. Forward the unchanged body to Hermes.


## Configuration

Provider-specific details are configured entirely through environment variables:

```yaml
PROVIDER_SECRET: ${WEBHOOK_SECRET}
PROVIDER_SIGNATURE_HEADER: X-Provider-Signature
PROVIDER_SIGNATURE_ALGORITHM: hmac-sha256
PROVIDER_SIGNATURE_ENCODING: hex
PROVIDER_SIGNATURE_PREFIX:
```

v0.1 supports:

- HMAC-SHA256
- hexadecimal signatures
- optional signature prefixes such as `sha256=`

The provider signature is calculated over the **original raw request body**.

Hermes:

```yaml
HERMES_URL: ${HERMES_WEBHOOK_URL}
HERMES_SECRET: ${HERMES_WEBHOOK_SECRET}
```

The outgoing Hermes signature is:

```text
HMAC-SHA256(HERMES_SECRET, original_body)
```

and is sent as:

```text
X-Webhook-Signature: <hex signature>
```

This corresponds to Hermes' legacy V1 webhook signature format.

## Multiple routes (`WEBHOOK_MAP`)

The relay is generic: a single process can expose any number of inbound paths,
each forwarding to a configured upstream destination. The topology is defined
entirely by environment configuration — the relay never knows what a path or
destination represents.

`WEBHOOK_MAP` is a JSON object mapping each inbound `POST` path to a
destination. When it is set, each key is exposed as a relay path; when it is
unset, the relay keeps the original single-route behavior: `POST /webhook`
forwarding to `HERMES_URL`.

A destination may be either a URL string (reusing the global `PROVIDER_SECRET`,
`HERMES_SECRET`, and `PROVIDER_SIGNATURE_*` settings) or an object with its own
secrets referenced by environment-variable name (so secret values never sit
inside the map):

```yaml
WEBHOOK_MAP: '{
  "/webhook1": {
    "url": "http://hermes-address:8644/webhooks/webhook1",
    "provider_secret_env": "WEBHOOK1_PROVIDER_SECRET",
    "hermes_secret_env": "WEBHOOK1_HERMES_SECRET",
    "provider_signature_header": "X-Provider-Signature",
    "provider_signature_algorithm": "hmac-sha256",
    "provider_signature_encoding": "hex",
    "provider_signature_prefix": "",
    "payload_mapping_enabled": true,
    "payload_event_source": "event_name",
    "payload_event_target": "event_type",
    "dedupe_enabled": true,
    "dedupe_window_seconds": 5
  },
  "/webhook2": {
    "url": "http://hermes-address:8644/webhooks/webhook2",
    "provider_secret_env": "WEBHOOK2_PROVIDER_SECRET",
    "hermes_secret_env": "WEBHOOK2_HERMES_SECRET"
  }
}'
WEBHOOK1_PROVIDER_SECRET: <secret>
WEBHOOK1_HERMES_SECRET: <secret>
WEBHOOK2_PROVIDER_SECRET: <secret>
WEBHOOK2_HERMES_SECRET: <secret>
```

Provider signature verification is per-route. Each route may override the
signature header, algorithm, encoding, prefix, and whether verification is
required:

- `provider_signature_header` — the header to read the signature from
- `provider_signature_algorithm` — signature algorithm (`hmac-sha256`)
- `provider_signature_encoding` — signature encoding (`hex`)
- `provider_signature_prefix` — optional prefix such as `sha256=`
- `provider_signature_required` — `true`/`false`, e.g. to disable
  verification for a route

Any key omitted on a route (and the URL-string form entirely) falls back to the
corresponding global `PROVIDER_SIGNATURE_HEADER` / `PROVIDER_SIGNATURE_ALGORITHM` /
`PROVIDER_SIGNATURE_ENCODING` / `PROVIDER_SIGNATURE_PREFIX` /
`PROVIDER_SIGNATURE_REQUIRED` variables, whose defaults remain
`X-Provider-Signature`, `hmac-sha256`, `hex`, empty, and `true`.

Payload mapping is likewise per-route, using the same fallback pattern:

- `payload_mapping_enabled` — `true`/`false`, enable event-field mapping for
  this route
- `payload_event_source` — source field copied to the target
- `payload_event_target` — target field added on the payload

Any payload key omitted falls back to the global `PAYLOAD_MAPPING_ENABLED` /
`PAYLOAD_EVENT_SOURCE` / `PAYLOAD_EVENT_TARGET` variables, whose defaults remain
`true`, `event_name`, `event_type`. Legacy single `/webhook` mode (no
`WEBHOOK_MAP`) always uses the global `PAYLOAD_*` values. When mapping is
enabled the relay parses the JSON object, copies the source field into the
target field (only when the source exists and the target does not), and
preserves all original fields; when disabled it forwards the original body
byte-for-byte untransformed.

Duplicate suppression is also per-route with a global fallback:

- `dedupe_enabled` — `true`/`false` (default `true`; global `DEDUPE_ENABLED`)
- `dedupe_window_seconds` — how long an identical delivery is remembered
  (default `5`; global `DEDUPE_WINDOW_SECONDS`)

A provider such as Vikunja sometimes delivers the same `task.updated` event
twice — byte-identical bodies a couple of seconds apart (e.g. a bucket/
position change or a queued retry). Without a guard both reach Hermes and
spawn a duplicate agent session. The relay suppresses the second delivery by
hashing the final outgoing body (keyed per route) and returning the prior one's
status, **but only when the first delivery already reached Hermes successfully**:
a duplicate whose first attempt failed upstream (`502`) is treated as a fresh
retry and forwarded, so an event is never lost to suppression. Suppressed
requests are answered `200` with `{"status":"duplicate_suppressed"}` and logged
with `"dedupe_suppressed":true` / `outcome:"duplicate_suppressed"`. The window
is short and the store is in-memory, so a process restart cannot accidentally
swallow a legitimate later delivery.

The incoming request path alone selects the destination; a client can never
supply or override the upstream URL, and any unconfigured path is a 404.
Provider signature verification always runs against the original raw request
body before payload parsing/transformation, and the Hermes-facing signature is
independent: HMAC-SHA256 over the exact transformed body, sent as
`X-Webhook-Signature` (V1).

Malformed configuration fails fast at startup with a clear message and a
non-zero exit: invalid JSON, empty map, invalid/short path, reserved `/health`
path, empty or non-http(s) destination, unknown keys, duplicate paths, or a
referenced secret variable that is not set.

## Docker Compose

Copy the example environment:

```bash
cp .env.example .env
```

Configure the provider and Hermes values, then build and start:

```bash
docker compose build
docker compose up -d
```

The relay listens on:

```text
POST /webhook
GET  /health
```

When the provider shares the external Docker network with the relay, it can target:

```text
http://hermes-webhook-relay:8080/webhook
```

The relay also has an egress network so it can forward to Hermes even when the provider network is isolated.

No host port is published by default.

## Calling the relay

The relay is a plain HTTP `POST` endpoint. A provider calls it exactly like any
webhook destination: send the request body plus the signature the
`PROVIDER_SIGNATURE_HEADER` expects (see below for how that signature is
computed). The provider never has to know anything about Hermes — the relay
adapter strips the provider signature and attaches the Hermes one.

### Single route (no `WEBHOOK_MAP`)

Default endpoint: `POST /webhook`. The provider signs the **raw request body**
with `PROVIDER_SECRET` using HMAC-SHA256 (hex-encoded, optional `sha256=`
prefix), and sends it in `PROVIDER_SIGNATURE_HEADER`:

```bash
curl -X POST http://hermes-webhook-relay:8080/webhook \
  -H "Content-Type: application/json" \
  -H "X-Provider-Signature: <hex hmac-sha256(PROVIDER_SECRET, body)>" \
  -d '{"event_name":"task.created","task_id":42}'
```

That signature above is:

```text
HMAC-SHA256(PROVIDER_SECRET, '{"event_name":"task.created","task_id":42}')
```

computable locally with, e.g.:

```bash
body='{"event_name":"task.created","task_id":42}'
printf '%s' "$body" | openssl dgst -sha256 -hmac 'replace-me'
```

With the default global mapping (`PAYLOAD_EVENT_SOURCE=event_name`,
`PAYLOAD_EVENT_TARGET=event_type`), the relay verifies the provider signature,
then re-signs the transformed body for Hermes and forwards it:

```text
POST http://hermes-address:8644/webhooks/example
X-Webhook-Signature: <hex hmac-sha256(HERMES_SECRET, body')>
Content-Type: application/json

{"event_name":"task.created","task_id":42,"event_type":"task.created"}
```

`event_type` was added with the value of `event_name`; all original fields are
preserved. If the body has no `event_name`, or already has `event_type`, it is
forwarded byte-for-byte unchanged. The provider's `X-Provider-Signature` is
never forwarded.

### Multi-route (`WEBHOOK_MAP`)

Each configured path is its own endpoint with its own destination, secrets,
signature settings, and (optionally) its own mapping. The provider targets the
route path directly; the route's secret and settings are used for verification.

```bash
curl -X POST http://hermes-webhook-relay:8080/webhook1 \
  -H "Content-Type: application/json" \
  -H "X-Provider-Signature: <hex hmac-sha256(WEBHOOK1_PROVIDER_SECRET, body)>" \
  -d '{"event_name":"invoice.paid","amount":0.5,"currency":"usd"}'
```

`/webhook1` in the example config verifies with `WEBHOOK1_PROVIDER_SECRET`,
enables mapping (`event_name` → `event_type`), and forwards to
`http://hermes-address:8644/webhooks/webhook1`:

```text
X-Webhook-Signature: <hex hmac-sha256(WEBHOOK1_HERMES_SECRET, body')>
Content-Type: application/json

{"event_name":"invoice.paid","amount":0.5,"currency":"usd","event_type":"invoice.paid"}
```

`/webhook2` uses its own secrets (`WEBHOOK2_PROVIDER_SECRET` /
`WEBHOOK2_HERMES_SECRET`) and, having no mapping overrides, falls back to the
global `PAYLOAD_*` defaults (mapping enabled, `event_name` → `event_type`):

```bash
curl -X POST http://hermes-webhook-relay:8080/webhook2 \
  -H "Content-Type: application/json" \
  -H "X-Provider-Signature: <hex hmac-sha256(WEBHOOK2_PROVIDER_SECRET, body)>" \
  -d '{"event_name":"task.updated","n":2}'
```

In both modes the relay verifies the provider signature against the original
raw body, then signs for Hermes with the route's `HERMES_SECRET` and sends the
result as `X-Webhook-Signature`. The original provider signature header is
always dropped.

## Testing

Set:

```bash
export PROVIDER_SECRET=replace-me
```

Then:

```bash
./scripts/test.sh http://localhost:8080/webhook
```

## Future versions

More generic adaptation features can be added in later versions, for example:

- Hermes V2 timestamp signatures
- provider event header mapping
- selected header mapping
- configurable event filtering (beyond the body-hash duplicate suppression)
