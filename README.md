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

## Example

For a provider sending:

```text
X-Provider-Signature: abc123...
```

the relay verifies that signature and sends the same body to Hermes with:

```text
X-Webhook-Signature: <new Hermes signature>
```

The original provider signature is not forwarded.

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
- payload field mapping
- selected header mapping
- configurable event filtering
- multiple relay routes
