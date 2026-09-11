import hashlib
import hmac
import json
import os

from aiohttp import ClientSession, ClientTimeout, web


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


def verify_provider_signature(body: bytes, request: web.Request) -> None:
    if not env_bool("PROVIDER_SIGNATURE_REQUIRED", True):
        return

    secret = os.getenv("PROVIDER_SECRET")
    if not secret:
        raise web.HTTPInternalServerError(
            text="PROVIDER_SECRET is required"
        )
    header = os.getenv("PROVIDER_SIGNATURE_HEADER", "X-Provider-Signature")
    algorithm = os.getenv("PROVIDER_SIGNATURE_ALGORITHM", "hmac-sha256")
    encoding = os.getenv("PROVIDER_SIGNATURE_ENCODING", "hex")
    prefix = os.getenv("PROVIDER_SIGNATURE_PREFIX", "")

    if algorithm.lower().replace("_", "-") != "hmac-sha256":
        raise web.HTTPInternalServerError(
            text="Only hmac-sha256 supported"
        )

    if encoding.lower() != "hex":
        raise web.HTTPInternalServerError(
            text="Only hmac-sha256 supported"
        )

    received = request.headers.get(header)
    if not received:
        raise web.HTTPUnauthorized(text="Missing provider signature")

    if prefix and received.startswith(prefix):
        received = received[len(prefix):]

    expected = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, received):
        raise web.HTTPUnauthorized(text="Invalid provider signature")


def map_payload_for_hermes(payload: dict) -> dict:
    if not env_bool("PAYLOAD_MAPPING_ENABLED", True):
        return payload

    source = os.getenv("PAYLOAD_EVENT_SOURCE", "event_name")
    target = os.getenv("PAYLOAD_EVENT_TARGET", "event_type")

    if not source or not target or source == target:
        return payload

    if source not in payload or target in payload:
        return payload

    mapped = dict(payload)
    mapped[target] = mapped[source]
    return mapped


async def webhook(request: web.Request) -> web.Response:
    raw_body = await request.read()
    verify_provider_signature(raw_body, request)

    hermes_url = os.environ["HERMES_URL"]
    hermes_secret = os.environ["HERMES_SECRET"]

    body = raw_body
    if env_bool("PAYLOAD_MAPPING_ENABLED", True):
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise web.HTTPBadRequest(text="Invalid JSON payload") from exc

        if not isinstance(payload, dict):
            raise web.HTTPBadRequest(text="JSON payload must be an object")

        payload = map_payload_for_hermes(payload)
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    signature = hmac.new(
        hermes_secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    signature = hmac.new(
        hermes_secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
    }

    timeout = ClientTimeout(
        total=float(os.getenv("HERMES_TIMEOUT_SECONDS", "10"))
    )

    try:
        async with ClientSession(timeout=timeout) as session:
            async with session.post(
                hermes_url,
                data=body,
                headers=headers,
            ) as response:
                response_body = await response.read()
                return web.Response(
                    status=response.status,
                    body=response_body,
                    content_type=response.headers.get(
                        "Content-Type", "text/plain"
                    ).split(";")[0],
                )
    except Exception as exc:
        raise web.HTTPBadGateway(
            text=f"Unable to reach Hermes: {exc}"
        ) from exc


async def health(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_post("/webhook", webhook)
    return app


if __name__ == "__main__":
    web.run_app(
        create_app(),
        host=os.getenv("RELAY_BIND_IP", "0.0.0.0"),
        port=int(os.getenv("RELAY_PORT", "8080")),
    )
