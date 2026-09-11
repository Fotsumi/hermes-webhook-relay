import hashlib
import hmac
import os
import time

from aiohttp import ClientSession, ClientTimeout, web


def verify_provider_signature(body: bytes, request: web.Request) -> None:
    secret = os.environ["PROVIDER_SECRET"]
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


async def webhook(request: web.Request) -> web.Response:
    body = await request.read()
    verify_provider_signature(body, request)

    hermes_url = os.environ["HERMES_URL"]
    hermes_secret = os.environ["HERMES_SECRET"]

    # v0.1 forwards the original body unchanged.
    # Hermes V1 signs the body directly with HMAC-SHA256.
    signature = hmac.new(
        hermes_secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    headers = {
        "Content-Type": request.headers.get(
            "Content-Type", "application/json"
        ),
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
