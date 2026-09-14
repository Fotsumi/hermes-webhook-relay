import hashlib
import hmac
import json
import logging
import os
import sys
import time
from urllib.parse import urlsplit, urlunsplit

from aiohttp import ClientSession, ClientTimeout, web


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


LOG = logging.getLogger("app.main")

# aiohttp 3.11+ Request storage keys (silences NotAppKeyWarning).
_BODY_BYTES = web.RequestKey("body_bytes")
_SIG_REQUIRED = web.RequestKey("provider_signature_required")
_SIG_PRESENT = web.RequestKey("provider_signature_present")
_OUTCOME = web.RequestKey("outcome")
_UPSTREAM_URL = web.RequestKey("upstream_url")
_UPSTREAM_STATUS = web.RequestKey("upstream_status")


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON object (one per line)."""

    def format(self, record: logging.LogRecord) -> str:
        data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "data", None)
        if isinstance(extra, dict):
            data.update(extra)
        return json.dumps(data, ensure_ascii=False, default=str)


def configure_logging() -> None:
    """Idempotently configure root logging for container use.

    Emits one JSON object per line to stdout so ``docker logs`` stays
    machine-readable. The aiohttp built-in access logger is silenced because
    our middleware already records a single access line per request.
    """
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(datefmt="%Y-%m-%dT%H:%M:%S%z"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)


def _remote_peer(request: web.Request) -> str:
    remote = getattr(request, "remote", None)
    if remote:
        return str(remote)
    transport = request.transport
    if transport is not None:
        peer = transport.get_extra_info("peername")
        if peer:
            return str(peer[0])
    return ""


def _safe_url(url: str) -> str:
    """Return scheme://host[:port]/path, stripping any credentials/query."""
    parts = urlsplit(url)
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/", "", ""))


def _default_outcome(status: int) -> str:
    if status >= 500:
        return "internal_error"
    if status in (401, 403):
        return "provider_signature_rejected"
    return "invalid_configuration"


def _emit_access(request, started, status, outcome, upstream_status) -> None:
    data = {
        "http_method": request.method,
        "request_path": request.path,
        "remote_peer": _remote_peer(request),
        "status": status,
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
        "body_bytes": request.get(_BODY_BYTES, request.content_length),
        "provider_signature_verification_enabled": request.get(_SIG_REQUIRED),
        "provider_signature_present": request.get(_SIG_PRESENT),
        "hermes_upstream_url": request.get(_UPSTREAM_URL),
        "hermes_upstream_status": upstream_status,
        "outcome": outcome,
    }
    LOG.info("webhook request", extra={"data": data})


@web.middleware
async def access_log_middleware(request, handler):
    started = time.monotonic()
    try:
        response = await handler(request)
    except web.HTTPException as exc:
        outcome = request.get(_OUTCOME) or _default_outcome(exc.status)
        _emit_access(
            request, started, exc.status, outcome,
            request.get(_UPSTREAM_STATUS),
        )
        raise
    except Exception:
        _emit_access(
            request, started, 500, request.get(_OUTCOME, "internal_error"), None
        )
        raise
    else:
        _emit_access(
            request,
            started,
            response.status,
            request.get(_OUTCOME, "accepted"),
            request.get(_UPSTREAM_STATUS),
        )
        return response


def verify_provider_signature(body: bytes, request: web.Request, prov: dict) -> None:
    request[_SIG_REQUIRED] = prov["required"]
    request[_SIG_PRESENT] = bool(
        request.headers.get(prov["header"])
    )
    request.setdefault(_OUTCOME, "accepted")

    if not prov["required"]:
        return

    provider_secret = prov["secret"]
    if not provider_secret:
        request[_OUTCOME] = "invalid_configuration"
        raise web.HTTPInternalServerError(
            text="PROVIDER_SECRET is required"
        )
    header = prov["header"]
    algorithm = prov["algorithm"]
    encoding = prov["encoding"]
    prefix = prov["prefix"]

    if algorithm.lower().replace("_", "-") != "hmac-sha256":
        request[_OUTCOME] = "invalid_configuration"
        raise web.HTTPInternalServerError(
            text="Only hmac-sha256 supported"
        )

    if encoding.lower() != "hex":
        request[_OUTCOME] = "invalid_configuration"
        raise web.HTTPInternalServerError(
            text="Only hmac-sha256 supported"
        )

    received = request.headers.get(header)
    if not received:
        request[_OUTCOME] = "provider_signature_rejected"
        raise web.HTTPUnauthorized(text="Missing provider signature")

    if prefix and received.startswith(prefix):
        received = received[len(prefix):]

    expected = hmac.new(
        provider_secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, received):
        request[_OUTCOME] = "provider_signature_rejected"
        raise web.HTTPUnauthorized(text="Invalid provider signature")


def map_payload_for_hermes(payload: dict, mapping: dict) -> dict:
    if not mapping["enabled"]:
        return payload

    source = mapping["source"]
    target = mapping["target"]

    if not source or not target or source == target:
        return payload

    if source not in payload or target in payload:
        return payload

    mapped = dict(payload)
    mapped[target] = mapped[source]
    return mapped


def _no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate path {key!r} in WEBHOOK_MAP")
        result[key] = value
    return result


def _value(r, key, env_name, default):
    if isinstance(r, dict) and key in r:
        return r[key]
    return os.getenv(env_name, default)


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("1", "true", "yes", "on")


def _build_provider(r, provider_secret, path):
    return {
        "secret": provider_secret,
        "required": _to_bool(
            _value(
                r, "provider_signature_required",
                "PROVIDER_SIGNATURE_REQUIRED", True,
            )
        ),
        "header": _value(
            r, "provider_signature_header",
            "PROVIDER_SIGNATURE_HEADER", "X-Provider-Signature",
        ),
        "algorithm": _value(
            r, "provider_signature_algorithm",
            "PROVIDER_SIGNATURE_ALGORITHM", "hmac-sha256",
        ),
        "encoding": _value(
            r, "provider_signature_encoding",
            "PROVIDER_SIGNATURE_ENCODING", "hex",
        ),
        "prefix": _value(
            r, "provider_signature_prefix",
            "PROVIDER_SIGNATURE_PREFIX", "",
        ),
    }


def _build_payload(r, path):
    return {
        "enabled": _to_bool(
            _value(
                r, "payload_mapping_enabled",
                "PAYLOAD_MAPPING_ENABLED", True,
            )
        ),
        "source": _value(
            r, "payload_event_source",
            "PAYLOAD_EVENT_SOURCE", "event_name",
        ),
        "target": _value(
            r, "payload_event_target",
            "PAYLOAD_EVENT_TARGET", "event_type",
        ),
    }


def _resolve_route(path, dest):
    if isinstance(dest, str):
        url = dest
        provider_secret_env = None
        hermes_secret_env = None
        r = None
    elif isinstance(dest, dict):
        unknown = set(dest) - (
            {"url", "provider_secret_env", "hermes_secret_env"}
            | {
                "provider_signature_header",
                "provider_signature_algorithm",
                "provider_signature_encoding",
                "provider_signature_prefix",
                "provider_signature_required",
                "payload_mapping_enabled",
                "payload_event_source",
                "payload_event_target",
            }
        )
        if unknown:
            raise ValueError(
                f"unknown keys {sorted(unknown)!r} in WEBHOOK_MAP entry {path!r}"
            )
        url = dest.get("url")
        provider_secret_env = dest.get("provider_secret_env")
        hermes_secret_env = dest.get("hermes_secret_env")
        r = dest
    else:
        raise ValueError(
            f"WEBHOOK_MAP entry {path!r} must be a URL string or an object"
        )

    if not isinstance(path, str) or not path.startswith("/") or len(path) <= 1:
        raise ValueError(f"invalid webhook path {path!r}")
    if any(char in path for char in "?# \t"):
        raise ValueError(f"invalid webhook path {path!r}")
    if path == "/health":
        raise ValueError("path '/health' is reserved")

    if not isinstance(url, str) or not url:
        raise ValueError(f"empty destination URL for path {path!r}")
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError(f"destination URL for {path!r} must be http(s): {url!r}")

    provider_secret = _secret(provider_secret_env, "PROVIDER_SECRET", path)
    hermes_secret = _secret(hermes_secret_env, "HERMES_SECRET", path)
    if not hermes_secret:
        raise ValueError(
            f"no HERMES secret resolved for path {path!r}"
        )

    return {
        "url": url,
        "hermes_secret": hermes_secret,
        "provider": _build_provider(r, provider_secret, path),
        "payload": _build_payload(r, path),
    }


def _secret(env_name, fallback, path):
    if env_name:
        try:
            return os.environ[env_name]
        except KeyError:
            raise ValueError(
                f"secret env var {env_name!r} referenced by {path!r} is not set"
            ) from None
    return os.getenv(fallback)


def load_routes():
    raw = os.getenv("WEBHOOK_MAP")
    if not raw:
        provider_secret = os.getenv("PROVIDER_SECRET")
        return {
            "/webhook": {
                "url": os.environ["HERMES_URL"],
                "hermes_secret": os.environ["HERMES_SECRET"],
                "provider": _build_provider(None, provider_secret, "/webhook"),
                "payload": _build_payload(None, "/webhook"),
            }
        }

    try:
        mapping = json.loads(raw, object_pairs_hook=_no_duplicate_pairs)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"WEBHOOK_MAP is not valid JSON: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError(f"invalid WEBHOOK_MAP: {exc}") from exc

    if not isinstance(mapping, dict):
        raise RuntimeError("WEBHOOK_MAP must be a JSON object mapping path to destination")
    if not mapping:
        raise RuntimeError("WEBHOOK_MAP must define at least one route")

    routes = {}
    for path, dest in mapping.items():
        try:
            routes[path] = _resolve_route(path, dest)
        except ValueError as exc:
            raise RuntimeError(f"invalid WEBHOOK_MAP: {exc}") from exc
    return routes


def make_handler(cfg):
    async def handle(request: web.Request) -> web.Response:
        raw_body = await request.read()
        request[_BODY_BYTES] = len(raw_body)
        verify_provider_signature(raw_body, request, cfg["provider"])

        hermes_url = cfg["url"]
        hermes_secret = cfg["hermes_secret"]
        request[_UPSTREAM_URL] = _safe_url(hermes_url)

        body = raw_body
        mapping = cfg["payload"]
        if mapping["enabled"]:
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError as exc:
                raise web.HTTPBadRequest(text="Invalid JSON payload") from exc

            if not isinstance(payload, dict):
                raise web.HTTPBadRequest(text="JSON payload must be an object")

            payload = map_payload_for_hermes(payload, mapping)
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
                    request[_UPSTREAM_STATUS] = response.status
                    response_body = await response.read()
                    return web.Response(
                        status=response.status,
                        body=response_body,
                        content_type=response.headers.get(
                            "Content-Type", "text/plain"
                        ).split(";")[0],
                    )
        except Exception as exc:
            request[_OUTCOME] = "upstream_error"
            raise web.HTTPBadGateway(
                text=f"Unable to reach Hermes: {exc}"
            ) from exc

    return handle


async def health(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def create_app() -> web.Application:
    configure_logging()
    routes = load_routes()
    app = web.Application(middlewares=[access_log_middleware])
    app.router.add_get("/health", health)
    for path, cfg in routes.items():
        app.router.add_post(path, make_handler(cfg))
    return app


if __name__ == "__main__":
    try:
        app = create_app()
    except (RuntimeError, KeyError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    web.run_app(
        app,
        host=os.getenv("RELAY_BIND_IP", "0.0.0.0"),
        port=int(os.getenv("RELAY_PORT", "8080")),
        access_log=None,
    )