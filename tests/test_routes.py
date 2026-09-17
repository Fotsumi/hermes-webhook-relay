import asyncio
import hashlib
import hmac
import http.server
import json
import os
import threading
import unittest
from unittest.mock import patch

from aiohttp.test_utils import TestClient, TestServer

from app.main import JsonFormatter, create_app


def sign(secret: str, body: bytes, prefix: str = "") -> str:
    return prefix + hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()


class _CaptureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.requests.append(
            {
                "path": self.path,
                "body": body,
                "headers": {k.lower(): v for k, v in self.headers.items()},
            }
        )
        payload = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class FakeHermes:
    def __init__(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CaptureHandler)
        self.server.requests = []
        self._thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    @property
    def requests(self):
        return self.server.requests

    def start(self):
        self._thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def run(coro):
    return asyncio.run(coro)


async def _post(app, path, body, headers):
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        return await client.post(path, data=body, headers=headers)
    finally:
        await client.close()


async def _post_many(app, requests):
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        responses = []
        for path, body, headers in requests:
            responses.append(await client.post(path, data=body, headers=headers))
        return responses
    finally:
        await client.close()


def assert_forwarded(upstream, index, expected_path, hermes_secret,
                     expected_event_type):
    req = upstream.requests[index]
    assert req["path"] == expected_path, req["path"]
    sent = json.loads(req["body"])
    assert sent.get("event_type") == expected_event_type, sent
    assert req["headers"]["x-webhook-signature"] == sign(hermes_secret, req["body"])


class LegacyModeTest(unittest.TestCase):
    def test_legacy_single_route_when_map_unset(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "HERMES_URL": upstream.base_url + "/hermes",
                "HERMES_SECRET": "h1",
                "PROVIDER_SECRET": "p1",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.created","x":1}'
                r = run(_post(
                    app, "/webhook", body,
                    {"Content-Type": "application/json",
                     "X-Provider-Signature": sign("p1", body)},
                ))
            assert r.status == 200, r.status
            assert len(upstream.requests) == 1
            assert_forwarded(upstream, 0, "/hermes", "h1", "task.created")
        finally:
            upstream.stop()

    def test_legacy_uses_global_signature_settings(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "HERMES_URL": upstream.base_url + "/hermes",
                "HERMES_SECRET": "h1",
                "PROVIDER_SECRET": "p1",
                "PROVIDER_SIGNATURE_HEADER": "X-Custom-Signature",
                "PROVIDER_SIGNATURE_PREFIX": "sha256=",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.created"}'
                r = run(_post(
                    app, "/webhook", body,
                    {"Content-Type": "application/json",
                     "X-Custom-Signature": sign("p1", body, "sha256=")},
                ))
            assert r.status == 200, r.status
            assert len(upstream.requests) == 1
            assert_forwarded(upstream, 0, "/hermes", "h1", "task.created")
        finally:
            upstream.stop()

    def test_legacy_unknown_path_is_404(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "HERMES_URL": upstream.base_url + "/hermes",
                "HERMES_SECRET": "h1",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                r = run(_post(app, "/anything", b"{}", {"Content-Type": "application/json"}))
            assert r.status == 404, r.status
            assert not upstream.requests
        finally:
            upstream.stop()


class MultiRouteTest(unittest.TestCase):
    def _env(self, u1, u2):
        webhook1 = {
            "url": u1.base_url + "/d1",
            "provider_secret_env": "W1_PROVIDER_SECRET",
            "hermes_secret_env": "W1_HERMES_SECRET",
            "provider_signature_header": "X-Route1-Signature",
        }
        webhook2 = {
            "url": u2.base_url + "/d2",
            "provider_secret_env": "W2_PROVIDER_SECRET",
            "hermes_secret_env": "W2_HERMES_SECRET",
            "provider_signature_header": "X-Route2-Signature",
        }
        return {
            "WEBHOOK_MAP": json.dumps({"/webhook1": webhook1, "/webhook2": webhook2}),
            "W1_PROVIDER_SECRET": "p1",
            "W1_HERMES_SECRET": "h1",
            "W2_PROVIDER_SECRET": "p2",
            "W2_HERMES_SECRET": "h2",
        }

    def test_each_path_forwards_to_its_own_destination(self):
        u1, u2 = FakeHermes(), FakeHermes()
        u1.start()
        u2.start()
        try:
            env = self._env(u1, u2)
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                b1 = b'{"event_name":"task.created","n":1}'
                b2 = b'{"event_name":"task.updated","n":2}'
                r1, r2 = run(_post_many(app, [
                    ("/webhook1", b1, {
                        "Content-Type": "application/json",
                        "X-Route1-Signature": sign("p1", b1)}),
                    ("/webhook2", b2, {
                        "Content-Type": "application/json",
                        "X-Route2-Signature": sign("p2", b2)}),
                ]))
            assert r1.status == 200 and r2.status == 200
            assert len(u1.requests) == 1 and len(u2.requests) == 1
            assert_forwarded(u1, 0, "/d1", "h1", "task.created")
            assert_forwarded(u2, 0, "/d2", "h2", "task.updated")
        finally:
            u1.stop()
            u2.stop()

    def test_per_route_secret_isolation_and_wrong_secret_401(self):
        u1, u2 = FakeHermes(), FakeHermes()
        u1.start()
        u2.start()
        try:
            env = self._env(u1, u2)
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.created"}'
                ok, bad = run(_post_many(app, [
                    ("/webhook1", body, {
                        "Content-Type": "application/json",
                        "X-Route1-Signature": sign("p1", body)}),
                    ("/webhook1", body, {
                        "Content-Type": "application/json",
                        "X-Route1-Signature": sign("p2", body)}),
                ]))
            assert ok.status == 200 and bad.status == 401, (ok.status, bad.status)
            assert len(u1.requests) == 1
        finally:
            u1.stop()
            u2.stop()

    def test_wrong_or_missing_signature_header_401(self):
        u1, u2 = FakeHermes(), FakeHermes()
        u1.start()
        u2.start()
        try:
            env = self._env(u1, u2)
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.created"}'
                # correct sig but under the global header name, not the route's;
                # and no signature header at all
                wrong_header, missing = run(_post_many(app, [
                    ("/webhook1", body, {
                        "Content-Type": "application/json",
                        "X-Provider-Signature": sign("p1", body)}),
                    ("/webhook1", body, {
                        "Content-Type": "application/json"}),
                ]))
            assert wrong_header.status == 401, wrong_header.status
            assert missing.status == 401, missing.status
            assert not u1.requests
        finally:
            u1.stop()
            u2.stop()

    def test_unknown_path_cannot_reach_any_destination(self):
        u1, u2 = FakeHermes(), FakeHermes()
        u1.start()
        u2.start()
        try:
            env = self._env(u1, u2)
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                r = run(_post(app, "/unconfigured", b"{}", {"Content-Type": "application/json"}))
            assert r.status == 404, r.status
            assert not u1.requests and not u2.requests
        finally:
            u1.stop()
            u2.stop()


class SignatureOverrideTest(unittest.TestCase):
    def test_per_route_header_overrides_global(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "WEBHOOK_MAP": json.dumps({"/h1": {
                    "url": upstream.base_url + "/h1",
                    "provider_secret_env": "H1_P",
                    "hermes_secret_env": "H1_H",
                    "provider_signature_header": "X-Route1-Signature",
                }}),
                "H1_P": "p1",
                "H1_H": "h1",
                "PROVIDER_SECRET": "pglobal",
                "HERMES_SECRET": "hglobal",
                "PROVIDER_SIGNATURE_HEADER": "X-Global-Signature",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.created"}'
                routed, global_header = run(_post_many(app, [
                    ("/h1", body, {
                        "Content-Type": "application/json",
                        "X-Route1-Signature": sign("p1", body)}),
                    ("/h1", body, {
                        "Content-Type": "application/json",
                        "X-Global-Signature": sign("pglobal", body)}),
                ]))
            assert routed.status == 200, routed.status
            assert global_header.status == 401, global_header.status
            assert len(upstream.requests) == 1
            assert_forwarded(upstream, 0, "/h1", "h1", "task.created")
        finally:
            upstream.stop()

    def test_per_route_prefix_override(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "WEBHOOK_MAP": json.dumps({"/p1": {
                    "url": upstream.base_url + "/p1",
                    "provider_secret_env": "P1_S",
                    "hermes_secret_env": "P1_H",
                    "provider_signature_header": "X-Route1-Signature",
                    "provider_signature_prefix": "sha256=",
                }}),
                "P1_S": "p1",
                "P1_H": "h1",
                "PROVIDER_SIGNATURE_PREFIX": "",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.created"}'
                r = run(_post(app, "/p1", body, {
                    "Content-Type": "application/json",
                    "X-Route1-Signature": sign("p1", body, "sha256=")}))
            assert r.status == 200, r.status
            assert len(upstream.requests) == 1
            assert_forwarded(upstream, 0, "/p1", "h1", "task.created")
        finally:
            upstream.stop()

    def test_route_without_override_falls_back_to_global(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "WEBHOOK_MAP": json.dumps({"/g1": {
                    "url": upstream.base_url + "/g1",
                }}),
                "PROVIDER_SECRET": "pglobal",
                "HERMES_SECRET": "hglobal",
                "PROVIDER_SIGNATURE_HEADER": "X-Global-Signature",
                "PROVIDER_SIGNATURE_PREFIX": "sha256=",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.created"}'
                r = run(_post(app, "/g1", body, {
                    "Content-Type": "application/json",
                    "X-Global-Signature": sign("pglobal", body, "sha256=")}))
            assert r.status == 200, r.status
            assert len(upstream.requests) == 1
            assert_forwarded(upstream, 0, "/g1", "hglobal", "task.created")
        finally:
            upstream.stop()

    def test_per_route_signature_required_override(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "WEBHOOK_MAP": json.dumps({
                    "/unverified": {
                        "url": upstream.base_url + "/uv",
                        "provider_secret_env": "U_P",
                        "hermes_secret_env": "U_H",
                        "provider_signature_required": False,
                    },
                    "/verified": {
                        "url": upstream.base_url + "/v",
                        "provider_secret_env": "V_P",
                        "hermes_secret_env": "V_H",
                    },
                }),
                "U_P": "pu",
                "U_H": "hu",
                "V_P": "pv",
                "V_H": "hv",
                "PROVIDER_SIGNATURE_REQUIRED": "true",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.created"}'
                unsigned, missing, signed = run(_post_many(app, [
                    ("/unverified", body, {"Content-Type": "application/json"}),
                    ("/verified", body, {"Content-Type": "application/json"}),
                    ("/verified", body, {
                        "Content-Type": "application/json",
                        "X-Provider-Signature": sign("pv", body)}),
                ]))
            assert unsigned.status == 200, unsigned.status
            assert missing.status == 401, missing.status
            assert signed.status == 200, signed.status
            assert len(upstream.requests) == 2  # uv + v
        finally:
            upstream.stop()


class StringFormTest(unittest.TestCase):
    def test_string_form_reuses_global_secrets_and_settings(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "WEBHOOK_MAP": json.dumps({"/s": upstream.base_url + "/s1"}),
                "PROVIDER_SECRET": "pglobal",
                "HERMES_SECRET": "hglobal",
                "PROVIDER_SIGNATURE_HEADER": "X-Provider-Signature",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.deleted"}'
                r = run(_post(app, "/s", body, {
                    "Content-Type": "application/json",
                    "X-Provider-Signature": sign("pglobal", body)}))
            assert r.status == 200, r.status
            assert_forwarded(upstream, 0, "/s1", "hglobal", "task.deleted")
        finally:
            upstream.stop()


class PayloadMappingTest(unittest.TestCase):
    def test_different_routes_use_different_payload_mappings(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "WEBHOOK_MAP": json.dumps({
                    "/a": {
                        "url": upstream.base_url + "/ra",
                        "provider_secret_env": "A_P",
                        "hermes_secret_env": "A_H",
                        "provider_signature_header": "X-Sig",
                        "payload_event_source": "action",
                        "payload_event_target": "kind",
                    },
                    "/b": {
                        "url": upstream.base_url + "/rb",
                        "provider_secret_env": "B_P",
                        "hermes_secret_env": "B_H",
                        "provider_signature_header": "X-Sig",
                        "payload_event_source": "op",
                        "payload_event_target": "type",
                    },
                }),
                "A_P": "pa", "A_H": "ha",
                "B_P": "pb", "B_H": "hb",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body_a = b'{"action":"a1","n":1}'
                body_b = b'{"op":"b1"}'
                r1, r2 = run(_post_many(app, [
                    ("/a", body_a, {
                        "Content-Type": "application/json",
                        "X-Sig": sign("pa", body_a)}),
                    ("/b", body_b, {
                        "Content-Type": "application/json",
                        "X-Sig": sign("pb", body_b)}),
                ]))
            assert r1.status == 200 and r2.status == 200, (r1.status, r2.status)
            req_a, req_b = upstream.requests
            sent_a = json.loads(req_a["body"])
            sent_b = json.loads(req_b["body"])
            assert sent_a["kind"] == "a1" and "action" in sent_a, sent_a
            assert "event_type" not in sent_a, sent_a
            assert sent_b["type"] == "b1" and "op" in sent_b, sent_b
            assert "event_type" not in sent_b, sent_b
            # Hermes signature over each transformed body
            assert req_a["headers"]["x-webhook-signature"] == sign("ha", req_a["body"])
            assert req_b["headers"]["x-webhook-signature"] == sign("hb", req_b["body"])
        finally:
            upstream.stop()

    def test_per_route_mapping_disabled_while_global_enabled(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "WEBHOOK_MAP": json.dumps({
                    "/off": {
                        "url": upstream.base_url + "/roff",
                        "provider_secret_env": "O_P",
                        "hermes_secret_env": "O_H",
                        "provider_signature_header": "X-Sig",
                        "payload_mapping_enabled": False,
                    },
                }),
                "O_P": "po", "O_H": "ho",
                "PAYLOAD_MAPPING_ENABLED": "true",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                raw = b'{"event_name":"x","raw":true}'
                r = run(_post(app, "/off", raw, {
                    "Content-Type": "application/json",
                    "X-Sig": sign("po", raw)}))
            assert r.status == 200, r.status
            req = upstream.requests[0]
            assert req["body"] == raw, req["body"]  # forwarded byte-identical
            assert req["headers"]["x-webhook-signature"] == sign("ho", raw)
        finally:
            upstream.stop()

    def test_route_without_mapping_overrides_falls_back_to_global(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "WEBHOOK_MAP": json.dumps({"/g": upstream.base_url + "/rg"}),
                "PROVIDER_SECRET": "pg",
                "HERMES_SECRET": "hg",
                "PAYLOAD_EVENT_SOURCE": "action",
                "PAYLOAD_EVENT_TARGET": "kind",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"action":"z","n":2}'
                r = run(_post(app, "/g", body, {
                    "Content-Type": "application/json",
                    "X-Provider-Signature": sign("pg", body)}))
            assert r.status == 200, r.status
            sent = json.loads(upstream.requests[0]["body"])
            assert sent["kind"] == "z" and "action" in sent, sent
            assert "event_type" not in sent, sent
        finally:
            upstream.stop()

    def test_legacy_honors_global_payload_mapping(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "HERMES_URL": upstream.base_url + "/hermes",
                "HERMES_SECRET": "h1",
                "PROVIDER_SECRET": "p1",
                "PAYLOAD_EVENT_SOURCE": "action",
                "PAYLOAD_EVENT_TARGET": "kind",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"action":"w","n":1}'
                r = run(_post(app, "/webhook", body, {
                    "Content-Type": "application/json",
                    "X-Provider-Signature": sign("p1", body)}))
            assert r.status == 200, r.status
            sent = json.loads(upstream.requests[0]["body"])
            assert sent["kind"] == "w" and "action" in sent, sent
            assert "event_type" not in sent, sent
        finally:
            upstream.stop()

    def test_legacy_mapping_disabled_forwards_unchanged(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = {
                "HERMES_URL": upstream.base_url + "/hermes",
                "HERMES_SECRET": "h1",
                "PROVIDER_SECRET": "p1",
                "PAYLOAD_MAPPING_ENABLED": "false",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                raw = b'{"event_name":"x"}'
                r = run(_post(app, "/webhook", raw, {
                    "Content-Type": "application/json",
                    "X-Provider-Signature": sign("p1", raw)}))
            assert r.status == 200, r.status
            req = upstream.requests[0]
            assert req["body"] == raw, req["body"]
            assert req["headers"]["x-webhook-signature"] == sign("h1", raw)
        finally:
            upstream.stop()


class StartupValidationTest(unittest.TestCase):
    def _assert_startup_fails(self, map_value):
        with patch.dict(os.environ, {"WEBHOOK_MAP": map_value}, clear=False):
            with self.assertRaises(RuntimeError):
                create_app()

    def test_malformed_json_fails(self):
        self._assert_startup_fails("not json {{")

    def test_empty_object_fails(self):
        self._assert_startup_fails("{}")

    def test_missing_url_fails(self):
        self._assert_startup_fails('{"/w": {"provider_secret_env": "A"}}')

    def test_empty_destination_url_fails(self):
        self._assert_startup_fails('{"/w": ""}')

    def test_duplicate_path_fails(self):
        self._assert_startup_fails('{"a": "http://x/1", "a": "http://x/2"}')

    def test_invalid_path_fails(self):
        self._assert_startup_fails('{"nominal": "http://x/1"}')

    def test_unknown_key_fails(self):
        self._assert_startup_fails('{"/w": {"url": "http://x/1", "bogus": 1}}')

    def test_missing_referenced_secret_env_fails(self):
        with patch.dict(os.environ, {
            "WEBHOOK_MAP": json.dumps({"/w": {
                "url": "http://x/1",
                "hermes_secret_env": "NOT_SET_ANYWHERE",
            }}),
        }, clear=False):
            with self.assertRaises(RuntimeError):
                create_app()


class LoggingTest(unittest.TestCase):
    def _capture(self, app_logger, body, headers, env, path="/webhook",
                 upstream=None):
        """POST once, return parsed JSON log lines captured via assertLogs."""
        import logging

        from app.main import JsonFormatter

        formatter = JsonFormatter(datefmt="%Y-%m-%dT%H:%M:%S%z")
        with patch.dict(os.environ, env, clear=False):
            app = create_app()
        with self.assertLogs(app_logger, level="INFO") as cm:
            with patch.dict(os.environ, env, clear=False):
                r = run(_post(app, path, body, headers))
        records = []
        for rec in cm.records:
            records.append(json.loads(formatter.format(rec)))
        return r, records

    def _env(self, upstream, **extra):
        env = {
            "HERMES_URL": upstream.base_url + "/hermes",
            "HERMES_SECRET": "h1",
            "PROVIDER_SECRET": "p1",
        }
        env.update(extra)
        return env

    def test_successful_request_emits_access_log(self):
        import logging

        from app.main import LOG
        upstream = FakeHermes()
        upstream.start()
        try:
            env = self._env(upstream)
            body = b'{"event_name":"task.created"}'
            r, records = self._capture(
                LOG, body, {
                    "Content-Type": "application/json",
                    "X-Provider-Signature": sign("p1", body),
                }, env)
            assert r.status == 200, r.status
            assert len(records) == 1, records
            rec = records[0]
            assert rec["http_method"] == "POST"
            assert rec["request_path"] == "/webhook"
            assert rec["status"] == 200
            assert rec["outcome"] == "accepted"
            assert rec["body_bytes"] == len(body)
            assert rec["provider_signature_verification_enabled"] is True
            assert rec["provider_signature_present"] is True
            assert rec["hermes_upstream_status"] == 200
            assert rec["hermes_upstream_url"] == upstream.base_url + "/hermes"
            assert rec["timestamp"] and rec["level"] == "INFO"
            assert "duration_ms" in rec
        finally:
            upstream.stop()

    def test_signature_rejection_emits_access_log(self):
        import logging

        from app.main import LOG
        upstream = FakeHermes()
        upstream.start()
        try:
            env = self._env(upstream)
            body = b'{"event_name":"task.created"}'
            r, records = self._capture(
                LOG, body, {
                    "Content-Type": "application/json",
                    "X-Provider-Signature": sign("wrong", body),
                }, env)
            assert r.status == 401, r.status
            assert len(records) == 1, records
            rec = records[0]
            assert rec["status"] == 401
            assert rec["outcome"] == "provider_signature_rejected"
            assert rec["provider_signature_present"] is True
            assert rec["hermes_upstream_url"] is None
            assert rec["hermes_upstream_status"] is None
        finally:
            upstream.stop()

    def test_upstream_failure_emits_access_log(self):
        import logging

        from app.main import LOG
        env = {
            "HERMES_URL": "http://127.0.0.1:1/hermes",  # nothing listens
            "HERMES_SECRET": "h1",
            "PROVIDER_SECRET": "p1",
        }
        body = b'{"event_name":"task.created"}'
        r, records = self._capture(
            LOG, body, {
                "Content-Type": "application/json",
                "X-Provider-Signature": sign("p1", body),
            }, env)
        assert r.status == 502, r.status
        assert len(records) == 1, records
        rec = records[0]
        assert rec["status"] == 502
        assert rec["outcome"] == "upstream_error"
        assert rec["hermes_upstream_status"] is None
        assert rec["hermes_upstream_url"] == "http://127.0.0.1:1/hermes"

    def test_secrets_and_body_never_logged(self):
        import logging

        from app.main import LOG
        upstream = FakeHermes()
        upstream.start()
        try:
            secret = "super-secret-provider-value-12345"
            hermes_secret = "super-secret-hermes-value-67890"
            env = self._env(upstream, PROVIDER_SECRET=secret)
            body = b'{"event_name":"task.created","secret":"sensitive-field","password":"hunter2"}'
            r, records = self._capture(
                LOG, body, {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer tok-3579",
                    "Cookie": "session=abc123",
                    "X-Webhook-Signature": sign(hermes_secret, body),
                    "X-Provider-Signature": sign(secret, body),
                }, env)
            assert r.status == 200, r.status
            blobs = json.dumps(records)
            assert secret not in blobs
            assert hermes_secret not in blobs
            assert "hunter2" not in blobs
            assert "sensitive-field" not in blobs
            assert "session=abc123" not in blobs
            assert "tok-3579" not in blobs
            assert "abc123" not in blobs
        finally:
            upstream.stop()

    def test_logs_emit_to_stdout(self):
        import logging
        import sys

        from app.main import configure_logging
        configure_logging()
        root = logging.getLogger()
        handlers = [
            h for h in root.handlers
            if isinstance(h, logging.StreamHandler)
        ]
        assert handlers, "no StreamHandler configured"
        assert any(h.stream is sys.stdout for h in handlers)

    def test_log_level_configuration(self):
        import logging

        from app.main import configure_logging
        with patch.dict(os.environ, {"LOG_LEVEL": "ERROR"}, clear=False):
            configure_logging()
        assert logging.getLogger().level == logging.ERROR
        # INFO below threshold must be suppressed by the configured handler.
        records = []
        class _Cap(logging.Handler):
            def emit(self, record):
                records.append(record)
        cap = _Cap()
        logging.getLogger().addHandler(cap)
        try:
            logging.getLogger("app.main").info("should be filtered")
            assert records == [], records
        finally:
            logging.getLogger().removeHandler(cap)


class DedupTest(unittest.TestCase):
    """Duplicate suppression: identical re-deliveries are swallowed only when
    the first one already reached Hermes OK, and only within the window."""

    def _env(self, upstream, **extra):
        env = {
            "HERMES_URL": upstream.base_url + "/hermes",
            "HERMES_SECRET": "h1",
            "PROVIDER_SECRET": "p1",
        }
        env.update(extra)
        return env

    def _sign(self, body):
        return sign("p1", body)

    def test_identical_body_within_window_is_suppressed(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = self._env(upstream)
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.updated","task":{"id":57}}'
                h = {"Content-Type": "application/json",
                     "X-Provider-Signature": self._sign(body)}
                r1, r2 = run(_post_many(app, [
                    ("/webhook", body, h),
                    ("/webhook", body, h),
                ]))
            assert r1.status == 200 and r2.status == 200
            # Only the first reached Hermes; the duplicate was suppressed.
            assert len(upstream.requests) == 1, len(upstream.requests)
        finally:
            upstream.stop()

    def test_duplicate_is_suppressed_only_if_first_reached_upstream(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = self._env(upstream)
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                body = b'{"event_name":"task.updated","task":{"id":57}}'
                h = {"Content-Type": "application/json",
                     "X-Provider-Signature": self._sign(body)}
                # First delivery fails upstream (no Hermes reachable on :1),
                # so the logical retry must be allowed through — not swallowed.
                env_bad = self._env(upstream, HERMES_URL="http://127.0.0.1:1/hermes")
                with patch.dict(os.environ, env_bad, clear=False):
                    app_bad = create_app()
                    r1 = run(_post(app_bad, "/webhook", body, h))
                assert r1.status == 502
            # Now with a reachable Hermes, the SAME body is fresh: because the
            # previous attempt never delivered, it is forwarded, not suppressed.
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                r2 = run(_post(app, "/webhook", body, h))
            assert r2.status == 200
            assert len(upstream.requests) == 1
        finally:
            upstream.stop()

    def test_distinct_bodies_are_not_suppressed(self):
        upstream = FakeHermes()
        upstream.start()
        try:
            env = self._env(upstream)
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                b1 = b'{"event_name":"task.updated","task":{"id":57}}'
                b2 = b'{"event_name":"task.updated","task":{"id":58}}'
                r1, r2 = run(_post_many(app, [
                    ("/webhook", b1, {"Content-Type": "application/json",
                                      "X-Provider-Signature": self._sign(b1)}),
                    ("/webhook", b2, {"Content-Type": "application/json",
                                      "X-Provider-Signature": self._sign(b2)}),
                ]))
            assert r1.status == 200 and r2.status == 200
            assert len(upstream.requests) == 2
        finally:
            upstream.stop()

    def test_suppressed_duplicate_reports_outcome_in_log(self):
        import logging

        from app.main import LOG
        upstream = FakeHermes()
        upstream.start()
        try:
            env = self._env(upstream)
            body = b'{"event_name":"task.updated","task":{"id":57}}'
            headers = {"Content-Type": "application/json",
                       "X-Provider-Signature": self._sign(body)}
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
            formatter = JsonFormatter(datefmt="%Y-%m-%dT%H:%M:%S%z")
            with self.assertLogs(LOG, level="INFO") as cm:
                with patch.dict(os.environ, env, clear=False):
                    run(_post_many(app, [("/webhook", body, headers),
                                         ("/webhook", body, headers)]))
            records = [json.loads(formatter.format(rec)) for rec in cm.records]
            # Two access lines: first forwarded, second suppressed.
            assert len([r for r in records if r.get("request_path") == "/webhook"]) == 2
            suppressed = [r for r in records if r.get("dedupe_suppressed")]
            assert len(suppressed) == 1, records
            assert suppressed[0]["outcome"] == "duplicate_suppressed"
        finally:
            upstream.stop()


if __name__ == "__main__":
    unittest.main()