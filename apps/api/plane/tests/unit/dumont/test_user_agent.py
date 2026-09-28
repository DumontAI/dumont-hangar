# Dumont addition: every request to Dumont Auth carries an explicit User-Agent. Not upstream Plane.
#
# auth.getdumont.ai sits behind Cloudflare, which answers 403 to urllib's default
# `Python-urllib/3.x`. These tests drive the real urllib code against a loopback HTTP server
# started here (no outside network) and check the header that actually went over the wire.

import http.server
import json
import threading

import pytest

from plane.dumont.auth import introspection as introspection_module
from plane.dumont.auth import jwks as jwks_module
from plane.dumont.auth.config import USER_AGENT

from .conftest import make_config


@pytest.fixture
def loopback():
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self, body):
            seen.append({"method": self.command, "path": self.path, "user_agent": self.headers.get("User-Agent")})
            raw = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self._answer({"keys": []})

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self._answer({"active": False})

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.unit
class TestDumontAuthUserAgent:
    def test_value(self):
        assert USER_AGENT == "dumont-hangar-api (+https://hangar.getdumont.ai)"

    def test_jwks_fetch(self, loopback):
        base, seen = loopback
        assert jwks_module._fetch_jwks(f"{base}/oauth/v2/keys", 5) == {"keys": []}
        assert seen == [{"method": "GET", "path": "/oauth/v2/keys", "user_agent": USER_AGENT}]

    def test_introspection_request(self, loopback):
        base, seen = loopback
        config = make_config(
            issuer=base,
            introspection_url=f"{base}/oauth/v2/introspect",
            introspection_client_id="client",
            introspection_client_secret="secret-for-tests",
        )
        assert introspection_module._call_issuer("opaque-token", config) == {"active": False}
        assert seen == [{"method": "POST", "path": "/oauth/v2/introspect", "user_agent": USER_AGENT}]
