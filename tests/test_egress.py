"""
GuardedProxy tests.

A real (loopback-only) HTTP server plays the role of "upstream", and a
real `GuardedProxy` sits in front of it, so these exercise the actual
socket and HTTP plumbing rather than mocking it away. Everything binds
to 127.0.0.1 on an OS-assigned port (port 0) so the suite never touches
the network or a fixed port another test could collide with.

Requests go through `http.client.HTTPConnection` pointed directly at the
proxy's host:port with an absolute-URI request target, rather than
`urllib.request`'s `ProxyHandler`. `urllib` (and most HTTP libraries)
treat 127.0.0.1/localhost targets as proxy-bypass candidates by default
on some platforms, which would silently skip the proxy entirely and
test nothing.
"""

from __future__ import annotations

import http.client
import http.server
import threading

import pytest

from guardrail_core.audit import AuditLog
from guardrail_core.egress import GuardedProxy
from guardrail_core.guard import Guard
from guardrail_core.policy import Allowlist, Policy, RateLimit


class _EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # keep test output quiet
        pass


@pytest.fixture
def upstream():
    server = http.server.HTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port
    server.shutdown()


@pytest.fixture
def log(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def _get(proxy: GuardedProxy, target_url: str, timeout: float = 5) -> http.client.HTTPResponse:
    """GET `target_url` through `proxy`, one connection per call.

    Mirrors how a real HTTP client behind `HTTP_PROXY` talks to a
    forward proxy: connect to the proxy's own host:port, then send an
    absolute-URI request line naming the real destination.
    """
    conn = http.client.HTTPConnection(proxy.host, proxy.port, timeout=timeout)
    conn.request("GET", target_url)
    return conn.getresponse()


# -- allow --------------------------------------------------------------------


def test_allowlisted_host_is_forwarded(upstream, log):
    guard = Guard(Policy(allowlist=Allowlist(recipients=("127.0.0.1",))), audit_log=log)

    with GuardedProxy(guard, port=0) as proxy:
        resp = _get(proxy, f"http://127.0.0.1:{upstream}/ping")
        assert resp.status == 200
        assert resp.read() == b"ok"


def test_no_allowlist_means_no_restriction(upstream, log):
    guard = Guard(Policy(), audit_log=log)  # no allowlist section at all

    with GuardedProxy(guard, port=0) as proxy:
        resp = _get(proxy, f"http://127.0.0.1:{upstream}/ping")
        assert resp.status == 200
        assert resp.read() == b"ok"


# -- block --------------------------------------------------------------------


def test_non_allowlisted_host_is_rejected_with_403(log):
    guard = Guard(Policy(allowlist=Allowlist(recipients=("127.0.0.1",))), audit_log=log)

    with GuardedProxy(guard, port=0) as proxy:
        resp = _get(proxy, "http://blocked.invalid.example/x")
        assert resp.status == 403
        resp.read()


def test_blocked_host_is_never_dns_resolved_or_connected(log):
    """The policy check happens before any attempt to reach the host, so
    a completely bogus hostname is refused the same way a real-but-
    disallowed one would be -- no network attempt, no timeout."""
    guard = Guard(Policy(allowlist=Allowlist(recipients=("127.0.0.1",))), audit_log=log)

    with GuardedProxy(guard, port=0) as proxy:
        resp = _get(proxy, "http://this-host-does-not-exist.invalid/x", timeout=2)
        assert resp.status == 403
        resp.read()


def test_rate_limit_applies_across_requests(upstream, log):
    guard = Guard(Policy(rate_limit=RateLimit(max_calls=1, window_seconds=60)), audit_log=log)

    with GuardedProxy(guard, port=0) as proxy:
        first = _get(proxy, f"http://127.0.0.1:{upstream}/a")
        assert first.status == 200
        assert first.read() == b"ok"

        second = _get(proxy, f"http://127.0.0.1:{upstream}/b")
        assert second.status == 403
        second.read()


# -- audit trail ----------------------------------------------------------------


def test_every_request_is_audited(upstream, log):
    guard = Guard(Policy(allowlist=Allowlist(recipients=("127.0.0.1",))), audit_log=log)

    with GuardedProxy(guard, port=0) as proxy:
        _get(proxy, f"http://127.0.0.1:{upstream}/ping").read()
        _get(proxy, "http://blocked.invalid.example/x").read()

    entries = log.read_all()
    assert len(entries) == 2
    assert entries[0].decision == "ALLOW"
    assert entries[0].recipient == "127.0.0.1"
    assert entries[1].decision == "BLOCK"
    assert entries[1].recipient == "blocked.invalid.example"


# -- lifecycle ------------------------------------------------------------------


def test_proxy_picks_a_free_port_when_given_zero(log):
    guard = Guard(Policy(), audit_log=log)

    with GuardedProxy(guard, port=0) as proxy:
        assert proxy.port != 0
        assert proxy.url == f"http://127.0.0.1:{proxy.port}"


def test_shutdown_stops_the_background_thread(log):
    guard = Guard(Policy(), audit_log=log)
    proxy = GuardedProxy(guard, port=0).run_in_background()

    proxy.shutdown()

    assert proxy._thread is None
