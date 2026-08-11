"""
Local forward proxy enforcing a network egress allowlist.

Every other enforcement point in this package acts at the tool-call
layer: it sees an MCP `tools/call`, a Claude Code `PreToolUse` event, a
decorated Python function -- and blocks or allows based on what the
*tool* claims it is about to do. That is necessarily best effort:
`guardrail_core.adapters.claude_code.extract_recipient` reads a Bash
command's text looking for a URL, and a command that builds a URL from
a variable at runtime is invisible to it.

`GuardedProxy` is a different enforcement point: a real HTTP/HTTPS
forward proxy the agent process is *configured* to use (`HTTP_PROXY`,
`HTTPS_PROXY`), so every outbound connection -- `curl`, `requests`,
`fetch`, an MCP server's own HTTP client, anything -- goes through one
choke point regardless of which tool made it or how the destination was
computed. `policy.allowlist` becomes the set of hosts the process may
reach at all; `policy.rate_limit` caps outbound connections per window.

    guard = Guard(Policy.from_yaml("policy.yaml"), audit_log="logs/guardrail-audit.jsonl")
    proxy = GuardedProxy(guard, port=8899)
    proxy.serve_forever()   # or .run_in_background() for tests/embedding

Then point the agent's process at it:

    export HTTP_PROXY=http://127.0.0.1:8899
    export HTTPS_PROXY=http://127.0.0.1:8899

## What this does not do

- **No TLS interception.** `CONNECT` requests are allowed or denied by
  hostname only; once tunneled, bytes are relayed opaquely. Seeing
  inside an HTTPS request would mean terminating TLS at the proxy with
  a locally-trusted CA installed into the agent's trust store -- a much
  bigger, more fragile piece of infrastructure than a spend/audit tool
  should quietly take on. This proxy answers "is this host allowed?",
  not "is this request's content allowed?" -- pair it with
  `guardrail_core.detectors` at the tool-call layer for content rules.
- **No enforcement against a process that ignores the proxy.** Nothing
  stops code with direct socket access from dialing out and bypassing
  `HTTP_PROXY` entirely. This is a control for well-behaved HTTP
  clients (which covers the overwhelming majority of what agent tooling
  actually does), not a network namespace or firewall. For a hard
  boundary, run the agent in a container or VM whose only route out is
  through this proxy.
"""

from __future__ import annotations

import argparse
import http.client
import logging
import os
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .guard import Guard, ToolCall
from .policy import Policy

__all__ = ["GuardedProxy", "main"]

logger = logging.getLogger("guardrail_core.egress")

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
}


def _relay(client_sock: socket.socket, upstream_sock: socket.socket, *, idle_timeout: float = 60.0) -> None:
    """Bidirectionally copy bytes between two connected sockets until
    either side closes or goes idle for `idle_timeout` seconds."""
    sockets = [client_sock, upstream_sock]
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, idle_timeout)
            if exceptional or not readable:
                break
            stop = False
            for sock in readable:
                other = upstream_sock if sock is client_sock else client_sock
                try:
                    data = sock.recv(65536)
                except OSError:
                    stop = True
                    break
                if not data:
                    stop = True
                    break
                try:
                    other.sendall(data)
                except OSError:
                    stop = True
                    break
            if stop:
                break
    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass


class _Handler(BaseHTTPRequestHandler):
    guard: Guard  # bound per-instance by GuardedProxy via a handler subclass
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default; use logging instead
        logger.debug(fmt, *args)

    # -- CONNECT (HTTPS tunnel) -----------------------------------------

    def do_CONNECT(self) -> None:  # noqa: N802 - http.server's naming convention
        host, _, port_s = self.path.partition(":")
        port = int(port_s or 443)

        if not self._check(host, "CONNECT"):
            self._send_empty(403, "Forbidden by guardrail-core policy")
            return

        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            self._send_empty(502, f"Could not reach {host}:{port}: {exc}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        _relay(self.connection, upstream)

    # -- plain HTTP methods -----------------------------------------------

    def _do_forward(self, method: str) -> None:
        parsed = urlsplit(self.path)
        host = parsed.hostname or self.headers.get("Host", "").split(":")[0]

        if not self._check(host, method):
            self._send_empty(403, "Forbidden by guardrail-core policy")
            return

        is_https = parsed.scheme == "https"
        port = parsed.port or (443 if is_https else 80)
        conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
        target = parsed.path or "/"
        if parsed.query:
            target += f"?{parsed.query}"

        body_len = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(body_len) if body_len else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP}

        try:
            conn = conn_cls(host, port, timeout=15)
            conn.request(method, target, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except OSError as exc:
            self._send_empty(502, f"Upstream error: {exc}")
            return

        self.send_response(resp.status, resp.reason)
        sent_length = False
        for key, value in resp.getheaders():
            if key.lower() not in _HOP_BY_HOP:
                self.send_header(key, value)
                sent_length = sent_length or key.lower() == "content-length"
        if not sent_length:
            # Under HTTP/1.1 keep-alive, a response with neither
            # Content-Length nor chunked encoding leaves the client
            # blocked in read() waiting for a body that will never
            # arrive and a connection that will never close on its own.
            self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_empty(self, status: int, reason: str) -> None:
        """A response with no body, safe under HTTP/1.1 keep-alive.

        `send_response`/`end_headers` alone leave Content-Length unset,
        which under `protocol_version = "HTTP/1.1"` means the client
        waits for a close-delimited body that this handler -- which
        keeps the connection open for the next request -- never sends.
        Every early-return path (blocked, upstream unreachable) must
        set Content-Length: 0 explicitly.
        """
        self.send_response(status, reason)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self._do_forward("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._do_forward("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._do_forward("PUT")

    def do_PATCH(self) -> None:  # noqa: N802
        self._do_forward("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._do_forward("DELETE")

    def do_HEAD(self) -> None:  # noqa: N802
        self._do_forward("HEAD")

    # -- policy -----------------------------------------------------------

    def _check(self, host: str, method: str) -> bool:
        call = ToolCall(tool=f"egress:{method.lower()}", recipient=host or None)
        result = self.guard.check(call)
        return result.allowed


class GuardedProxy:
    """A guardrail-core-enforced HTTP/HTTPS forward proxy.

    Every `CONNECT` (HTTPS) and every plain HTTP request is evaluated as
    a `ToolCall(tool="egress:<method>", recipient=<hostname>)` against
    `guard`'s policy before being forwarded.
    """

    def __init__(self, guard: Guard, *, host: str = "127.0.0.1", port: int = 8899):
        self.guard = guard
        self.host = host
        handler = type("_BoundHandler", (_Handler,), {"guard": guard})
        self._server = ThreadingHTTPServer((host, port), handler)
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._server.server_port

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def serve_forever(self) -> None:
        logger.info("guardrail-core egress proxy listening on %s", self.url)
        self._server.serve_forever()

    def run_in_background(self) -> "GuardedProxy":
        """Start serving on a daemon thread; returns self for chaining.

        Intended for tests and for embedding the proxy inside a longer-
        running process. Call `shutdown()` (or use as a context manager)
        to stop it.
        """
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "GuardedProxy":
        return self.run_in_background()

    def __exit__(self, *exc_info: Any) -> None:
        self.shutdown()


# -- CLI entry point --------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m guardrail_core.egress",
        description="Run a guardrail-core-enforced HTTP/HTTPS forward proxy.",
    )
    parser.add_argument(
        "--policy", default=os.environ.get("GUARDRAIL_POLICY", "guardrails/policy.yaml")
    )
    parser.add_argument(
        "--audit-log",
        default=os.environ.get("GUARDRAIL_AUDIT_LOG", "logs/guardrail-audit.jsonl"),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8899)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    policy = Policy.from_yaml(args.policy)
    guard = Guard(policy, audit_log=args.audit_log)
    proxy = GuardedProxy(guard, host=args.host, port=args.port)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
