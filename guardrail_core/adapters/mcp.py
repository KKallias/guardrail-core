"""
MCP (Model Context Protocol) adapter.

Guards `tools/call` requests as they pass through an MCP proxy: your
client points at this instead of the upstream server, every tool call is
evaluated against a `Policy`, and blocked calls never reach the upstream.

This adapter has a capability the LangChain one does not. A LangChain
callback can only allow or refuse - it cannot touch the tool input - so
REDACT has to fail closed there. An MCP proxy sits in the middle of the
JSON-RPC stream and *can* rewrite `params.arguments` before forwarding,
so REDACT does what it says: the upstream server receives the redacted
arguments and the call still succeeds.

No dependency on any MCP SDK: requests and responses are plain dicts, in
the same style as the x402 and MPP adapters. That keeps this usable from
a stdio proxy, an HTTP shim, or a test, without pinning a transport.

    guard = MCPGuard(Policy.from_yaml("policy.yaml"))

    def handle(request):
        decision = guard.inspect(request)
        if decision.response is not None:
            return decision.response          # refused, never forwarded
        return upstream.send(decision.request) # possibly redacted

A blocked call comes back as a normal tool result with `isError: true`,
not a JSON-RPC protocol error. That is deliberate: MCP reserves protocol
errors for malformed requests, while a tool-level failure goes back to
the model as content it can read and adapt to ("that was blocked by
policy, try something cheaper"). A protocol error would instead look to
the client like the server is broken.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..audit import AuditLog
from ..guard import Decision, Guard, GuardResult, ToolCall
from ..policy import Policy

__all__ = ["MCPGuard", "MCPDecision", "is_tool_call"]

TOOLS_CALL = "tools/call"


def is_tool_call(request: dict[str, Any]) -> bool:
    """True for a `tools/call` JSON-RPC request.

    Everything else on the wire - `initialize`, `tools/list`,
    `resources/read`, notifications - is not a tool invocation and is
    not this adapter's business.
    """
    return isinstance(request, dict) and request.get("method") == TOOLS_CALL


@dataclass
class MCPDecision:
    """What the proxy should do with one request.

    Exactly one of the two matters at a time:

    - `response` is not None -> the call was refused. Return this to the
      client and do not contact the upstream server.
    - `response` is None -> forward `request`. It is the original object
      for ALLOW, and a copy with redacted arguments for REDACT.

    `result` is the underlying `GuardResult`, or None for a request that
    was not a tool call and so was never evaluated.
    """

    request: dict[str, Any]
    response: dict[str, Any] | None = None
    result: GuardResult | None = None

    @property
    def blocked(self) -> bool:
        return self.response is not None

    @property
    def redacted(self) -> bool:
        return self.result is not None and self.result.decision is Decision.REDACT


class MCPGuard:
    """Evaluates MCP `tools/call` requests against a `Policy`.

    Parameters
    ----------
    policy / guard:
        A policy to enforce, or an existing `Guard` to share spend and
        rate-limit budget with other adapters in the same process.
    server:
        Name of the upstream server, recorded in the audit log and used
        as the call's recipient so `allowlist.recipients` can restrict
        which servers may be reached. Leave None to skip that rule.
    amount_for:
        Callable `(tool_name, arguments) -> float | None` returning what
        this call costs. MCP has no notion of price, so without this
        every call is free and only rate-limit, allowlist and PII rules
        apply.
    tool_prefix:
        Prefix for the recorded tool name. Defaults to `"mcp:"`, so an
        audit log covering several protocols stays readable.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        guard: Guard | None = None,
        audit_log: AuditLog | Path | str | None = None,
        server: str | None = None,
        amount_for: Callable[[str, dict[str, Any]], float | None] | None = None,
        tool_prefix: str = "mcp:",
    ):
        if guard is None:
            if policy is None:
                raise ValueError("MCPGuard requires either a policy or a guard")
            guard = Guard(policy, audit_log)
        self.guard = guard
        self.server = server
        self.amount_for = amount_for
        self.tool_prefix = tool_prefix

    # -- mapping ---------------------------------------------------------

    def to_call(self, request: dict[str, Any]) -> ToolCall:
        """Map a `tools/call` request onto a `ToolCall`."""
        params = request.get("params") or {}
        name = params.get("name") or "unknown"
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            # MCP allows arguments to be omitted for a no-argument tool.
            arguments = {} if arguments is None else {"arguments": arguments}

        amount = self.amount_for(name, arguments) if self.amount_for else None

        return ToolCall(
            tool=f"{self.tool_prefix}{name}",
            payload=arguments,
            amount=amount,
            # The upstream server is the counterparty here: which server a
            # call may reach is the MCP-shaped version of "who may be paid".
            recipient=self.server,
            metadata={
                "protocol": "mcp",
                "server": self.server,
                "mcp_tool": name,
                "request_id": request.get("id"),
            },
        )

    # -- enforcement -----------------------------------------------------

    def inspect(self, request: dict[str, Any], *, commit: bool = True) -> MCPDecision:
        """Evaluate one request and say what the proxy should do with it.

        Non-tool-call traffic passes straight through unevaluated and
        unlogged - guarding `initialize` would only add noise to the
        audit log.
        """
        if not is_tool_call(request):
            return MCPDecision(request=request)

        call = self.to_call(request)
        result = self.guard.check(call, commit=commit)

        if result.blocked:
            return MCPDecision(
                request=request,
                response=self.error_response(request, result),
                result=result,
            )

        if result.decision is Decision.REDACT:
            # The whole point of proxying: rewrite before forwarding, so
            # the upstream server never sees the sensitive values.
            return MCPDecision(request=self.redacted_request(request, result), result=result)

        return MCPDecision(request=request, result=result)

    def redacted_request(
        self, request: dict[str, Any], result: GuardResult
    ) -> dict[str, Any]:
        """A shallow copy of `request` with redacted `params.arguments`.

        The original request object is left untouched - a caller that
        logs the raw request elsewhere should keep seeing what arrived.
        """
        params = dict(request.get("params") or {})
        params["arguments"] = result.redacted_payload
        forwarded = dict(request)
        forwarded["params"] = params
        return forwarded

    def error_response(
        self, request: dict[str, Any], result: GuardResult
    ) -> dict[str, Any]:
        """A tool result marking the call as refused.

        `isError: true` rather than a JSON-RPC `error` object - see the
        module docstring on why the model, not the client, should be the
        one to see this.
        """
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"Blocked by guardrail policy "
                            f"[{result.rule or 'policy'}]: {result.reason}"
                        ),
                    }
                ],
            },
        }

    def handle(
        self,
        request: dict[str, Any],
        forward: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        """Convenience wrapper: inspect, then refuse or forward.

        `forward` is whatever actually talks to the upstream server.
        """
        decision = self.inspect(request)
        if decision.response is not None:
            return decision.response
        return forward(decision.request)
