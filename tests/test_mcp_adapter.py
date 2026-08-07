"""
MCP adapter tests.

No MCP SDK, no transport, no upstream server - requests are plain dicts
and `forward` is a local function that records what it received.
"""

from __future__ import annotations

import pytest

from guardrail_core import Decision, Policy
from guardrail_core.adapters.mcp import MCPGuard, is_tool_call
from guardrail_core.audit import AuditLog
from guardrail_core.policy import Allowlist, PiiRules, RateLimit, SpendCap


@pytest.fixture
def log(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def tool_call(name: str = "search", arguments: dict | None = None, request_id: int = 1):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments if arguments is not None else {}},
    }


# -- request classification -------------------------------------------------


def test_is_tool_call():
    assert is_tool_call(tool_call()) is True
    assert is_tool_call({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) is False
    assert is_tool_call({"jsonrpc": "2.0", "method": "initialize"}) is False
    assert is_tool_call("not a dict") is False


def test_non_tool_traffic_passes_through_unevaluated(log):
    guard = MCPGuard(Policy(rate_limit=RateLimit(max_calls=1)), audit_log=log)
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

    decision = guard.inspect(request)

    assert decision.blocked is False
    assert decision.request is request
    assert decision.result is None
    # Nothing logged: guarding handshake traffic would only add noise.
    assert log.read_all() == []


# -- allow ------------------------------------------------------------------


def test_allowed_call_is_forwarded_unchanged(log):
    guard = MCPGuard(Policy(rate_limit=RateLimit(max_calls=5)), audit_log=log)
    request = tool_call(arguments={"q": "weather"})

    decision = guard.inspect(request)

    assert decision.result.decision is Decision.ALLOW
    assert decision.request is request
    assert decision.response is None


def test_tool_name_and_arguments_are_mapped(log):
    guard = MCPGuard(Policy(), audit_log=log, server="files-server")

    call = guard.to_call(tool_call("read_file", {"path": "/tmp/x"}))

    assert call.tool == "mcp:read_file"
    assert call.payload == {"path": "/tmp/x"}
    assert call.recipient == "files-server"
    assert call.metadata["mcp_tool"] == "read_file"
    assert call.metadata["request_id"] == 1


def test_missing_arguments_are_treated_as_empty(log):
    guard = MCPGuard(Policy(), audit_log=log)

    call = guard.to_call({"method": "tools/call", "params": {"name": "ping"}})

    assert call.payload == {}


# -- block ------------------------------------------------------------------


def test_blocked_call_never_reaches_the_upstream(log):
    forwarded = []
    guard = MCPGuard(
        Policy(rate_limit=RateLimit(max_calls=1, window_seconds=60)), audit_log=log
    )

    guard.handle(tool_call(), forward=forwarded.append)
    response = guard.handle(tool_call(request_id=2), forward=forwarded.append)

    assert len(forwarded) == 1
    assert response["result"]["isError"] is True
    assert "rate limit exceeded" in response["result"]["content"][0]["text"]
    assert "rate_limit" in response["result"]["content"][0]["text"]


def test_block_is_a_tool_error_not_a_protocol_error(log):
    """The model should see the refusal as tool content it can act on."""
    guard = MCPGuard(Policy(rate_limit=RateLimit(max_calls=0)), audit_log=log)

    decision = guard.inspect(tool_call(request_id=7))

    assert "error" not in decision.response
    assert decision.response["id"] == 7
    assert decision.response["jsonrpc"] == "2.0"
    assert decision.response["result"]["isError"] is True


def test_spend_cap_blocks_with_amount_for(log):
    guard = MCPGuard(
        Policy(spend_cap=SpendCap(per_call=0.10)),
        audit_log=log,
        amount_for=lambda name, args: 1.00,
    )

    decision = guard.inspect(tool_call("premium_search"))

    assert decision.blocked is True
    assert decision.result.rule == "spend_cap.per_call"


def test_server_allowlist_blocks_untrusted_upstream(log):
    guard = MCPGuard(
        Policy(allowlist=Allowlist(recipients=("trusted-server",))),
        audit_log=log,
        server="sketchy-server",
    )

    decision = guard.inspect(tool_call())

    assert decision.blocked is True
    assert decision.result.rule == "allowlist.recipient_not_allowed"


def test_no_server_configured_skips_the_allowlist(log):
    guard = MCPGuard(
        Policy(allowlist=Allowlist(recipients=("trusted-server",))), audit_log=log
    )

    assert guard.inspect(tool_call()).blocked is False


# -- redact -----------------------------------------------------------------


def test_redaction_rewrites_arguments_before_forwarding(log):
    """The capability the LangChain adapter cannot offer."""
    received = []
    guard = MCPGuard(
        Policy(pii_rules=PiiRules(detectors=("email", "api_key"))), audit_log=log
    )
    request = tool_call("send", {"body": "ping ada@example.com", "n": 3})

    guard.handle(request, forward=lambda r: received.append(r) or {"ok": True})

    forwarded_args = received[0]["params"]["arguments"]
    assert "ada@example.com" not in forwarded_args["body"]
    assert "[REDACTED:email]" in forwarded_args["body"]
    # Non-string arguments survive untouched.
    assert forwarded_args["n"] == 3


def test_redaction_does_not_mutate_the_original_request(log):
    guard = MCPGuard(Policy(pii_rules=PiiRules(detectors=("email",))), audit_log=log)
    request = tool_call("send", {"body": "ping ada@example.com"})

    decision = guard.inspect(request)

    assert decision.redacted is True
    assert decision.request is not request
    assert request["params"]["arguments"]["body"] == "ping ada@example.com"


def test_redacted_call_is_still_forwarded(log):
    guard = MCPGuard(Policy(pii_rules=PiiRules(detectors=("email",))), audit_log=log)

    decision = guard.inspect(tool_call("send", {"body": "ada@example.com"}))

    # REDACT allows the call - unlike the LangChain adapter, which must
    # fail closed because it cannot rewrite the payload.
    assert decision.blocked is False
    assert decision.response is None


def test_pii_action_block_refuses_instead(log):
    guard = MCPGuard(
        Policy(pii_rules=PiiRules(detectors=("email",), action="block")), audit_log=log
    )

    decision = guard.inspect(tool_call("send", {"body": "ada@example.com"}))

    assert decision.blocked is True
    assert decision.result.rule == "pii_rules.block"


# -- shared state -----------------------------------------------------------


def test_budget_is_shared_with_another_adapter(log):
    """One Guard, several protocols, one budget."""
    from guardrail_core.adapters.generic import guarded

    policy = Policy(spend_cap=SpendCap(window_amount=1.0, window_seconds=3600))
    mcp = MCPGuard(policy, audit_log=log, amount_for=lambda name, args: 0.60)

    @guarded(guard=mcp.guard, amount=0.60)
    def local_tool() -> str:
        return "ok"

    assert mcp.inspect(tool_call()).blocked is False

    from guardrail_core import BlockedByPolicy

    with pytest.raises(BlockedByPolicy):
        local_tool()


def test_dry_run_does_not_consume_budget(log):
    guard = MCPGuard(
        Policy(rate_limit=RateLimit(max_calls=1, window_seconds=60)), audit_log=log
    )

    assert guard.inspect(tool_call(), commit=False).blocked is False
    assert guard.inspect(tool_call()).blocked is False


def test_requires_a_policy_or_guard():
    with pytest.raises(ValueError):
        MCPGuard()
