"""
Claude Code hook adapter tests.

No Claude Code process involved - hook events are plain dicts in the
same shape Claude Code sends on stdin, matching the fixture style
`tests/test_mcp_adapter.py` uses for MCP requests.
"""

from __future__ import annotations

import pytest

from guardrail_core import Decision, Policy
from guardrail_core.adapters.claude_code import ClaudeCodeGuard, extract_recipient
from guardrail_core.audit import AuditLog
from guardrail_core.policy import Allowlist, PiiRules, RateLimit


@pytest.fixture
def log(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def pretooluse(tool_name: str, tool_input: dict | None = None, call_id: str = "toolu_1"):
    return {
        "session_id": "s1",
        "cwd": "/tmp/project",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input if tool_input is not None else {},
        "tool_use_id": call_id,
    }


# -- recipient extraction ----------------------------------------------------


def test_webfetch_recipient_is_the_url_host():
    assert extract_recipient("WebFetch", {"url": "https://api.example.com/v1"}) == "api.example.com"


def test_webfetch_with_no_url_has_no_recipient():
    assert extract_recipient("WebFetch", {}) is None


def test_mcp_tool_recipient_is_the_server_name():
    assert extract_recipient("mcp__github__create_pr", {}) == "github"


def test_bash_with_curl_and_url_resolves_a_recipient():
    r = extract_recipient("Bash", {"command": "curl -sX POST https://api.stripe.com/v1/charges"})
    assert r == "api.stripe.com"


def test_bash_without_a_network_verb_has_no_recipient():
    assert extract_recipient("Bash", {"command": "ls -la /tmp"}) is None


def test_read_and_other_local_tools_have_no_recipient():
    assert extract_recipient("Read", {"file_path": "/etc/passwd"}) is None


# -- PreToolUse: allow --------------------------------------------------------


def test_allowed_call_returns_permission_decision_allow(log):
    guard = ClaudeCodeGuard(Policy(rate_limit=RateLimit(max_calls=5)), audit_log=log)

    out = guard.handle_pretooluse(pretooluse("Bash", {"command": "echo hi"}))

    spec = out["hookSpecificOutput"]
    assert spec["hookEventName"] == "PreToolUse"
    assert spec["permissionDecision"] == "allow"
    assert "updatedInput" not in spec


def test_tool_use_id_becomes_the_call_id(log):
    adapter = ClaudeCodeGuard(Policy(), audit_log=log)

    call = adapter.to_call(pretooluse("Bash", {"command": "echo hi"}, call_id="toolu_abc"))

    assert call.call_id == "toolu_abc"
    assert call.metadata["protocol"] == "claude-code"
    assert call.metadata["session_id"] == "s1"


# -- PreToolUse: deny ----------------------------------------------------------


def test_disallowed_recipient_is_denied(log):
    guard = ClaudeCodeGuard(
        Policy(allowlist=Allowlist(recipients=("api.example.com",))), audit_log=log
    )

    out = guard.handle_pretooluse(pretooluse("WebFetch", {"url": "https://evil.example.net"}))

    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "deny"
    assert "allowlist" in spec["permissionDecisionReason"]


def test_deny_is_ask_flag_escalates_instead_of_refusing(log):
    guard = ClaudeCodeGuard(
        Policy(allowlist=Allowlist(recipients=("api.example.com",))),
        audit_log=log,
        deny_is_ask=True,
    )

    out = guard.handle_pretooluse(pretooluse("WebFetch", {"url": "https://evil.example.net"}))

    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_rate_limit_blocks_the_call_over_budget(log):
    guard = ClaudeCodeGuard(Policy(rate_limit=RateLimit(max_calls=1, window_seconds=60)), audit_log=log)

    first = guard.handle_pretooluse(pretooluse("Bash", {"command": "echo 1"}, call_id="a"))
    second = guard.handle_pretooluse(pretooluse("Bash", {"command": "echo 2"}, call_id="b"))

    assert first["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert second["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "rate_limit" in second["hookSpecificOutput"]["permissionDecisionReason"]


# -- PreToolUse: redact --------------------------------------------------------


def test_pii_redaction_rewrites_tool_input_via_updated_input(log):
    guard = ClaudeCodeGuard(Policy(pii_rules=PiiRules(detectors=("email",))), audit_log=log)

    out = guard.handle_pretooluse(
        pretooluse("Bash", {"command": "echo 'contact ada@example.com'"})
    )

    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "allow"
    assert "[REDACTED:email]" in spec["updatedInput"]["command"]
    assert "ada@example.com" not in spec["updatedInput"]["command"]


def test_pii_block_action_denies_instead_of_redacting(log):
    guard = ClaudeCodeGuard(
        Policy(pii_rules=PiiRules(detectors=("email",), action="block")), audit_log=log
    )

    out = guard.handle_pretooluse(pretooluse("Bash", {"command": "ada@example.com"}))

    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


# -- amount_for is opt-in and Claude-Code-supplies-no-real-cost ---------------


def test_spend_cap_only_applies_when_amount_for_is_supplied(log):
    from guardrail_core.policy import SpendCap

    guard = ClaudeCodeGuard(
        Policy(spend_cap=SpendCap(per_call=0.01)),
        audit_log=log,
        amount_for=lambda tool, inp: 5.00,
    )

    out = guard.handle_pretooluse(pretooluse("mcp__stripe__charge", {}))

    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "spend_cap" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_no_amount_for_means_no_spend_tracking(log):
    from guardrail_core.policy import SpendCap

    guard = ClaudeCodeGuard(Policy(spend_cap=SpendCap(per_call=0.01)), audit_log=log)

    out = guard.handle_pretooluse(pretooluse("mcp__stripe__charge", {}))

    # No amount_for -> call.amount is None -> spend_cap rule is skipped entirely.
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


# -- PostToolUse ----------------------------------------------------------------


def test_posttooluse_reconciles_a_prior_decision(log):
    guard = ClaudeCodeGuard(Policy(), audit_log=log)
    guard.handle_pretooluse(pretooluse("Bash", {"command": "echo hi"}, call_id="toolu_x"))

    out = guard.handle_posttooluse(
        {"tool_use_id": "toolu_x", "tool_response": {"is_error": False}}
    )

    assert out == {}
    entries = log.read_all()
    assert any(e.decision == "RECONCILE" for e in entries)


def test_posttooluse_never_raises_for_an_unknown_call_id(log):
    guard = ClaudeCodeGuard(Policy(), audit_log=log)

    # No matching PreToolUse decision was ever recorded for this id.
    out = guard.handle_posttooluse({"tool_use_id": "never-seen", "tool_response": {}})

    assert out == {}


def test_posttooluse_without_tool_use_id_is_a_noop(log):
    guard = ClaudeCodeGuard(Policy(), audit_log=log)

    assert guard.handle_posttooluse({}) == {}
