"""
Guard decision tests: spend cap, rate limit, PII redaction, pass-through.

No network, no external services - the guard is pure local logic and the
audit log is a file in tmp_path.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from guardrail_core import Decision, Guard, Policy, ToolCall
from guardrail_core.audit import AuditLog, utcnow
from guardrail_core.policy import Allowlist, PiiRules, RateLimit, SpendCap


def make_guard(tmp_path, **policy_kwargs) -> Guard:
    policy = Policy(name="test", **policy_kwargs)
    return Guard(policy, AuditLog(tmp_path / "audit.jsonl"))


# -- allowed pass-through ---------------------------------------------------


def test_call_within_all_limits_is_allowed(tmp_path):
    guard = make_guard(
        tmp_path,
        spend_cap=SpendCap(per_call=1.0, window_amount=5.0, window_seconds=3600),
        rate_limit=RateLimit(max_calls=10, window_seconds=60),
        pii_rules=PiiRules(),
    )

    result = guard.check(ToolCall(tool="search", payload={"q": "weather"}, amount=0.25))

    assert result.decision is Decision.ALLOW
    assert result.allowed is True
    assert result.findings == []
    # The payload is passed through untouched when nothing fires.
    assert result.payload == {"q": "weather"}
    assert guard.window_spend() == 0.25
    assert guard.remaining_budget() == pytest.approx(4.75)


def test_free_call_skips_spend_rules(tmp_path):
    guard = make_guard(tmp_path, spend_cap=SpendCap(per_call=0.10))

    result = guard.check(ToolCall(tool="lookup", payload={"q": "x"}))

    assert result.decision is Decision.ALLOW
    assert guard.window_spend() == 0.0


# -- allowlist --------------------------------------------------------------


def test_allowlisted_recipient_is_allowed(tmp_path):
    guard = make_guard(tmp_path, allowlist=Allowlist(recipients=("acct_trusted",)))

    result = guard.check(ToolCall(tool="pay", recipient="acct_trusted"))

    assert result.decision is Decision.ALLOW


def test_recipient_not_on_the_allowlist_is_blocked(tmp_path):
    """Moved here from the MPP adapter: this is now a core rule."""
    guard = make_guard(tmp_path, allowlist=Allowlist(recipients=("acct_trusted",)))

    result = guard.check(ToolCall(tool="pay", recipient="acct_unknown"))

    assert result.decision is Decision.BLOCK
    assert result.rule == "allowlist.recipient_not_allowed"
    assert "acct_unknown" in result.reason


def test_calls_without_a_recipient_skip_the_allowlist(tmp_path):
    guard = make_guard(tmp_path, allowlist=Allowlist(recipients=("acct_trusted",)))

    result = guard.check(ToolCall(tool="search", payload={"q": "weather"}))

    assert result.call.recipient is None
    assert result.decision is Decision.ALLOW


def test_empty_allowlist_permits_everything(tmp_path):
    """An empty list is 'no restriction', not deny-all."""
    guard = make_guard(tmp_path, allowlist=Allowlist())

    assert guard.check(ToolCall(tool="pay", recipient="anyone")).decision is Decision.ALLOW


def test_allowlist_is_checked_before_spend_rules(tmp_path):
    guard = make_guard(
        tmp_path,
        allowlist=Allowlist(recipients=("acct_trusted",)),
        spend_cap=SpendCap(per_call=0.10),
    )

    result = guard.check(ToolCall(tool="pay", amount=99.0, recipient="acct_unknown"))

    assert result.rule == "allowlist.recipient_not_allowed"


def test_blocked_recipient_consumes_no_budget(tmp_path):
    guard = make_guard(
        tmp_path,
        allowlist=Allowlist(recipients=("acct_trusted",)),
        spend_cap=SpendCap(window_amount=5.0),
        rate_limit=RateLimit(max_calls=5, window_seconds=60),
    )

    guard.check(ToolCall(tool="pay", amount=3.0, recipient="acct_unknown"))

    assert guard.window_spend() == 0.0
    assert guard.window_calls() == 0


def test_recipient_is_recorded_in_the_audit_log(tmp_path):
    guard = make_guard(tmp_path, allowlist=Allowlist(recipients=("acct_trusted",)))
    guard.check(ToolCall(tool="pay", recipient="acct_trusted"))

    assert guard.audit_log.read_all()[-1].recipient == "acct_trusted"


# -- spend cap --------------------------------------------------------------


def test_per_call_spend_cap_blocks(tmp_path):
    guard = make_guard(tmp_path, spend_cap=SpendCap(per_call=1.00))

    result = guard.check(ToolCall(tool="premium_api", amount=2.50))

    assert result.decision is Decision.BLOCK
    assert result.rule == "spend_cap.per_call"
    assert "per-call spend cap exceeded" in result.reason
    # A blocked call consumes no budget.
    assert guard.window_spend() == 0.0


def test_rolling_window_spend_cap_blocks(tmp_path):
    guard = make_guard(
        tmp_path, spend_cap=SpendCap(window_amount=5.00, window_seconds=3600)
    )

    for _ in range(4):
        assert guard.check(ToolCall(tool="paid", amount=1.20)).allowed

    result = guard.check(ToolCall(tool="paid", amount=1.20))

    assert result.decision is Decision.BLOCK
    assert result.rule == "spend_cap.window"
    assert "rolling spend cap exceeded" in result.reason
    assert guard.window_spend() == pytest.approx(4.80)


def test_spend_exactly_on_the_cap_is_allowed(tmp_path):
    guard = make_guard(tmp_path, spend_cap=SpendCap(per_call=1.0, window_amount=1.0))

    result = guard.check(ToolCall(tool="paid", amount=1.0))

    assert result.decision is Decision.ALLOW


def test_spend_outside_the_window_does_not_count(tmp_path):
    guard = make_guard(
        tmp_path, spend_cap=SpendCap(window_amount=5.00, window_seconds=60)
    )

    old = ToolCall(tool="paid", amount=4.90, timestamp=utcnow() - timedelta(minutes=5))
    assert guard.check(old).allowed

    result = guard.check(ToolCall(tool="paid", amount=4.90))

    assert result.decision is Decision.ALLOW


def test_currency_mismatch_blocks(tmp_path):
    guard = make_guard(tmp_path, spend_cap=SpendCap(window_amount=5.0, currency="USD"))

    result = guard.check(ToolCall(tool="paid", amount=1.0, currency="EUR"))

    assert result.decision is Decision.BLOCK
    assert result.rule == "spend_cap.currency"


def test_spend_history_survives_a_new_guard_instance(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    policy = Policy(spend_cap=SpendCap(window_amount=5.00, window_seconds=3600))

    first = Guard(policy, log)
    assert first.check(ToolCall(tool="paid", amount=4.00)).allowed

    # A second process (fresh Guard) must reload the log and remember.
    second = Guard(policy, log)
    assert second.window_spend() == pytest.approx(4.00)
    assert second.check(ToolCall(tool="paid", amount=2.00)).decision is Decision.BLOCK


# -- rate limit -------------------------------------------------------------


def test_rate_limit_blocks_after_max_calls(tmp_path):
    guard = make_guard(tmp_path, rate_limit=RateLimit(max_calls=3, window_seconds=60))

    for _ in range(3):
        assert guard.check(ToolCall(tool="search")).allowed

    result = guard.check(ToolCall(tool="search"))

    assert result.decision is Decision.BLOCK
    assert result.rule == "rate_limit"
    assert "rate limit exceeded" in result.reason


def test_rate_limit_window_rolls_off(tmp_path):
    guard = make_guard(tmp_path, rate_limit=RateLimit(max_calls=2, window_seconds=60))

    past = utcnow() - timedelta(minutes=2)
    for _ in range(2):
        assert guard.check(ToolCall(tool="search", timestamp=past)).allowed

    # Those two calls are outside the 60s window now.
    assert guard.check(ToolCall(tool="search")).decision is Decision.ALLOW


def test_blocked_calls_do_not_consume_rate_budget(tmp_path):
    guard = make_guard(
        tmp_path,
        spend_cap=SpendCap(per_call=1.0),
        rate_limit=RateLimit(max_calls=2, window_seconds=60),
    )

    guard.check(ToolCall(tool="paid", amount=99.0))  # blocked on spend
    guard.check(ToolCall(tool="paid", amount=99.0))  # blocked on spend

    assert guard.window_calls() == 0
    assert guard.check(ToolCall(tool="paid", amount=0.5)).allowed


def test_dry_run_does_not_consume_budget(tmp_path):
    guard = make_guard(tmp_path, rate_limit=RateLimit(max_calls=1, window_seconds=60))

    assert guard.check(ToolCall(tool="search"), commit=False).allowed
    assert guard.window_calls() == 0
    assert guard.check(ToolCall(tool="search")).allowed


# -- PII --------------------------------------------------------------------


def test_pii_in_payload_is_redacted(tmp_path):
    guard = make_guard(tmp_path, pii_rules=PiiRules(action="redact"))

    result = guard.check(
        ToolCall(
            tool="send_prompt",
            payload={"prompt": "email me at ada@example.com", "key": "sk-abcdef0123456789ABCD"},
        )
    )

    assert result.decision is Decision.REDACT
    assert result.allowed is True
    assert "ada@example.com" not in str(result.redacted_payload)
    assert "sk-abcdef0123456789ABCD" not in str(result.redacted_payload)
    assert "[REDACTED:email]" in result.redacted_payload["prompt"]
    assert "[REDACTED:api_key]" in result.redacted_payload["key"]
    # The original call object is never mutated.
    assert "ada@example.com" in result.call.payload["prompt"]
    # .payload gives the caller the safe version to actually send.
    assert result.payload == result.redacted_payload


def test_pii_action_block_refuses_the_call(tmp_path):
    guard = make_guard(tmp_path, pii_rules=PiiRules(action="block"))

    result = guard.check(ToolCall(tool="send", payload={"body": "ada@example.com"}))

    assert result.decision is Decision.BLOCK
    assert result.rule == "pii_rules.block"


def test_pii_fields_restriction(tmp_path):
    guard = make_guard(
        tmp_path, pii_rules=PiiRules(detectors=("email",), fields=("query",))
    )

    result = guard.check(
        ToolCall(
            tool="search",
            payload={"query": "clean text", "notes": "ada@example.com"},
        )
    )

    # `notes` is outside the scanned fields, so nothing fires.
    assert result.decision is Decision.ALLOW


def test_spend_cap_wins_over_pii_when_both_would_fire(tmp_path):
    guard = make_guard(
        tmp_path, spend_cap=SpendCap(per_call=0.10), pii_rules=PiiRules()
    )

    result = guard.check(
        ToolCall(tool="paid", payload={"q": "ada@example.com"}, amount=5.0)
    )

    assert result.rule == "spend_cap.per_call"


# -- raise_if_blocked -------------------------------------------------------


def test_raise_if_blocked(tmp_path):
    from guardrail_core import BlockedByPolicy

    guard = make_guard(tmp_path, spend_cap=SpendCap(per_call=0.10))
    result = guard.check(ToolCall(tool="paid", amount=1.0))

    with pytest.raises(BlockedByPolicy) as excinfo:
        result.raise_if_blocked()

    assert excinfo.value.result is result
    assert "spend cap" in excinfo.value.reason
