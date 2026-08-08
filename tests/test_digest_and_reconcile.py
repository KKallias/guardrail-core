"""
Decision digests and after-the-fact reconciliation.

Neither of these prevents anything - they make a divergence between what
was decided and what actually ran detectable. The tests pin exactly that
much and no more.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from guardrail_core import Decision, Guard, Policy, ToolCall
from guardrail_core.audit import RECONCILE, AuditLog, utcnow
from guardrail_core.guard import UnknownCallId, compute_digest
from guardrail_core.policy import PiiRules, SpendCap


@pytest.fixture
def log(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def make_call(**overrides) -> ToolCall:
    defaults = dict(
        tool="pay",
        payload={"q": "x"},
        amount=1.00,
        currency="USD",
        recipient="acct_a",
        call_id="fixed-id",
        timestamp=utcnow(),
    )
    defaults.update(overrides)
    return ToolCall(**defaults)


# -- digest stability -------------------------------------------------------


def test_digest_is_stable_for_identical_input():
    call = make_call()

    assert compute_digest(call) == compute_digest(call)
    # A separate object with the same field values digests identically.
    assert compute_digest(call) == compute_digest(make_call(timestamp=call.timestamp))


@pytest.mark.parametrize(
    "field,value",
    [
        ("tool", "other_tool"),
        ("recipient", "acct_b"),
        ("amount", 1.01),
        ("currency", "EUR"),
        ("call_id", "different-id"),
    ],
)
def test_digest_changes_when_any_covered_field_changes(field, value):
    base = make_call()
    changed = make_call(**{field: value, "timestamp": base.timestamp})

    assert compute_digest(changed) != compute_digest(base)


def test_digest_changes_with_the_timestamp():
    base = make_call()
    later = make_call(timestamp=base.timestamp + timedelta(seconds=1))

    assert compute_digest(later) != compute_digest(base)


def test_digest_ignores_the_payload():
    """Redaction rewrites the payload; it must not invalidate the digest."""
    base = make_call(payload={"body": "ada@example.com"})
    other = make_call(payload={"body": "[REDACTED:email]"}, timestamp=base.timestamp)

    assert compute_digest(other) == compute_digest(base)


def test_digest_is_hex_sha256():
    digest = compute_digest(make_call())

    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


# -- digest on results ------------------------------------------------------


def test_allow_and_redact_carry_a_digest(log):
    guard = Guard(Policy(pii_rules=PiiRules(detectors=("email",))), log)

    allowed = guard.check(ToolCall(tool="a", payload={"q": "clean"}))
    redacted = guard.check(ToolCall(tool="b", payload={"q": "ada@example.com"}))

    assert allowed.decision is Decision.ALLOW
    assert redacted.decision is Decision.REDACT
    assert allowed.digest and redacted.digest
    assert allowed.digest != redacted.digest


def test_blocked_result_has_no_digest(log):
    """Nothing was approved, so there is no operation to bind."""
    guard = Guard(Policy(spend_cap=SpendCap(per_call=0.10)), log)

    result = guard.check(ToolCall(tool="pay", amount=5.00))

    assert result.decision is Decision.BLOCK
    assert result.digest is None
    assert result.matches(result.call) is False


def test_matches_detects_drift_between_check_and_execution(log):
    guard = Guard(Policy(), log)
    call = make_call(amount=1.00)
    result = guard.check(call)

    # Same operation: safe to execute.
    assert result.matches(call) is True

    # The amount was recomputed between the check and the call - a retry,
    # a re-resolved price. Not what was approved.
    drifted = make_call(amount=9.99, timestamp=call.timestamp)
    assert result.matches(drifted) is False

    # A re-resolved recipient is caught too.
    assert result.matches(make_call(recipient="acct_evil", timestamp=call.timestamp)) is False


def test_digest_is_written_to_the_audit_log(log):
    guard = Guard(Policy(), log)

    result = guard.check(make_call())

    assert log.read_all()[-1].digest == result.digest


# -- reconciliation ---------------------------------------------------------


def test_reconcile_records_a_match(log):
    guard = Guard(Policy(), log)
    result = guard.check(make_call(recipient="acct_a", amount=1.00))

    guard.reconcile(result.call.call_id, {"recipient": "acct_a", "amount": 1.00})

    entry = log.read_all()[-1]
    assert entry.decision == RECONCILE
    assert entry.rule == "reconcile.match"
    assert entry.metadata["reconciles"] == result.call.call_id


def test_reconcile_flags_a_recipient_mismatch(log):
    guard = Guard(Policy(), log)
    result = guard.check(make_call(recipient="acct_approved"))

    guard.reconcile(result.call.call_id, {"recipient": "acct_somewhere_else"})

    entry = log.read_all()[-1]
    assert entry.rule == "reconcile.mismatch"
    assert "acct_approved" in entry.reason
    assert "acct_somewhere_else" in entry.reason
    # The entry records what actually happened, not what was decided.
    assert entry.recipient == "acct_somewhere_else"


def test_reconcile_flags_an_amount_mismatch(log):
    guard = Guard(Policy(), log)
    result = guard.check(make_call(amount=1.00))

    guard.reconcile(result.call.call_id, {"amount": 2.50})

    assert log.read_all()[-1].rule == "reconcile.mismatch"


def test_reconcile_tolerates_float_noise(log):
    """0.1 + 0.2 must not read as a mismatch against 0.3."""
    guard = Guard(Policy(), log)
    result = guard.check(make_call(amount=0.3))

    guard.reconcile(result.call.call_id, {"amount": 0.1 + 0.2})

    assert log.read_all()[-1].rule == "reconcile.match"


def test_reconcile_flags_a_caller_reported_failure(log):
    guard = Guard(Policy(), log)
    result = guard.check(make_call())

    guard.reconcile(
        result.call.call_id, {"ok": False, "reason": "settlement never landed"}
    )

    entry = log.read_all()[-1]
    assert entry.rule == "reconcile.mismatch"
    assert "settlement never landed" in entry.reason


def test_reconcile_on_unknown_call_id_raises(log):
    """Silence here would produce a log that looks complete but isn't."""
    guard = Guard(Policy(), log)
    guard.check(make_call())

    with pytest.raises(UnknownCallId) as excinfo:
        guard.reconcile("never-decided", {"recipient": "acct_a"})

    assert "never-decided" in str(excinfo.value)
    # Nothing was appended for the unknown id.
    assert all(e.call_id != "never-decided" for e in log.read_all())


def test_reconcile_does_not_rewrite_the_original_entry(log):
    guard = Guard(Policy(), log)
    result = guard.check(make_call(recipient="acct_a"))
    original_line = log.path.read_text(encoding="utf-8").splitlines()[0]

    guard.reconcile(result.call.call_id, {"recipient": "acct_b"})

    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == original_line
    assert len(lines) == 2


def test_reconcile_entry_points_at_the_original_digest(log):
    guard = Guard(Policy(), log)
    result = guard.check(make_call())

    guard.reconcile(result.call.call_id, {"amount": 99.0})

    assert log.read_all()[-1].digest == result.digest


def test_reconciling_twice_compares_against_the_decision(log):
    guard = Guard(Policy(), log)
    result = guard.check(make_call(recipient="acct_a"))

    guard.reconcile(result.call.call_id, {"recipient": "acct_b"})
    guard.reconcile(result.call.call_id, {"recipient": "acct_a"})

    # The second reconciliation compares against the original decision,
    # not against the first reconciliation.
    assert log.read_all()[-1].rule == "reconcile.match"


def test_extra_keys_are_recorded_as_metadata(log):
    guard = Guard(Policy(), log)
    result = guard.check(make_call())

    guard.reconcile(result.call.call_id, {"tx_hash": "0xabc", "network": "base-sepolia"})

    metadata = log.read_all()[-1].metadata
    assert metadata["tx_hash"] == "0xabc"
    assert metadata["network"] == "base-sepolia"


def test_reconciliation_never_moves_a_budget(log):
    policy = Policy(spend_cap=SpendCap(window_amount=5.00))
    guard = Guard(policy, log)
    result = guard.check(make_call(amount=2.00))
    guard.reconcile(result.call.call_id, {"amount": 2.00})

    assert guard.window_spend() == pytest.approx(2.00)

    # And a fresh process replaying the log must not double-count it.
    assert Guard(policy, log).window_spend() == pytest.approx(2.00)


def test_blocked_calls_can_be_reconciled_too(log):
    """A refused call that somehow ran is the most important mismatch."""
    guard = Guard(Policy(spend_cap=SpendCap(per_call=0.10)), log)
    result = guard.check(make_call(amount=5.00))
    assert result.blocked

    guard.reconcile(result.call.call_id, {"ok": False, "reason": "executed anyway"})

    entry = log.read_all()[-1]
    assert entry.rule == "reconcile.mismatch"
    assert entry.metadata["original_decision"] == Decision.BLOCK.value
