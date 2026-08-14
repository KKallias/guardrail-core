"""
Two-phase reservations: `Guard.reserve` / `finalize` / `release`.

`check(commit=False)` is a pure evaluation with no side effects (see its
docstring) - it holds nothing, so two concurrent dry runs can both
evaluate against the same unspent budget and then both go on to commit.
`reserve` closes that gap by evaluating and holding the budget under one
lock, and gives the call site an explicit way to say "it happened"
(`finalize`) or "it didn't" (`release`) afterwards - including release
happening automatically once a reservation's TTL passes unconfirmed.

These tests pin the five cases from the discussion review: a concurrent
race for the last unit of budget, a challenge that changes after
preflight, a duplicate call_id, a failure after reservation, and a
settlement mismatch. No network, no threads left running past their
test - offline, same as the rest of the suite.
"""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest

from guardrail_core import Decision, Guard, Policy, ToolCall
from guardrail_core.audit import AuditLog, utcnow
from guardrail_core.guard import UnknownCallId
from guardrail_core.policy import RateLimit, SpendCap


def make_guard(tmp_path, **policy_kwargs) -> Guard:
    policy = Policy(name="test", **policy_kwargs)
    return Guard(policy, AuditLog(tmp_path / "audit.jsonl"))


# -- 1. concurrent calls racing the last unit of budget ----------------------


def test_concurrent_reserve_exactly_one_wins_the_last_unit_of_budget(tmp_path):
    """Two threads reserve against a cap that only fits one of them.

    `check(commit=False)` would let both threads evaluate against the
    same unspent budget and both come back ALLOW. `reserve` serializes
    the evaluate-and-hold under one lock, so only the thread that
    actually gets the lock first sees the budget as available.
    """
    guard = make_guard(tmp_path, spend_cap=SpendCap(window_amount=1.0, window_seconds=3600))

    barrier = threading.Barrier(2)
    results: list[Decision] = []
    results_lock = threading.Lock()

    def attempt(call_id: str) -> None:
        barrier.wait()  # line both threads up so they race for real
        call = ToolCall(tool="pay", amount=0.6, call_id=call_id)
        result = guard.reserve(call)
        with results_lock:
            results.append(result.decision)

    threads = [
        threading.Thread(target=attempt, args=("racer-a",)),
        threading.Thread(target=attempt, args=("racer-b",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert sorted(results) == sorted([Decision.ALLOW, Decision.BLOCK])
    # Only the winner's amount is held - never both.
    assert guard.window_spend() == pytest.approx(0.6)


# -- 2. a challenge that changes after preflight ------------------------------


def test_challenge_change_after_preflight_is_caught_and_released(tmp_path):
    """The amount (or recipient) quoted at preflight is not what actually
    settled. The call site must detect this with `matches()` and release
    rather than finalize - it must never silently accept the new terms.
    """
    guard = make_guard(tmp_path, spend_cap=SpendCap(window_amount=5.0))

    quoted = ToolCall(tool="x402:/data", amount=1.00, recipient="acct_a", call_id="chal-1")
    result = guard.reserve(quoted)
    assert result.allowed

    # The facilitator settles at a different amount than it quoted.
    actually_charged = ToolCall(
        tool="x402:/data",
        amount=4.00,
        recipient="acct_a",
        call_id="chal-1",
        timestamp=result.call.timestamp,
    )
    assert result.matches(actually_charged) is False

    guard.release(result.call.call_id, reason="challenge changed after preflight")

    # The held budget comes back - nothing was actually spent.
    assert guard.window_spend() == pytest.approx(0.0)
    # And the call_id is closed: it cannot be finalized after release.
    with pytest.raises(UnknownCallId):
        guard.finalize(result.call.call_id)


# -- 3. duplicate call_id ------------------------------------------------------


def test_duplicate_call_id_produces_exactly_one_debit(tmp_path):
    guard = make_guard(tmp_path, spend_cap=SpendCap(window_amount=5.0))

    call = ToolCall(tool="pay", amount=1.0, call_id="idem-1")
    first = guard.reserve(call)
    second = guard.reserve(ToolCall(tool="pay", amount=1.0, call_id="idem-1"))

    assert first.decision is Decision.ALLOW
    assert second.decision is Decision.ALLOW
    # Reserved once, not twice.
    assert guard.window_spend() == pytest.approx(1.0)

    entries = guard.audit_log.read_all()
    assert any(e.rule == "reservation.duplicate_call_id" for e in entries)


def test_duplicate_call_id_after_release_is_also_refused(tmp_path):
    """call_id is a one-shot idempotency key. A genuine retry after a
    release must mint a new call_id - reusing the failed one is treated
    as a duplicate, not a fresh attempt.
    """
    guard = make_guard(tmp_path, spend_cap=SpendCap(window_amount=5.0))

    call = ToolCall(tool="pay", amount=1.0, call_id="idem-2")
    result = guard.reserve(call)
    guard.release(result.call.call_id, reason="payment failed")

    retry_with_same_id = guard.reserve(ToolCall(tool="pay", amount=1.0, call_id="idem-2"))

    entries = guard.audit_log.read_all()
    assert entries[-1].rule == "reservation.duplicate_call_id"
    assert guard.window_spend() == pytest.approx(0.0)
    assert retry_with_same_id.decision is Decision.ALLOW  # echoes the original decision

    # A genuinely new attempt with a new call_id works normally.
    fresh = guard.reserve(ToolCall(tool="pay", amount=1.0, call_id="idem-2-retry"))
    assert fresh.allowed
    assert guard.window_spend() == pytest.approx(1.0)


# -- 4. failure after reservation ---------------------------------------------


def test_release_after_failure_restores_budget_and_rate_slot(tmp_path):
    guard = make_guard(
        tmp_path,
        spend_cap=SpendCap(window_amount=5.0),
        rate_limit=RateLimit(max_calls=1, window_seconds=60),
    )

    call = ToolCall(tool="pay", amount=2.0, call_id="fail-1")
    result = guard.reserve(call)
    assert guard.window_spend() == pytest.approx(2.0)
    assert guard.window_calls() == 1
    # The rate limit is fully held - a second reservation is blocked.
    assert guard.reserve(ToolCall(tool="pay", amount=0.1, call_id="fail-1-blocked")).blocked

    guard.release(result.call.call_id, reason="payment errored before settlement")

    assert guard.window_spend() == pytest.approx(0.0)
    assert guard.window_calls() == 0
    assert guard.audit_log.read_all()[-1].rule == "reservation.released"

    # The freed budget and rate slot are usable again.
    retry = guard.reserve(ToolCall(tool="pay", amount=2.0, call_id="fail-1-retry"))
    assert retry.allowed


def test_release_on_unknown_call_id_raises(tmp_path):
    guard = make_guard(tmp_path)

    with pytest.raises(UnknownCallId):
        guard.release("never-reserved")


def test_unconfirmed_reservation_expires_and_frees_budget(tmp_path):
    guard = make_guard(tmp_path, spend_cap=SpendCap(window_amount=1.0, window_seconds=3600))
    t0 = utcnow()

    first = ToolCall(tool="pay", amount=0.9, call_id="ttl-1", timestamp=t0)
    assert guard.reserve(first, ttl_seconds=1.0).allowed

    # Too soon - the first reservation has not expired yet, so there is
    # not enough remaining budget for a second one.
    too_soon = ToolCall(tool="pay", amount=0.9, call_id="ttl-2-too-soon", timestamp=t0 + timedelta(milliseconds=1))
    assert guard.reserve(too_soon).blocked

    # Past the TTL - reserving anything sweeps the expired reservation
    # first, and its budget is available again.
    after_ttl = ToolCall(tool="pay", amount=0.9, call_id="ttl-3-after", timestamp=t0 + timedelta(seconds=2))
    assert guard.reserve(after_ttl).allowed

    entries = guard.audit_log.read_all()
    assert any(e.call_id == "ttl-1" and e.rule == "reservation.expired" for e in entries)


# -- 5. settlement mismatch ----------------------------------------------------


def test_settlement_mismatch_is_logged_and_never_reports_success(tmp_path):
    guard = make_guard(tmp_path, spend_cap=SpendCap(window_amount=5.0))

    call = ToolCall(tool="pay", amount=1.0, recipient="acct_approved", call_id="settle-1")
    result = guard.reserve(call)
    guard.finalize(result.call.call_id)

    # The settlement landed somewhere other than what was approved.
    guard.reconcile(result.call.call_id, {"recipient": "acct_somewhere_else", "amount": 1.0})

    entry = guard.audit_log.read_all()[-1]
    assert entry.rule == "reconcile.mismatch"
    assert "acct_approved" in entry.reason
    assert "acct_somewhere_else" in entry.reason
    # Reconciliation never moves budget either way.
    assert guard.window_spend() == pytest.approx(1.0)


def test_finalize_then_reconcile_match_is_the_happy_path(tmp_path):
    guard = make_guard(tmp_path, spend_cap=SpendCap(window_amount=5.0))

    call = ToolCall(tool="pay", amount=1.0, recipient="acct_a", call_id="settle-2")
    result = guard.reserve(call)
    guard.finalize(result.call.call_id)
    guard.reconcile(result.call.call_id, {"recipient": "acct_a", "amount": 1.0})

    assert guard.audit_log.read_all()[-1].rule == "reconcile.match"
    assert guard.window_spend() == pytest.approx(1.0)
    # A finalized reservation cannot be finalized or released again.
    with pytest.raises(UnknownCallId):
        guard.finalize(result.call.call_id)
    with pytest.raises(UnknownCallId):
        guard.release(result.call.call_id)


def test_finalize_on_unknown_call_id_raises(tmp_path):
    guard = make_guard(tmp_path)

    with pytest.raises(UnknownCallId):
        guard.finalize("never-reserved")


# -- reservations survive a process restart -----------------------------------


def test_open_reservation_survives_a_new_guard_instance(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    policy = Policy(spend_cap=SpendCap(window_amount=5.0, window_seconds=3600))

    first = Guard(policy, log)
    result = first.reserve(ToolCall(tool="pay", amount=2.0, call_id="persist-1"))
    assert result.allowed

    second = Guard(policy, log)
    assert second.window_spend() == pytest.approx(2.0)

    # The reservation itself carried over, not just the spend - it can
    # still be finalized on the new instance.
    second.finalize("persist-1")
    assert second.audit_log.read_all()[-1].rule == "reservation.finalized"


def test_released_reservation_does_not_replay_as_spend_after_restart(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    policy = Policy(spend_cap=SpendCap(window_amount=5.0, window_seconds=3600))

    first = Guard(policy, log)
    result = first.reserve(ToolCall(tool="pay", amount=2.0, call_id="persist-2"))
    first.release(result.call.call_id, reason="failed before restart")

    second = Guard(policy, log)
    assert second.window_spend() == pytest.approx(0.0)

    # persist-2 already has a decision on record (now released) - it is
    # a duplicate, not a fresh reservation, even across the restart.
    retry = second.reserve(ToolCall(tool="pay", amount=2.0, call_id="persist-2"))
    assert second.audit_log.read_all()[-1].rule == "reservation.duplicate_call_id"
    assert second.window_spend() == pytest.approx(0.0)
