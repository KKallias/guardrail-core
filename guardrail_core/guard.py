"""
The enforcement point: `Guard.check(call) -> GuardResult`.

Everything in guardrail-core funnels through here. Adapters (x402, MPP,
LangChain, the `@guarded` decorator) exist only to turn some framework's
notion of "a tool is about to run" into a `ToolCall`, hand it to
`Guard.check`, and honour the returned `GuardResult`.

Check order is fixed and cheapest-refusal-first:

    1. allowlist (who the call is directed at)
    2. spend cap, per call
    3. spend cap, rolling window
    4. rate limit
    5. PII / secret detectors

The first failing rule decides, so a call that is both over budget and
leaking a key is reported as over budget - it was never going to run.
The allowlist runs first because "this counterparty is not allowed at
all" is a more useful reason than "this call is too expensive".

Every check writes exactly one audit entry, including allowed ones.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from .audit import RECONCILE, AuditEntry, AuditLog, utcnow
from .detectors import pii
from .policy import Policy


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"


class UnknownCallId(KeyError):
    """Raised by `Guard.reconcile` when no decision matches the call_id.

    Loud on purpose: silently accepting a reconciliation for a call that
    was never decided would produce an audit trail that looks complete
    while describing something the guard never saw.
    """


def compute_digest(call: "ToolCall") -> str:
    """A stable sha256 over the operation a decision was made against.

    Covers exactly the fields that identify *which operation* was
    approved - tool, recipient, amount, currency, call_id, timestamp -
    and deliberately not the payload, which redaction rewrites.

    Serialization is canonical (sorted keys, no whitespace) so the same
    call produces the same digest across processes and Python versions.
    """
    canonical = json.dumps(
        {
            "tool": call.tool,
            "recipient": call.recipient,
            "amount": call.amount,
            "currency": call.currency,
            "call_id": call.call_id,
            "timestamp": call.timestamp.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _amounts_differ(left: float | None, right: float | None) -> bool:
    if left is None or right is None:
        return left is not right
    return not math.isclose(left, right, rel_tol=1e-9, abs_tol=1e-9)


class BlockedByPolicy(Exception):
    """Raised by adapters when a guarded call is refused.

    Carries the full `GuardResult` so callers can inspect which rule
    fired without parsing the message.
    """

    def __init__(self, result: "GuardResult"):
        super().__init__(result.reason)
        self.result = result

    @property
    def reason(self) -> str:
        return self.result.reason


@dataclass
class ToolCall:
    """A tool invocation about to happen.

    `amount` is the charge this call would incur, in the policy's
    currency - None for a call that costs nothing (spend rules are then
    skipped, rate limit and PII rules still apply).

    `recipient` is the counterparty the call is directed at - an MPP
    account id, an x402 `pay_to` address, an API vendor. None means the
    call has no counterparty, and the allowlist rule is skipped.
    """

    tool: str
    payload: Any = field(default_factory=dict)
    amount: float | None = None
    currency: str | None = None
    recipient: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    call_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = field(default_factory=utcnow)


@dataclass
class GuardResult:
    """The verdict for one `ToolCall`.

    `digest` is set for ALLOW and REDACT and is None for BLOCK - there is
    no approved operation to bind a digest to when the call is refused.
    """

    decision: Decision
    reason: str
    call: ToolCall
    policy: str | None = None
    rule: str | None = None
    findings: list[pii.Finding] = field(default_factory=list)
    redacted_payload: Any | None = None
    digest: str | None = None

    def __post_init__(self) -> None:
        if self.digest is None and self.decision is not Decision.BLOCK:
            self.digest = compute_digest(self.call)

    def matches(self, call: ToolCall) -> bool:
        """Does `call` still describe the operation this decision approved?

        Call this immediately before executing, passing the call object
        you are about to act on. It catches drift between `check()` and
        execution - an amount recomputed, a recipient re-resolved, a
        retry that rebuilt the call - where the thing being run is no
        longer the thing that was approved.

        This is a consistency check against accident, not a security
        control: code that can change the operation can also skip this.
        """
        if self.digest is None:
            return False
        return compute_digest(call) == self.digest

    @property
    def allowed(self) -> bool:
        """True for ALLOW and REDACT - i.e. the call may proceed.

        Only ALLOW, BLOCK and REDACT can ever reach here: RECONCILE is an
        audit-log decision type written after the fact and never appears
        on a `GuardResult`, so branching on this stays exhaustive. To
        find reconciliation outcomes, read the audit log and check
        `rule` for `reconcile.match` / `reconcile.mismatch`.
        """
        return self.decision is not Decision.BLOCK

    @property
    def blocked(self) -> bool:
        """True for BLOCK only - see `allowed` on why RECONCILE is absent."""
        return self.decision is Decision.BLOCK

    @property
    def payload(self) -> Any:
        """The payload to actually send: redacted when redaction fired."""
        return self.redacted_payload if self.decision is Decision.REDACT else self.call.payload

    def raise_if_blocked(self) -> "GuardResult":
        if self.blocked:
            raise BlockedByPolicy(self)
        return self


#: Default hold time for an unconfirmed reservation before `reserve`
#: sweeps and releases it automatically. Long enough for a slow
#: settlement, short enough that an abandoned call does not tie up
#: budget indefinitely.
DEFAULT_RESERVATION_TTL = 300.0


@dataclass
class _Reservation:
    """An open, unconfirmed hold on budget and rate-limit, taken by
    `Guard.reserve` and resolved by `Guard.finalize` or `Guard.release`
    (including the automatic release of a reservation past its TTL).
    """

    call: ToolCall
    result: GuardResult
    expires_at: datetime
    spend_event: tuple[datetime, float] | None
    call_event: datetime | None


class Guard:
    """Evaluates tool-calls against a `Policy` and records every decision.

    Spend and rate-limit state is rolling-window based and is rebuilt
    from the audit log on construction, so limits survive process
    restarts (an agent script that runs once per cron tick still shares
    one budget). Any reservation still open (see `reserve`) when the log
    was last written is rebuilt too, so it can still expire or be
    released after a restart.
    """

    def __init__(
        self,
        policy: Policy,
        audit_log: AuditLog | Path | str | None = None,
        *,
        load_history: bool = True,
    ):
        self.policy = policy
        if isinstance(audit_log, AuditLog):
            self.audit_log = audit_log
        else:
            self.audit_log = AuditLog(audit_log)

        # (timestamp, amount) for committed spend; timestamps for committed calls.
        self._spend_events: list[tuple[datetime, float]] = []
        self._call_events: list[datetime] = []

        # Guards every read and mutation of the two lists above, plus
        # `_reservations`, so `check`/`reserve`/`commit`/`finalize`/
        # `release` are each atomic even under concurrent threads. RLock
        # because `check` and `reserve` call other locking methods
        # (`commit`, `_release_locked`) on the same thread while already
        # holding it.
        self._lock = threading.RLock()

        # Open reservations taken by `reserve`, keyed by call_id, not yet
        # resolved by `finalize` or `release`.
        self._reservations: dict[str, _Reservation] = {}

        if load_history:
            self._load_history()

    # -- history ---------------------------------------------------------

    #: Only these decisions represent budget actually consumed. A BLOCK
    #: spent nothing, and a RECONCILE describes a call already counted
    #: from its original ALLOW - replaying it would double-count the
    #: spend on every process restart.
    REPLAYED_DECISIONS = frozenset({Decision.ALLOW.value, Decision.REDACT.value})

    #: Rules written to the log by `release`/`_sweep_expired` for a
    #: reservation that was given back. A call_id marked with either
    #: never actually held its budget, so history replay must skip it.
    _RESERVATION_GIVEN_BACK = frozenset({"reservation.released", "reservation.expired"})

    def _load_history(self) -> None:
        """Rebuild rolling-window state, and any still-open reservations,
        from the audit log.

        Two passes: the first finds which call_ids had a reservation
        that was later released/expired (skip their spend entirely) or
        finalized (spend stays, but it is no longer an open reservation);
        the second replays spend/rate history and re-opens whatever
        reservation is still pending, exactly as `reserve` left it.
        """
        entries = list(self.audit_log.iter_entries())

        given_back: set[str] = set()
        finalized: set[str] = set()
        for entry in entries:
            if entry.decision != RECONCILE:
                continue
            if entry.rule in self._RESERVATION_GIVEN_BACK:
                given_back.add(entry.call_id)
            elif entry.rule == "reservation.finalized":
                finalized.add(entry.call_id)

        for entry in entries:
            if entry.decision not in self.REPLAYED_DECISIONS:
                continue
            if entry.call_id in given_back:
                continue  # released or expired - never actually spent

            self._call_events.append(entry.timestamp)
            spend_event = None
            if entry.amount:
                spend_event = (entry.timestamp, entry.amount)
                self._spend_events.append(spend_event)

            if entry.metadata.get("phase") == "reserved" and entry.call_id not in finalized:
                # Still open when the log was last written - rebuild the
                # reservation so it can still be finalized, released, or
                # swept once its TTL has passed.
                call = ToolCall(
                    tool=entry.tool,
                    amount=entry.amount,
                    currency=entry.currency,
                    recipient=entry.recipient,
                    call_id=entry.call_id,
                    timestamp=entry.timestamp,
                )
                result = GuardResult(
                    decision=Decision(entry.decision),
                    reason=entry.reason,
                    call=call,
                    policy=entry.policy,
                    rule=entry.rule,
                    digest=entry.digest,
                )
                ttl = entry.metadata.get("ttl_seconds", DEFAULT_RESERVATION_TTL)
                self._reservations[entry.call_id] = _Reservation(
                    call=call,
                    result=result,
                    expires_at=entry.timestamp + timedelta(seconds=ttl),
                    spend_event=spend_event,
                    call_event=entry.timestamp,
                )

    # -- introspection ---------------------------------------------------

    def window_spend(self, now: datetime | None = None) -> float:
        """Total committed spend inside the spend cap's rolling window."""
        with self._lock:
            cap = self.policy.spend_cap
            if cap is None or cap.window_amount is None:
                return sum(amount for _, amount in self._spend_events)
            now = now or utcnow()
            start = now - timedelta(seconds=cap.window_seconds)
            return sum(amount for ts, amount in self._spend_events if ts >= start)

    def window_calls(self, now: datetime | None = None) -> int:
        """Number of committed calls inside the rate limit's window."""
        with self._lock:
            limit = self.policy.rate_limit
            if limit is None:
                return len(self._call_events)
            now = now or utcnow()
            start = now - timedelta(seconds=limit.window_seconds)
            return sum(1 for ts in self._call_events if ts >= start)

    def remaining_budget(self, now: datetime | None = None) -> float | None:
        cap = self.policy.spend_cap
        if cap is None or cap.window_amount is None:
            return None
        return max(0.0, cap.window_amount - self.window_spend(now))

    # -- the check --------------------------------------------------------

    def check(self, call: ToolCall, *, commit: bool = True) -> GuardResult:
        """Evaluate `call` and write an audit entry.

        With `commit=True` (the default) an allowed call immediately
        consumes its spend and rate-limit budget, which is what a
        wrapper that is about to execute the call wants. Pass
        `commit=False` for a dry run - a pure "would this be allowed?"
        with no side effects at all, not even a hold - and call
        `Guard.commit(call)` yourself once the call actually happens.

        `commit=False` does not reserve anything: two concurrent dry
        runs can both evaluate against the same unspent budget and then
        both go on to commit. For any flow where the call site decides
        now but pays later - the classic "check, then sign and send,
        then settle" shape - use `reserve`/`finalize`/`release` instead,
        which hold the budget atomically between the two.
        """
        with self._lock:
            result = self._evaluate(call)
            self._write_audit(result)
            if commit and result.allowed:
                self.commit(call)
        return result

    def commit(self, call: ToolCall) -> None:
        """Record that `call` actually consumed budget."""
        with self._lock:
            self._call_events.append(call.timestamp)
            if call.amount:
                self._spend_events.append((call.timestamp, call.amount))

    # -- two-phase reservations --------------------------------------------

    def reserve(self, call: ToolCall, *, ttl_seconds: float = DEFAULT_RESERVATION_TTL) -> GuardResult:
        """Atomically evaluate `call` and, if allowed, hold its budget
        and rate-limit slot until `finalize`, `release`, or expiry.

        This is the concurrency-safe replacement for the
        `check(commit=False)` + manual `commit()` split: that pattern
        evaluates without holding anything, so two calls racing for the
        same remaining budget can both pass the check and then both
        spend it. `reserve` closes that gap - the evaluation and the
        hold happen together under one lock, so a second `reserve`
        racing for the last unit of budget sees the first reservation
        already counted.

        Typical use (the x402/MPP "quote now, pay later" shape)::

            result = guard.reserve(call)
            if result.blocked:
                return  # never signs, never sends
            settlement = do_the_actual_payment(result.payload)
            if settlement.ok and result.matches(actual_call(settlement)):
                guard.finalize(call.call_id)
                guard.reconcile(call.call_id, {...})
            else:
                guard.release(call.call_id, reason="settlement mismatch or failure")

        A BLOCK result holds nothing, exactly like `check`. An ALLOW or
        REDACT result holds its budget until resolved; a reservation
        left unresolved for `ttl_seconds` is swept and released the next
        time `reserve` runs, logged as `reservation.expired`.

        `call.call_id` is a one-shot idempotency key. Calling `reserve`
        again with a call_id that already has *any* decision on record -
        pending, finalized, released, or expired - never reserves a
        second time: it is logged as `reservation.duplicate_call_id` and
        the original decision is returned unchanged, so a duplicate call
        (a retry that reused the same id instead of minting a new one)
        produces exactly one debit, not two. A genuine retry after a
        release or an expiry must use a new call_id.
        """
        with self._lock:
            self._sweep_expired(call.timestamp)

            existing = self.find_decision(call.call_id)
            if existing is not None:
                self.audit_log.append(
                    AuditEntry(
                        timestamp=utcnow(),
                        call_id=call.call_id,
                        tool=existing.tool,
                        decision=RECONCILE,
                        reason=(
                            f"duplicate call_id: a decision was already recorded for "
                            f"{call.call_id!r}, not reserving again"
                        ),
                        policy=existing.policy,
                        rule="reservation.duplicate_call_id",
                        amount=existing.amount,
                        currency=existing.currency,
                        recipient=existing.recipient,
                        digest=existing.digest,
                        metadata={"reconciles": call.call_id, "phase": "duplicate"},
                    )
                )
                return GuardResult(
                    decision=Decision(existing.decision),
                    reason=existing.reason,
                    call=call,
                    policy=existing.policy,
                    rule=existing.rule,
                    digest=existing.digest,
                )

            result = self._evaluate(call)
            self._write_audit(
                result, extra_metadata={"phase": "reserved", "ttl_seconds": ttl_seconds}
            )

            if result.allowed:
                spend_event = None
                if call.amount:
                    spend_event = (call.timestamp, call.amount)
                    self._spend_events.append(spend_event)
                call_event = call.timestamp
                self._call_events.append(call_event)
                self._reservations[call.call_id] = _Reservation(
                    call=call,
                    result=result,
                    expires_at=call.timestamp + timedelta(seconds=ttl_seconds),
                    spend_event=spend_event,
                    call_event=call_event,
                )
            return result

    def finalize(self, call_id: str) -> None:
        """Confirm a reservation actually happened.

        The budget was already held at `reserve` time; `finalize` only
        stops it from expiring and records the confirmation as
        `reservation.finalized`. Call `reconcile` separately (before or
        after) to record what the settlement actually was - `finalize`
        says "the call went ahead", `reconcile` says "and here is what
        it actually did".

        Raises `UnknownCallId` if `call_id` has no open reservation -
        already finalized, released, expired, or never reserved at all.
        """
        with self._lock:
            reservation = self._reservations.pop(call_id, None)
            if reservation is None:
                raise UnknownCallId(
                    f"no open reservation for call_id {call_id!r} in "
                    f"{self.audit_log.path} - nothing to finalize"
                )
            self.audit_log.append(
                AuditEntry(
                    timestamp=utcnow(),
                    call_id=call_id,
                    tool=reservation.call.tool,
                    decision=RECONCILE,
                    reason="reservation finalized: call executed as approved",
                    policy=reservation.result.policy,
                    rule="reservation.finalized",
                    amount=reservation.call.amount,
                    currency=reservation.call.currency,
                    recipient=reservation.call.recipient,
                    digest=reservation.result.digest,
                    metadata={"reconciles": call_id, "phase": "finalized"},
                )
            )

    def release(self, call_id: str, *, reason: str = "reservation released") -> None:
        """Give back a reservation's held budget and rate-limit slot.

        Use this on a definite failure - the payment errored, the
        counterparty rejected it, the challenge changed after preflight
        and the call site decided not to proceed. Raises `UnknownCallId`
        if `call_id` has no open reservation, the same loud-on-purpose
        behaviour as `reconcile` and `finalize`.
        """
        with self._lock:
            self._release_locked(call_id, reason=reason, rule="reservation.released")

    def _release_locked(self, call_id: str, *, reason: str, rule: str) -> None:
        """`release`'s body, callable while `self._lock` is already held
        (by `release` itself, or by `_sweep_expired` from inside `reserve`).
        """
        reservation = self._reservations.pop(call_id, None)
        if reservation is None:
            raise UnknownCallId(
                f"no open reservation for call_id {call_id!r} in "
                f"{self.audit_log.path} - nothing to release"
            )
        if reservation.spend_event is not None:
            try:
                self._spend_events.remove(reservation.spend_event)
            except ValueError:
                pass  # already gone somehow; releasing is still safe
        if reservation.call_event is not None:
            try:
                self._call_events.remove(reservation.call_event)
            except ValueError:
                pass
        self.audit_log.append(
            AuditEntry(
                timestamp=utcnow(),
                call_id=call_id,
                tool=reservation.call.tool,
                decision=RECONCILE,
                reason=reason,
                policy=reservation.result.policy,
                rule=rule,
                amount=reservation.call.amount,
                currency=reservation.call.currency,
                recipient=reservation.call.recipient,
                digest=reservation.result.digest,
                metadata={"reconciles": call_id, "phase": "released"},
            )
        )

    def _sweep_expired(self, now: datetime) -> None:
        """Release every reservation whose TTL has passed as of `now`.

        Called at the top of `reserve`, under the lock, so an abandoned
        reservation's budget comes back before it can block a later
        call that would otherwise fit.
        """
        expired_ids = [
            call_id
            for call_id, reservation in self._reservations.items()
            if reservation.expires_at <= now
        ]
        for call_id in expired_ids:
            self._release_locked(
                call_id,
                reason=f"reservation expired unconfirmed as of {now.isoformat()}",
                rule="reservation.expired",
            )

    def _evaluate(self, call: ToolCall) -> GuardResult:
        now = call.timestamp
        policy_name = self.policy.name

        allowlist = self.policy.allowlist
        if allowlist is not None and not allowlist.permits(call.recipient):
            return GuardResult(
                Decision.BLOCK,
                f"recipient not allowlisted: {call.recipient!r}",
                call,
                policy_name,
                rule="allowlist.recipient_not_allowed",
            )

        cap = self.policy.spend_cap
        if cap is not None and call.amount is not None:
            currency = call.currency or cap.currency
            if currency != cap.currency:
                return GuardResult(
                    Decision.BLOCK,
                    f"currency mismatch: call is in {currency}, "
                    f"policy caps are in {cap.currency}",
                    call,
                    policy_name,
                    rule="spend_cap.currency",
                )
            if cap.per_call is not None and call.amount > cap.per_call:
                return GuardResult(
                    Decision.BLOCK,
                    f"per-call spend cap exceeded: {call.amount:.4f} > "
                    f"{cap.per_call:.4f} {cap.currency}",
                    call,
                    policy_name,
                    rule="spend_cap.per_call",
                )
            if cap.window_amount is not None:
                projected = self.window_spend(now) + call.amount
                if projected > cap.window_amount:
                    return GuardResult(
                        Decision.BLOCK,
                        f"rolling spend cap exceeded: {projected:.4f} > "
                        f"{cap.window_amount:.4f} {cap.currency} "
                        f"in {cap.window_seconds:g}s window",
                        call,
                        policy_name,
                        rule="spend_cap.window",
                    )

        limit = self.policy.rate_limit
        if limit is not None:
            used = self.window_calls(now)
            if used >= limit.max_calls:
                return GuardResult(
                    Decision.BLOCK,
                    f"rate limit exceeded: {used} calls already made in the last "
                    f"{limit.window_seconds:g}s (max {limit.max_calls})",
                    call,
                    policy_name,
                    rule="rate_limit",
                )

        rules = self.policy.pii_rules
        if rules is not None:
            findings = pii.scan_payload(call.payload, rules.detectors, rules.fields)
            if findings:
                kinds = sorted({f.detector for f in findings})
                summary = f"{len(findings)} match(es): {', '.join(kinds)}"
                if rules.action == "block":
                    return GuardResult(
                        Decision.BLOCK,
                        f"sensitive data detected in payload - {summary}",
                        call,
                        policy_name,
                        rule="pii_rules.block",
                        findings=findings,
                    )
                return GuardResult(
                    Decision.REDACT,
                    f"sensitive data redacted from payload - {summary}",
                    call,
                    policy_name,
                    rule="pii_rules.redact",
                    findings=findings,
                    redacted_payload=pii.redact_payload(
                        call.payload, rules.detectors, rules.fields
                    ),
                )

        return GuardResult(Decision.ALLOW, "allowed by policy", call, policy_name)

    # -- reconciliation ---------------------------------------------------

    #: Keys in `actual` that reconcile compares against the original
    #: decision. Everything else is recorded as metadata.
    RECONCILE_KEYS = ("recipient", "amount", "currency")

    def find_decision(self, call_id: str) -> AuditEntry | None:
        """The original decision entry for `call_id`, or None.

        Skips reconciliation entries, so reconciling twice still compares
        against the decision rather than against the previous
        reconciliation.
        """
        for entry in self.audit_log.iter_entries():
            if entry.call_id == call_id and entry.decision != RECONCILE:
                return entry
        return None

    def reconcile(self, call_id: str, actual: dict[str, Any]) -> None:
        """Record what actually happened for a previously decided call.

        `actual` describes the real operation after the fact. Three keys
        are compared against the original decision - `recipient`,
        `amount`, `currency` - and any that diverge are flagged. The
        reserved key `ok=False` lets an adapter report a
        protocol-level failure (a settlement that never landed, a
        transfer the counterparty rejected) with an optional `reason`.
        Every other key is recorded as metadata.

        The result is a follow-up audit entry, never an edit: the
        original decision line stays exactly as written. Reconciliation
        entries are excluded from spend and rate-limit replay, so
        recording one never moves a budget.

        This is detection, not prevention. A reconciliation record cannot
        stop a call that diverged from its decision - it makes the
        divergence visible afterwards to anyone reading the log.

        Raises
        ------
        UnknownCallId
            If no decision was ever recorded for `call_id`.
        """
        original = self.find_decision(call_id)
        if original is None:
            raise UnknownCallId(
                f"no decision recorded for call_id {call_id!r} in "
                f"{self.audit_log.path} - nothing to reconcile against"
            )

        mismatches: list[str] = []

        if "recipient" in actual and actual["recipient"] != original.recipient:
            mismatches.append(
                f"recipient: decided {original.recipient!r}, "
                f"actual {actual['recipient']!r}"
            )
        if "amount" in actual and _amounts_differ(actual["amount"], original.amount):
            mismatches.append(
                f"amount: decided {original.amount!r}, actual {actual['amount']!r}"
            )
        if "currency" in actual and actual["currency"] != original.currency:
            mismatches.append(
                f"currency: decided {original.currency!r}, "
                f"actual {actual['currency']!r}"
            )
        if actual.get("ok") is False:
            mismatches.append(
                actual.get("reason") or "caller reported the operation did not succeed"
            )

        if mismatches:
            reason = "reconciliation mismatch - " + "; ".join(mismatches)
            rule = "reconcile.mismatch"
        else:
            reason = "reconciled: actual outcome matches the decision"
            rule = "reconcile.match"

        extras = {
            key: value
            for key, value in actual.items()
            if key not in self.RECONCILE_KEYS and key not in ("ok", "reason")
        }

        self.audit_log.append(
            AuditEntry(
                timestamp=utcnow(),
                call_id=call_id,
                tool=original.tool,
                decision=RECONCILE,
                reason=reason,
                policy=original.policy,
                rule=rule,
                amount=actual.get("amount", original.amount),
                currency=actual.get("currency", original.currency),
                recipient=actual.get("recipient", original.recipient),
                # The original digest, not a new one: this entry points at
                # the decision it reconciles rather than describing a new
                # approved operation.
                digest=original.digest,
                metadata={
                    "reconciles": call_id,
                    "original_decision": original.decision,
                    "original_timestamp": original.timestamp.isoformat(),
                    **extras,
                },
            )
        )

    def record_decision(self, result: GuardResult) -> dict[str, Any]:
        """Write an audit entry for a decision made outside `check`.

        Adapters with protocol-specific rules (an MPP recipient
        allowlist, an x402 settlement outcome) use this so their
        refusals land in the same log as everything else.
        """
        return self._write_audit(result)

    def _write_audit(
        self, result: GuardResult, *, extra_metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        call = result.call
        metadata = dict(call.metadata)
        if extra_metadata:
            metadata.update(extra_metadata)
        entry = AuditEntry(
            timestamp=call.timestamp,
            call_id=call.call_id,
            tool=call.tool,
            decision=result.decision.value,
            reason=result.reason,
            policy=result.policy,
            rule=result.rule,
            amount=call.amount,
            currency=call.currency
            or (self.policy.spend_cap.currency if self.policy.spend_cap else None),
            recipient=call.recipient,
            digest=result.digest,
            findings=[f.to_dict() for f in result.findings],
            payload=result.redacted_payload,
            metadata=metadata,
        )
        return self.audit_log.append(entry)
