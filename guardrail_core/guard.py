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

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from .audit import AuditEntry, AuditLog, utcnow
from .detectors import pii
from .policy import Policy


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"


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
    """The verdict for one `ToolCall`."""

    decision: Decision
    reason: str
    call: ToolCall
    policy: str | None = None
    rule: str | None = None
    findings: list[pii.Finding] = field(default_factory=list)
    redacted_payload: Any | None = None

    @property
    def allowed(self) -> bool:
        """True for ALLOW and REDACT - i.e. the call may proceed."""
        return self.decision is not Decision.BLOCK

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK

    @property
    def payload(self) -> Any:
        """The payload to actually send: redacted when redaction fired."""
        return self.redacted_payload if self.decision is Decision.REDACT else self.call.payload

    def raise_if_blocked(self) -> "GuardResult":
        if self.blocked:
            raise BlockedByPolicy(self)
        return self


class Guard:
    """Evaluates tool-calls against a `Policy` and records every decision.

    Spend and rate-limit state is rolling-window based and is rebuilt
    from the audit log on construction, so limits survive process
    restarts (an agent script that runs once per cron tick still shares
    one budget).
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

        if load_history:
            self._load_history()

    # -- history ---------------------------------------------------------

    def _load_history(self) -> None:
        """Rebuild rolling-window state from previously allowed calls.

        Blocked calls are skipped: a refused call neither spent money nor
        consumed the rate-limit budget.
        """
        for entry in self.audit_log.iter_entries():
            if entry.decision == Decision.BLOCK.value:
                continue
            self._call_events.append(entry.timestamp)
            if entry.amount:
                self._spend_events.append((entry.timestamp, entry.amount))

    # -- introspection ---------------------------------------------------

    def window_spend(self, now: datetime | None = None) -> float:
        """Total committed spend inside the spend cap's rolling window."""
        cap = self.policy.spend_cap
        if cap is None or cap.window_amount is None:
            return sum(amount for _, amount in self._spend_events)
        now = now or utcnow()
        start = now - timedelta(seconds=cap.window_seconds)
        return sum(amount for ts, amount in self._spend_events if ts >= start)

    def window_calls(self, now: datetime | None = None) -> int:
        """Number of committed calls inside the rate limit's window."""
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
        `commit=False` for a dry run - a pre-flight "would this be
        allowed?" - and call `Guard.commit(call)` yourself once the call
        actually happens.
        """
        result = self._evaluate(call)
        self._write_audit(result)
        if commit and result.allowed:
            self.commit(call)
        return result

    def commit(self, call: ToolCall) -> None:
        """Record that `call` actually consumed budget."""
        self._call_events.append(call.timestamp)
        if call.amount:
            self._spend_events.append((call.timestamp, call.amount))

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

    def record_decision(self, result: GuardResult) -> dict[str, Any]:
        """Write an audit entry for a decision made outside `check`.

        Adapters with protocol-specific rules (an MPP recipient
        allowlist, an x402 settlement outcome) use this so their
        refusals land in the same log as everything else.
        """
        return self._write_audit(result)

    def _write_audit(self, result: GuardResult) -> dict[str, Any]:
        call = result.call
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
            findings=[f.to_dict() for f in result.findings],
            payload=result.redacted_payload,
            metadata=call.metadata,
        )
        return self.audit_log.append(entry)
