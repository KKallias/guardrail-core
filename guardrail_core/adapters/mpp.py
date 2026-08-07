"""
MPP (Machine Payments Protocol) adapter (scaffolding).

Maps an MPP Challenge - the 402 response describing price, recipient and
resource - onto a `ToolCall`, so MPP sessions are governed by the same
policy engine as everything else.

Status: mapping only, not yet wired into the mpp-spend-guard repo (that
project is JavaScript; this is the Python-side equivalent for agents
that speak MPP from Python). Transport-agnostic by design: it never
talks to a network, it only decides.

Amounts in MPP are minor units (cents / µUSD). Policies are written in
major units, so the adapter divides by `minor_units_per_major` (default
100) before checking - keeping "5.00" in the policy file meaning five
dollars, not five cents.

Recipient allowlisting is *not* done here: the challenge's `recipient`
is put on the `ToolCall` and the core `Allowlist` policy section
enforces it, so an MPP refusal carries the same rule name as any other.

    adapter = MppAdapter(policy)
    result = adapter.check_challenge({
        "amountMinor": 250, "recipient": "acct_x", "resource": "/report",
    })
    if result.blocked:
        ...  # do not authorize the payment
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..audit import AuditLog
from ..guard import Decision, Guard, GuardResult, ToolCall
from ..policy import Policy

__all__ = ["MppAdapter"]


class MppAdapter:
    """Guards MPP challenges with a guardrail-core `Policy`.

    To restrict which recipients may be paid, put them in the policy's
    `allowlist.recipients` - the adapter passes the challenge's
    `recipient` through to the guard, which enforces it.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        guard: Guard | None = None,
        audit_log: AuditLog | Path | str | None = None,
        minor_units_per_major: int = 100,
        currency: str = "USD",
    ):
        if guard is None:
            if policy is None:
                raise ValueError("MppAdapter requires either a policy or a guard")
            guard = Guard(policy, audit_log)
        self.guard = guard
        self.minor_units_per_major = minor_units_per_major
        self.currency = currency

    def to_call(self, challenge: dict[str, Any]) -> ToolCall:
        amount_minor = challenge.get("amountMinor")
        resource = challenge.get("resource") or "unknown"
        recipient = challenge.get("recipient")
        amount = (
            float(amount_minor) / self.minor_units_per_major
            if isinstance(amount_minor, (int, float))
            else None
        )
        return ToolCall(
            tool=f"mpp:{resource}",
            # The recipient is intentionally not in the scanned payload:
            # it is a counterparty we mean to pay, and an account id that
            # happens to look like a wallet address would otherwise trip
            # the crypto_wallet detector on every single challenge.
            payload={"resource": resource},
            amount=amount,
            currency=self.currency,
            recipient=recipient,
            metadata={
                "protocol": "mpp",
                "amount_minor": amount_minor,
                "recipient": recipient,
            },
        )

    def check_challenge(
        self,
        challenge: dict[str, Any],
        *,
        commit: bool = True,
    ) -> GuardResult:
        """Evaluate an MPP challenge before authorizing payment."""
        call = self.to_call(challenge)

        # A malformed price is a protocol-level problem, not a policy one -
        # the core rules have no meaningful verdict on `amountMinor: -5`.
        amount_minor = challenge.get("amountMinor")
        if not isinstance(amount_minor, (int, float)) or amount_minor < 0:
            return self._refuse(
                call, "mpp.invalid_amount", f"invalid amountMinor: {amount_minor!r}"
            )

        return self.guard.check(call, commit=commit)

    def _refuse(self, call: ToolCall, rule: str, reason: str) -> GuardResult:
        """Block on an MPP-specific rule, still writing one audit entry."""
        result = GuardResult(
            Decision.BLOCK, reason, call, self.guard.policy.name, rule=rule
        )
        self.guard.record_decision(result)
        return result
