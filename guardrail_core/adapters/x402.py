"""
x402 adapter (scaffolding).

Maps an x402 (HTTP 402 micropayment) request onto a `ToolCall` so the
same policy engine that guards ordinary tool-calls also guards payments.

Status: this module has the mapping and the testnet guard, but is not
yet wired into the x402-spend-guard repo - that is a follow-up. It has
no dependency on the `x402` SDK: callers pass plain dicts (the decoded
X-PAYMENT-RESPONSE settlement), exactly as x402-spend-guard's
`SpendGuard.record_transaction(settle_response=...)` does today.

Recipient allowlisting uses the core `Allowlist` policy section. The
recipient of an x402 payment is the resource server's receiving address -
`payTo` in the 402 payment requirements - which `check_payment` takes as
`pay_to`.

`pay_to` is **required, with no default, by design**: money is moving, so
the allowlist must not be bypassable by omission. A caller who forgets it
gets a TypeError at the call site rather than a payment that silently
skipped the recipient check. Requests where no money moves and there is
no counterparty yet use `check_free_request` - an explicit opt-in, never
a default.

Note what is deliberately *not* mapped to `recipient`: the settlement
response's `payer` field. That is our own wallet, the sender. Treating
it as the recipient would make an allowlist compare our own address
against the list of counterparties we trust - it would pass whatever the
money actually went to. `payer` stays in the audit metadata only.

Usage sketch:

    adapter = X402Adapter(policy, audit_log="logs/x402-audit.jsonl")

    result = adapter.check_payment("/weather", 0.01, requirements["payTo"])
    if result.blocked:
        ...                      # never send the request, never pay
    response = session.get(url)  # official x402 SDK does the paying
    adapter.record_settlement(result, settle_dict)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..audit import AuditEntry, AuditLog, utcnow
from ..guard import Decision, Guard, GuardResult, ToolCall
from ..policy import Policy

__all__ = ["X402Adapter", "ALLOWED_TESTNET_NETWORKS"]

# Carried over from x402-spend-guard: testnet-only by design. A
# settlement on any other network is refused regardless of spend caps.
ALLOWED_TESTNET_NETWORKS = frozenset({"base-sepolia", "eip155:84532"})


class X402Adapter:
    """Guards x402 payments with a guardrail-core `Policy`."""

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        guard: Guard | None = None,
        audit_log: AuditLog | Path | str | None = None,
        allowed_networks: frozenset[str] | set[str] = ALLOWED_TESTNET_NETWORKS,
    ):
        if guard is None:
            if policy is None:
                raise ValueError("X402Adapter requires either a policy or a guard")
            guard = Guard(policy, audit_log)
        self.guard = guard
        self.allowed_networks = frozenset(allowed_networks)

    def check_payment(
        self,
        endpoint: str,
        amount_usdc: float,
        pay_to: str,
        *,
        metadata: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> GuardResult:
        """Pre-flight check, before the HTTP request or any signing.

        This is the important ordering property inherited from
        x402-spend-guard: a blocked payment is blocked *before* anything
        is sent on the wire.

        `pay_to` is the resource server's receiving address from the 402
        payment requirements. It is required and has no default, so the
        allowlist cannot be skipped by forgetting it - an omitted
        recipient is a TypeError here, not a silent bypass. For a
        request where no money moves, use `check_free_request`.
        """
        if not pay_to:
            # Guards against the empty-string spelling of the same
            # mistake, which a required parameter alone would not catch.
            raise ValueError(
                "pay_to is required for a priced x402 request; use "
                "check_free_request() for requests where no money moves"
            )

        call = ToolCall(
            # `pay_to` stays out of the scanned payload: it is an address
            # we are deliberately paying, and the crypto_wallet detector
            # would otherwise flag every x402 payment as a leaked wallet.
            payload={"endpoint": endpoint},
            tool=f"x402:{endpoint}",
            amount=amount_usdc,
            currency="USDC",
            recipient=pay_to,
            metadata={"protocol": "x402", "pay_to": pay_to, **(metadata or {})},
        )
        return self.guard.check(call, commit=commit)

    def check_free_request(
        self,
        endpoint: str,
        *,
        metadata: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> GuardResult:
        """Check a request where no money moves and there is no recipient.

        Use this for an unpriced probe of an x402 endpoint - the request
        that *discovers* the 402 payment requirements, before any
        counterparty is known. Rate-limit and PII rules still apply;
        spend and allowlist rules do not, because there is nothing to
        spend and nobody to pay yet.

        This exists as its own method rather than a default on
        `check_payment` so that skipping the allowlist is always a
        deliberate choice visible at the call site.
        """
        call = ToolCall(
            tool=f"x402:{endpoint}",
            payload={"endpoint": endpoint},
            metadata={"protocol": "x402", "free": True, **(metadata or {})},
        )
        return self.guard.check(call, commit=commit)

    def check_settlement(self, settle_response: dict[str, Any]) -> tuple[bool, str]:
        """Validate a settlement returned by the x402 facilitator.

        Returns `(ok, reason)`. Kept separate from the spend check
        because it runs after the payment, on data the facilitator
        produced.
        """
        network = settle_response.get("network")
        if network not in self.allowed_networks:
            return False, (
                f"network not allowed: {network!r} "
                f"(allowed: {sorted(self.allowed_networks)})"
            )
        if not settle_response.get("success", False):
            return False, "facilitator reported a failed settlement"
        return True, "settlement accepted"

    def record_settlement(
        self,
        result: GuardResult,
        settle_response: dict[str, Any],
    ) -> dict[str, Any]:
        """Append the on-chain outcome of an approved payment to the audit log."""
        ok, reason = self.check_settlement(settle_response)
        entry = AuditEntry(
            timestamp=utcnow(),
            call_id=result.call.call_id,
            tool=result.call.tool,
            decision=Decision.ALLOW.value if ok else Decision.BLOCK.value,
            reason=f"settlement: {reason}",
            policy=result.policy,
            rule="x402.settlement",
            amount=result.call.amount,
            currency=result.call.currency,
            recipient=result.call.recipient,
            metadata={
                "protocol": "x402",
                "network": settle_response.get("network"),
                "tx_hash": settle_response.get("transaction"),
                # The sender (our own wallet), not the recipient - see the
                # module docstring on why these must not be conflated.
                "payer": settle_response.get("payer"),
                "success": settle_response.get("success"),
            },
        )
        return self.guard.audit_log.append(entry)
