#!/usr/bin/env python3
"""
examples/unified_demo.py - the guardrail-core tour, in three sections.

Everything here is mocked: `ToolCall` objects and plain Python
functions, no network, no testnet, no wallet. That is deliberate - the
demo is deterministic and replayable, so a recording of it looks the
same every time.

    python examples/unified_demo.py
    python examples/unified_demo.py --step    # pause for a keypress

------------------------------------------------------------------------
SCREEN-RECORDING CAPTIONS
------------------------------------------------------------------------

Section 1 - Payment protocol: x402
    An agent is paying per API call under a $5/hour budget, and may only
    pay one approved address. The first three calls go through and the
    running total climbs. The fourth would break the budget and the
    fifth is aimed at an address nobody approved - both are stopped
    before any money moves.

Section 2 - Generic agent: PII redaction
    Any Python function can be wrapped with one decorator. Here the
    agent tries to send a message containing a customer's email and a
    live API key, buried in an ordinary sentence. The function still
    runs, but what it actually receives has the secrets stripped out -
    redaction changes the real payload, not just the log.

Section 3 - Audit trail
    Every decision, allowed or blocked, is appended to a JSONL log with
    the exact rule that fired. Namespaced rule names make the log
    answer "why" directly: spend_cap.window, allowlist.recipient_not_
    allowed, pii_rules.redact. This is the artifact you hand to an
    auditor.
------------------------------------------------------------------------
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardrail_core import AuditLog, Policy  # noqa: E402
from guardrail_core.adapters.generic import guarded  # noqa: E402
from guardrail_core.adapters.x402 import X402Adapter  # noqa: E402
from guardrail_core.policy import Allowlist, PiiRules, SpendCap  # noqa: E402

# The resource server we are willing to pay, and one we are not.
APPROVED_SERVER = "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3"
UNKNOWN_SERVER = "0xd1c4e9b7a2f60358e0b9a4c85173d2f9a6e07b41"

SPEND_CAP = 5.00
PRICE = 1.50

# A fresh log per run keeps the demo reproducible for recording.
AUDIT_PATH = Path(tempfile.gettempdir()) / "guardrail-unified-demo.jsonl"

STEP_MODE = "--step" in sys.argv


def section(title: str) -> None:
    """Print a section header, pausing first so the viewer can catch up."""
    print()
    if STEP_MODE:
        input("   [enter to continue]")
    else:
        time.sleep(1)
    print(f"=== {title} ===\n")


def money(value: float) -> str:
    return f"${value:,.2f}"


# ---------------------------------------------------------------------------
# 1. Payment protocol: x402
# ---------------------------------------------------------------------------


def demo_x402(audit_log: AuditLog) -> None:
    section("PAYMENT PROTOCOL: X402")

    policy = Policy(
        name="x402-agent",
        allowlist=Allowlist(recipients=(APPROVED_SERVER,)),
        spend_cap=SpendCap(
            per_call=2.00,
            window_amount=SPEND_CAP,
            window_seconds=3600,
            currency="USDC",
        ),
    )
    adapter = X402Adapter(policy, audit_log=audit_log)

    print(f"policy:    {money(SPEND_CAP)} per hour, one approved recipient")
    print(f"approved:  {APPROVED_SERVER}")
    print(f"price:     {money(PRICE)} per call\n")

    for attempt in range(1, 4):
        result = adapter.check_payment("/market-data", PRICE, APPROVED_SERVER)
        print(
            f"  call {attempt}  {result.decision.value:6}  "
            f"{money(PRICE)} -> approved server     "
            f"(total {money(adapter.guard.window_spend())} / {money(SPEND_CAP)})"
        )

    # Over budget: 4.50 already spent + 1.50 would be 6.00.
    over_budget = adapter.check_payment("/market-data", PRICE, APPROVED_SERVER)
    print(f"\n  call 4  {over_budget.decision.value:6}  {money(PRICE)} -> approved server")
    print(f"          rule:   {over_budget.rule}")
    print(f"          reason: {over_budget.reason}")

    # Within budget (0.25 fits under the 5.00 cap), but nobody approved
    # this address - the allowlist is checked before the spend rules.
    wrong_payee = adapter.check_payment("/market-data", 0.25, UNKNOWN_SERVER)
    print(f"\n  call 5  {wrong_payee.decision.value:6}  {money(0.25)} -> UNKNOWN server")
    print(f"          rule:   {wrong_payee.rule}")
    print(f"          reason: {wrong_payee.reason}")

    print("\n  No payment was ever sent - every block happened pre-flight.")


# ---------------------------------------------------------------------------
# 2. Generic agent: PII redaction
# ---------------------------------------------------------------------------


def demo_redaction(audit_log: AuditLog) -> None:
    section("GENERIC AGENT: PII REDACTION")

    policy = Policy(
        name="notification-agent",
        pii_rules=PiiRules(detectors=("email", "api_key", "crypto_wallet", "card_number")),
    )

    @guarded(policy, audit_log=audit_log)
    def send_notification(message: str) -> str:
        # This is the tool itself. Whatever it prints is what actually
        # arrived - not a sanitized copy made for the log.
        print(f"  function received: {message}")
        return message

    raw = (
        "Heads up: the customer ada.lovelace@example.com reported a failure, "
        "and I retried using key sk-proj-9fK2mZq7X1bTvE4dR8sLpN6c before it worked."
    )

    print("  agent tried to send:")
    print(f"  {raw}\n")
    send_notification(raw)
    print("\n  The email and the API key never left the process.")


# ---------------------------------------------------------------------------
# 3. Audit trail
# ---------------------------------------------------------------------------


def demo_audit(audit_log: AuditLog) -> None:
    section("AUDIT TRAIL")

    entries = audit_log.tail(5)
    print(f"  last {len(entries)} entries from {audit_log.path}\n")

    for entry in entries:
        # ALLOW entries have no rule - nothing fired, which is the point.
        rule = entry.rule or "(no rule fired)"
        stamp = entry.timestamp.strftime("%H:%M:%S")
        print(f"  [{stamp}]  {rule:34} -> {entry.decision}")

    blocked = sum(1 for e in audit_log.read_all() if e.decision == "BLOCK")
    print(
        f"\n  {len(audit_log.read_all())} decisions recorded, {blocked} blocked. "
        "Append-only JSONL, one line per decision."
    )


def main() -> int:
    AUDIT_PATH.unlink(missing_ok=True)
    audit_log = AuditLog(AUDIT_PATH)

    print("guardrail-core - spend caps, allowlists, PII redaction, audit log")
    print("(all calls are mocked; nothing touches a network)")

    demo_x402(audit_log)
    demo_redaction(audit_log)
    demo_audit(audit_log)

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
