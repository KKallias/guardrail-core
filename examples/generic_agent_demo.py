#!/usr/bin/env python3
"""
examples/generic_agent_demo.py

A minimal "agent" whose paid tool is wrapped in @guarded. It runs the
same call in a loop until guardrail-core refuses it - the $5 rolling
spend cap is hit on the fifth call - then prints the audit log.

Nothing here touches the network: the tool is a stub that returns a
string. The point is the enforcement path, which is identical whether
the tool below is a stub, an x402 payment, or an LLM API call.

    python examples/generic_agent_demo.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardrail_core import AuditLog, BlockedByPolicy, Policy  # noqa: E402
from guardrail_core.adapters.generic import guarded  # noqa: E402
from guardrail_core.policy import PiiRules, RateLimit, SpendCap  # noqa: E402

PRICE_PER_CALL = 1.25
SPEND_CAP = 5.00

# A fresh log per run so the demo is reproducible. In a real agent this
# would be a stable path - that persistence is what makes the cap hold
# across separate runs of the same script.
AUDIT_PATH = Path(tempfile.gettempdir()) / "guardrail-demo-audit.jsonl"
AUDIT_PATH.unlink(missing_ok=True)

policy = Policy(
    name="demo-agent",
    spend_cap=SpendCap(per_call=2.00, window_amount=SPEND_CAP, window_seconds=3600),
    rate_limit=RateLimit(max_calls=20, window_seconds=60),
    pii_rules=PiiRules(detectors=("email", "api_key", "crypto_wallet", "card_number")),
)

audit_log = AuditLog(AUDIT_PATH)


@guarded(policy, audit_log=audit_log, amount=PRICE_PER_CALL, tool="market_data_api")
def fetch_market_data(symbol: str, note: str = "") -> str:
    """A paid tool: pretend this costs $1.25 per call."""
    return f"{symbol}: 42.00 USD"


def main() -> int:
    print(f"Policy: max ${SPEND_CAP:.2f} per hour, ${PRICE_PER_CALL:.2f} per call")
    print(f"Audit log: {AUDIT_PATH}\n")

    guard = fetch_market_data.guard

    for attempt in range(1, 7):
        try:
            result = fetch_market_data("AAPL")
        except BlockedByPolicy as exc:
            print(f"call {attempt}: BLOCKED - {exc.reason}")
            break
        spent = guard.window_spend()
        print(
            f"call {attempt}: ok  -> {result}   "
            f"(spent ${spent:.2f} / ${SPEND_CAP:.2f})"
        )

    # The same guard also strips sensitive data from tool arguments.
    # This call is under a fresh budget only because it is free - the
    # spend cap above is already exhausted, so use a second guard.
    print("\nPII redaction on tool arguments:")
    redaction_demo()

    print(f"\nAudit log ({AUDIT_PATH}):")
    for entry in audit_log.read_all():
        line = entry.to_dict()
        print("  " + json.dumps(line, default=str))

    entries = audit_log.read_all()
    blocked = [e for e in entries if e.decision == "BLOCK"]
    print(
        f"\n{len(entries)} decisions recorded, {len(blocked)} blocked, "
        f"${guard.window_spend():.2f} of ${SPEND_CAP:.2f} spent."
    )
    return 0


def redaction_demo() -> None:
    """A free tool under the same policy: PII rules still apply."""

    @guarded(
        Policy(name="demo-agent", pii_rules=policy.pii_rules),
        audit_log=audit_log,
        tool="send_report",
    )
    def send_report(body: str) -> str:
        # Whatever arrives here has already been through the guard.
        return body

    sent = send_report(
        "contact ada@example.com, key sk-abcdef0123456789ABCD, "
        "wallet 0x1234567890abcdef1234567890abcdef12345678"
    )
    print(f"  tool received: {sent}")


if __name__ == "__main__":
    raise SystemExit(main())
