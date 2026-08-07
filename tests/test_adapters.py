"""
Adapter tests: @guarded, the LangChain callback handler, and the x402 /
MPP mappings. Everything is local - the LangChain tests drive the
handler directly rather than running an agent, and no payment protocol
is contacted.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from guardrail_core import BlockedByPolicy, Decision, Policy
from guardrail_core.adapters.generic import guarded
from guardrail_core.adapters.langchain import GuardrailCallbackHandler
from guardrail_core.adapters.mpp import MppAdapter
from guardrail_core.adapters.x402 import X402Adapter
from guardrail_core.audit import AuditLog
from guardrail_core.policy import Allowlist, PiiRules, RateLimit, SpendCap


@pytest.fixture
def log(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


# -- @guarded ---------------------------------------------------------------


def test_guarded_allows_calls_under_the_cap(log):
    policy = Policy(spend_cap=SpendCap(window_amount=5.0, window_seconds=3600))

    @guarded(policy, audit_log=log, amount=1.0)
    def fetch(query: str) -> str:
        return f"result for {query}"

    assert fetch("weather") == "result for weather"
    assert fetch.guard.window_spend() == pytest.approx(1.0)


def test_guarded_raises_once_the_cap_is_exceeded(log):
    policy = Policy(spend_cap=SpendCap(window_amount=5.0, window_seconds=3600))
    calls = []

    @guarded(policy, audit_log=log, amount=2.0)
    def fetch(query: str) -> str:
        calls.append(query)
        return "ok"

    fetch("a")
    fetch("b")

    with pytest.raises(BlockedByPolicy) as excinfo:
        fetch("c")

    assert excinfo.value.result.rule == "spend_cap.window"
    # The wrapped function never ran for the blocked call.
    assert calls == ["a", "b"]


def test_guarded_reads_the_amount_from_an_argument(log):
    policy = Policy(spend_cap=SpendCap(per_call=1.0))

    @guarded(policy, audit_log=log, amount_arg="price")
    def buy(item: str, price: float) -> str:
        return item

    assert buy("cheap", 0.5) == "cheap"
    with pytest.raises(BlockedByPolicy):
        buy("expensive", 3.0)


def test_guarded_accepts_a_callable_amount(log):
    policy = Policy(spend_cap=SpendCap(per_call=1.0))

    @guarded(policy, audit_log=log, amount=lambda tokens: tokens * 0.001)
    def generate(tokens: int) -> int:
        return tokens

    assert generate(100) == 100
    with pytest.raises(BlockedByPolicy):
        generate(5000)


def test_guarded_rate_limit(log):
    policy = Policy(rate_limit=RateLimit(max_calls=2, window_seconds=60))

    @guarded(policy, audit_log=log)
    def ping() -> str:
        return "pong"

    ping()
    ping()
    with pytest.raises(BlockedByPolicy) as excinfo:
        ping()
    assert excinfo.value.result.rule == "rate_limit"


def test_guarded_passes_redacted_arguments_to_the_function(log):
    policy = Policy(pii_rules=PiiRules(detectors=("email",)))
    seen = {}

    @guarded(policy, audit_log=log)
    def send(message: str) -> str:
        seen["message"] = message
        return message

    send("ping ada@example.com")

    assert "ada@example.com" not in seen["message"]
    assert "[REDACTED:email]" in seen["message"]


def test_guarded_can_leave_arguments_alone(log):
    policy = Policy(pii_rules=PiiRules(detectors=("email",)))
    seen = {}

    @guarded(policy, audit_log=log, apply_redaction=False)
    def send(message: str) -> str:
        seen["message"] = message
        return message

    send("ping ada@example.com")

    # Audit-only mode: the decision is recorded, the payload is not changed.
    assert seen["message"] == "ping ada@example.com"
    assert log.read_all()[-1].decision == Decision.REDACT.value


def test_guarded_functions_can_share_one_budget(log):
    policy = Policy(spend_cap=SpendCap(window_amount=1.0, window_seconds=3600))

    @guarded(policy, audit_log=log, amount=0.6)
    def first() -> str:
        return "first"

    @guarded(guard=first.guard, amount=0.6)
    def second() -> str:
        return "second"

    first()
    with pytest.raises(BlockedByPolicy):
        second()


def test_guarded_wraps_async_functions(log):
    policy = Policy(spend_cap=SpendCap(per_call=1.0))

    @guarded(policy, audit_log=log, amount=5.0)
    async def fetch() -> str:
        return "never reached"

    with pytest.raises(BlockedByPolicy):
        asyncio.run(fetch())


def test_guarded_preserves_function_metadata(log):
    @guarded(Policy(), audit_log=log)
    def documented(x: int) -> int:
        """Docstring survives."""
        return x

    assert documented.__name__ == "documented"
    assert documented.__doc__ == "Docstring survives."


def test_guarded_requires_a_policy_or_guard():
    with pytest.raises(ValueError):
        guarded()


# -- LangChain handler ------------------------------------------------------


def test_langchain_handler_allows_a_clean_tool_start(log):
    handler = GuardrailCallbackHandler(
        Policy(rate_limit=RateLimit(max_calls=5, window_seconds=60)), audit_log=log
    )
    run_id = uuid4()

    handler.on_tool_start({"name": "search"}, "weather today", run_id=run_id)

    assert handler.results[str(run_id)].decision is Decision.ALLOW


def test_langchain_handler_blocks_on_rate_limit(log):
    handler = GuardrailCallbackHandler(
        Policy(rate_limit=RateLimit(max_calls=1, window_seconds=60)), audit_log=log
    )

    handler.on_tool_start({"name": "search"}, "first")

    with pytest.raises(BlockedByPolicy):
        handler.on_tool_start({"name": "search"}, "second")


def test_langchain_handler_blocks_on_spend_cap(log):
    handler = GuardrailCallbackHandler(
        Policy(spend_cap=SpendCap(per_call=0.10)),
        audit_log=log,
        amount_for=lambda tool, text, kwargs: 1.00,
    )

    with pytest.raises(BlockedByPolicy) as excinfo:
        handler.on_tool_start({"name": "premium"}, "query")

    assert excinfo.value.result.rule == "spend_cap.per_call"


def run_tool_like_langchain(handler, tool, tool_input: str, name: str = "send"):
    """Mimic LangChain's order: callbacks fire, then the tool runs.

    A callback exception propagates out of the run, so a raising
    `on_tool_start` means the tool body never executes.
    """
    handler.on_tool_start({"name": name}, tool_input)
    return tool(tool_input)


def test_langchain_redact_blocks_tool_execution_by_default(log):
    """A handler cannot rewrite tool input, so REDACT must fail closed."""
    executed = []
    handler = GuardrailCallbackHandler(
        Policy(pii_rules=PiiRules(detectors=("email",))), audit_log=log
    )

    with pytest.raises(BlockedByPolicy) as excinfo:
        run_tool_like_langchain(handler, executed.append, "mail ada@example.com")

    # The decision is a REDACT that the handler escalated to a refusal.
    assert excinfo.value.result.decision is Decision.REDACT
    assert executed == []
    assert log.read_all()[-1].decision == Decision.REDACT.value


def test_langchain_redact_as_block_opt_out_records_but_does_not_block(log):
    executed = []
    handler = GuardrailCallbackHandler(
        Policy(pii_rules=PiiRules(detectors=("email",))),
        audit_log=log,
        redact_as_block=False,
    )
    run_id = uuid4()

    handler.on_tool_start({"name": "send"}, "mail ada@example.com", run_id=run_id)
    executed.append("ran")

    result = handler.results[str(run_id)]
    assert result.decision is Decision.REDACT
    assert "[REDACTED:email]" in result.redacted_payload["input"]
    # Recorded, not enforced - the tool still ran.
    assert executed == ["ran"]
    assert log.read_all()[-1].decision == Decision.REDACT.value


def test_langchain_opt_out_leaves_the_raw_payload_reaching_the_tool(log):
    """The sharp edge the docstring warns about, pinned down by a test.

    With the opt-out, the audit log says REDACT but the tool receives the
    original text - which is why @guarded on the tool is then required.
    """
    received = []
    handler = GuardrailCallbackHandler(
        Policy(pii_rules=PiiRules(detectors=("email",))),
        audit_log=log,
        redact_as_block=False,
    )

    run_tool_like_langchain(handler, received.append, "mail ada@example.com")

    assert received == ["mail ada@example.com"]


# -- x402 / MPP mappings ----------------------------------------------------

# A resource server's receiving address (`payTo` in the 402 payment
# requirements) - the recipient of an x402 payment.
SERVER = "0x" + "ab12" * 10


def test_x402_adapter_blocks_over_budget_payment(log):
    adapter = X402Adapter(
        Policy(spend_cap=SpendCap(window_amount=0.015, window_seconds=86400, currency="USDC")),
        audit_log=log,
    )

    assert adapter.check_payment("/weather", 0.01, SERVER).allowed
    result = adapter.check_payment("/weather", 0.01, SERVER)

    assert result.decision is Decision.BLOCK
    assert result.rule == "spend_cap.window"


def test_x402_pay_to_is_enforced_by_the_core_allowlist(log):
    other = "0x" + "cd34" * 10
    adapter = X402Adapter(
        Policy(allowlist=Allowlist(recipients=(SERVER,))), audit_log=log
    )

    assert adapter.check_payment("/weather", 0.01, SERVER).allowed

    blocked = adapter.check_payment("/weather", 0.01, other)
    assert blocked.rule == "allowlist.recipient_not_allowed"


def test_x402_pay_to_is_not_scanned_as_a_leaked_wallet(log):
    """The address we are paying is not a wallet leak."""
    adapter = X402Adapter(Policy(pii_rules=PiiRules()), audit_log=log)

    result = adapter.check_payment("/weather", 0.01, SERVER)

    assert result.decision is Decision.ALLOW


def test_priced_payment_without_pay_to_raises_immediately(log):
    """The allowlist must not be bypassable by forgetting the recipient."""
    adapter = X402Adapter(
        Policy(allowlist=Allowlist(recipients=("0xsomething",))), audit_log=log
    )

    with pytest.raises(TypeError):
        adapter.check_payment("/weather", 0.01)  # type: ignore[call-arg]

    # The empty-string spelling of the same mistake is caught too.
    with pytest.raises(ValueError):
        adapter.check_payment("/weather", 0.01, "")

    # Nothing was evaluated, so nothing reached the audit log.
    assert log.read_all() == []


def test_free_request_is_an_explicit_opt_out_of_the_allowlist(log):
    adapter = X402Adapter(
        Policy(
            allowlist=Allowlist(recipients=("0xsomething",)),
            spend_cap=SpendCap(per_call=0.001, currency="USDC"),
        ),
        audit_log=log,
    )

    result = adapter.check_free_request("/weather")

    assert result.decision is Decision.ALLOW
    assert result.call.recipient is None
    assert result.call.amount is None
    assert log.read_all()[-1].metadata["free"] is True


def test_free_request_still_enforces_rate_and_pii_rules(log):
    adapter = X402Adapter(
        Policy(rate_limit=RateLimit(max_calls=1, window_seconds=60)), audit_log=log
    )

    assert adapter.check_free_request("/weather").allowed
    assert adapter.check_free_request("/weather").rule == "rate_limit"


def test_x402_payer_is_not_treated_as_the_recipient(log):
    """`payer` is our own wallet; conflating it with the recipient would
    make the allowlist check the sender against the trusted list."""
    adapter = X402Adapter(
        Policy(allowlist=Allowlist(recipients=(SERVER,))), audit_log=log
    )
    result = adapter.check_payment("/weather", 0.01, SERVER)

    adapter.record_settlement(
        result,
        {
            "success": True,
            "network": "base-sepolia",
            "transaction": "0xdeadbeef",
            "payer": "0x" + "ff99" * 10,  # our wallet, not on the allowlist
        },
    )

    last = log.read_all()[-1]
    assert last.recipient == SERVER
    assert last.metadata["payer"] != last.recipient
    assert last.decision == Decision.ALLOW.value


def test_x402_adapter_rejects_non_testnet_settlement(log):
    adapter = X402Adapter(Policy(), audit_log=log)

    ok, reason = adapter.check_settlement(
        {"success": True, "network": "base", "transaction": "0xabc"}
    )

    assert ok is False
    assert "not allowed" in reason


def test_x402_adapter_accepts_testnet_settlement_and_logs_it(log):
    adapter = X402Adapter(Policy(), audit_log=log)
    result = adapter.check_payment("/weather", 0.01, SERVER)

    adapter.record_settlement(
        result,
        {
            "success": True,
            "network": "base-sepolia",
            "transaction": "0xdeadbeef",
            "payer": "0x1234",
        },
    )

    last = log.read_all()[-1]
    assert last.rule == "x402.settlement"
    assert last.decision == Decision.ALLOW.value
    assert last.metadata["tx_hash"] == "0xdeadbeef"


def test_mpp_adapter_converts_minor_units(log):
    adapter = MppAdapter(
        Policy(spend_cap=SpendCap(per_call=2.00)), audit_log=log
    )

    allowed = adapter.check_challenge({"amountMinor": 150, "resource": "/report"})
    blocked = adapter.check_challenge({"amountMinor": 500, "resource": "/report"})

    assert allowed.decision is Decision.ALLOW
    assert allowed.call.amount == pytest.approx(1.50)
    assert blocked.decision is Decision.BLOCK


def test_mpp_adapter_delegates_recipient_checks_to_the_core_allowlist(log):
    adapter = MppAdapter(
        Policy(allowlist=Allowlist(recipients=("acct_trusted",))), audit_log=log
    )

    allowed = adapter.check_challenge(
        {"amountMinor": 10, "recipient": "acct_trusted", "resource": "/x"}
    )
    blocked = adapter.check_challenge(
        {"amountMinor": 10, "recipient": "acct_unknown", "resource": "/x"}
    )

    assert allowed.decision is Decision.ALLOW
    assert blocked.decision is Decision.BLOCK
    # The core rule name, not an MPP-local one.
    assert blocked.rule == "allowlist.recipient_not_allowed"
    assert log.read_all()[-1].recipient == "acct_unknown"


def test_mpp_recipient_is_not_scanned_as_payload(log):
    """A wallet-shaped recipient must not read as a leaked wallet."""
    adapter = MppAdapter(Policy(pii_rules=PiiRules()), audit_log=log)

    result = adapter.check_challenge(
        {
            "amountMinor": 10,
            "recipient": "0x1234567890abcdef1234567890abcdef12345678",
            "resource": "/x",
        }
    )

    assert result.decision is Decision.ALLOW


def test_mpp_adapter_rejects_invalid_amount(log):
    adapter = MppAdapter(Policy(), audit_log=log)

    result = adapter.check_challenge({"amountMinor": -5, "resource": "/x"})

    assert result.rule == "mpp.invalid_amount"
