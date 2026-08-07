"""Policy loading/validation and audit-log behaviour."""

from __future__ import annotations

import json

import pytest

from guardrail_core import Policy
from guardrail_core.audit import AuditEntry, AuditLog, utcnow
from guardrail_core.policy import PolicyError

POLICY_YAML = """
name: demo
allowlist:
  recipients:
    - acct_trusted
    - acct_partner
spend_cap:
  per_call: 1.0
  window_amount: 5.0
  window_seconds: 3600
  currency: USD
rate_limit:
  max_calls: 10
  window_seconds: 60
pii_rules:
  detectors: [email, api_key]
  action: redact
"""


# -- policy -----------------------------------------------------------------


def test_policy_loads_from_yaml(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY_YAML, encoding="utf-8")

    policy = Policy.from_yaml(path)

    assert policy.name == "demo"
    assert policy.spend_cap.per_call == 1.0
    assert policy.spend_cap.window_amount == 5.0
    assert policy.rate_limit.max_calls == 10
    assert policy.pii_rules.detectors == ("email", "api_key")
    assert policy.pii_rules.action == "redact"
    assert policy.allowlist.recipients == ("acct_trusted", "acct_partner")


def test_policy_sections_are_optional():
    policy = Policy.from_dict({"name": "minimal"})

    assert policy.allowlist is None
    assert policy.spend_cap is None
    assert policy.rate_limit is None
    assert policy.pii_rules is None


def test_allowlist_permits():
    allowlist = Policy.from_dict(
        {"allowlist": {"recipients": ["acct_a"]}}
    ).allowlist

    assert allowlist.permits("acct_a") is True
    assert allowlist.permits("acct_b") is False
    # No counterparty and no restriction both mean "not my business".
    assert allowlist.permits(None) is True

    empty = Policy.from_dict({"allowlist": {"recipients": []}}).allowlist
    assert empty.recipients == ()
    assert empty.permits("anyone") is True


def test_policy_roundtrips_through_dict(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY_YAML, encoding="utf-8")
    policy = Policy.from_yaml(path)

    assert Policy.from_dict(policy.to_dict()) == policy


@pytest.mark.parametrize(
    "data",
    [
        {"spend_cap": {"per_call": -1}},
        {"rate_limit": {"max_calls": 5, "window_seconds": 0}},
        {"pii_rules": {"action": "explode"}},
        {"spend_cap": {"nonsense_key": 1}},
        {"unexpected_section": {}},
        {"allowlist": {"recipients": [123]}},
        {"allowlist": {"recipients": ["ok", None]}},
        {"allowlist": {"recipients": "acct_a"}},  # bare string, not a list
        {"allowlist": {"nonsense_key": []}},
    ],
)
def test_invalid_policies_raise(data):
    with pytest.raises(PolicyError):
        Policy.from_dict(data)


def test_empty_yaml_raises(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")

    with pytest.raises(PolicyError):
        Policy.from_yaml(path)


# -- audit log --------------------------------------------------------------


def entry(**overrides) -> AuditEntry:
    defaults = dict(
        timestamp=utcnow(),
        call_id="abc123",
        tool="search",
        decision="ALLOW",
        reason="allowed by policy",
    )
    defaults.update(overrides)
    return AuditEntry(**defaults)


def test_audit_log_appends_one_json_line_per_entry(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")

    log.append(entry())
    log.append(entry(decision="BLOCK", reason="nope"))

    lines = log.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["decision"] == "BLOCK"


def test_audit_log_never_rewrites_existing_lines(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(entry(reason="first"))
    first_line = log.path.read_text(encoding="utf-8").splitlines()[0]

    log.append(entry(reason="second"))

    assert log.path.read_text(encoding="utf-8").splitlines()[0] == first_line


def test_audit_log_creates_missing_directories(tmp_path):
    log = AuditLog(tmp_path / "nested" / "deeper" / "audit.jsonl")

    log.append(entry())

    assert log.path.exists()


def test_audit_log_reads_back_entries(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(entry(amount=1.25, currency="USD"))

    read = log.read_all()

    assert len(read) == 1
    assert read[0].amount == 1.25
    assert read[0].currency == "USD"


def test_audit_log_skips_corrupted_lines(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(entry())
    # Simulate a process killed mid-write.
    with log.path.open("a", encoding="utf-8") as handle:
        handle.write('{"partial": tr\n')
    log.append(entry(reason="after the corruption"))

    read = log.read_all()

    assert len(read) == 2
    assert read[-1].reason == "after the corruption"


def test_audit_log_of_a_missing_file_is_empty(tmp_path):
    assert AuditLog(tmp_path / "nothing.jsonl").read_all() == []


def test_audit_tail(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for index in range(5):
        log.append(entry(reason=f"entry {index}"))

    assert [e.reason for e in log.tail(2)] == ["entry 3", "entry 4"]


def test_raw_payloads_are_not_written_to_the_log(tmp_path):
    """Only redacted payloads are ever persisted."""
    from guardrail_core import Guard, ToolCall
    from guardrail_core.policy import PiiRules

    log = AuditLog(tmp_path / "audit.jsonl")
    guard = Guard(Policy(pii_rules=PiiRules(detectors=("email",))), log)

    guard.check(ToolCall(tool="send", payload={"body": "ada@example.com"}))

    raw = log.path.read_text(encoding="utf-8")
    assert "ada@example.com" not in raw
    assert "[REDACTED:email]" in raw
