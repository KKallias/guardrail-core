"""CLI smoke tests - exit codes and output shape, no network."""

from __future__ import annotations

import json

import pytest

from guardrail_core.cli import EXIT_BLOCKED, EXIT_ERROR, EXIT_OK, main

POLICY_YAML = """
name: cli-demo
spend_cap:
  per_call: 1.0
  window_amount: 2.0
  window_seconds: 3600
pii_rules:
  detectors: [email]
  action: redact
"""


@pytest.fixture
def policy_file(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY_YAML, encoding="utf-8")
    return str(path)


def test_check_allows_and_exits_zero(policy_file, tmp_path, capsys):
    code = main(
        [
            "check",
            "--policy", policy_file,
            "--tool", "search",
            "--amount", "0.50",
            "--payload", '{"q": "weather"}',
            "--log", str(tmp_path / "audit.jsonl"),
        ]
    )

    assert code == EXIT_OK
    assert "ALLOW" in capsys.readouterr().out


def test_check_blocks_and_exits_one(policy_file, tmp_path, capsys):
    code = main(
        [
            "check",
            "--policy", policy_file,
            "--tool", "search",
            "--amount", "5.00",
            "--log", str(tmp_path / "audit.jsonl"),
        ]
    )

    assert code == EXIT_BLOCKED
    assert "BLOCK" in capsys.readouterr().out


def test_check_json_output_reports_redaction(policy_file, tmp_path, capsys):
    code = main(
        [
            "check",
            "--policy", policy_file,
            "--tool", "send",
            "--payload", '{"body": "ada@example.com"}',
            "--log", str(tmp_path / "audit.jsonl"),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == EXIT_OK
    assert payload["decision"] == "REDACT"
    assert payload["redacted_payload"]["body"] == "[REDACTED:email]"


def test_scan_reports_findings(capsys):
    code = main(["scan", "--text", "mail ada@example.com", "--json"])
    findings = json.loads(capsys.readouterr().out)

    assert code == EXIT_OK
    assert findings[0]["detector"] == "email"


def test_scan_fail_on_finding_exits_one(capsys):
    assert main(["scan", "--text", "ada@example.com", "--fail-on-finding"]) == EXIT_BLOCKED
    assert main(["scan", "--text", "nothing here", "--fail-on-finding"]) == EXIT_OK


def test_scan_redact_prints_clean_text(capsys):
    main(["scan", "--text", "mail ada@example.com", "--redact"])
    assert "[REDACTED:email]" in capsys.readouterr().out


def test_audit_tail_and_summary(policy_file, tmp_path, capsys):
    log = str(tmp_path / "audit.jsonl")
    main(["check", "--policy", policy_file, "--tool", "a", "--amount", "0.5", "--log", log])
    main(["check", "--policy", policy_file, "--tool", "b", "--amount", "9.0", "--log", log])
    capsys.readouterr()

    code = main(["audit", "--log", log, "--summary"])
    out = capsys.readouterr().out

    assert code == EXIT_OK
    assert "2 entries, 1 blocked" in out


def test_audit_filter_by_decision(policy_file, tmp_path, capsys):
    log = str(tmp_path / "audit.jsonl")
    main(["check", "--policy", policy_file, "--tool", "a", "--amount", "0.5", "--log", log])
    main(["check", "--policy", policy_file, "--tool", "b", "--amount", "9.0", "--log", log])
    capsys.readouterr()

    main(["audit", "--log", log, "--decision", "block", "--json"])
    entries = json.loads(capsys.readouterr().out)

    assert len(entries) == 1
    assert entries[0]["tool"] == "b"


def test_policy_command_validates(policy_file, capsys):
    assert main(["policy", "--policy", policy_file]) == EXIT_OK
    assert "cli-demo" in capsys.readouterr().out


def test_bad_policy_exits_two(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("spend_cap:\n  per_call: -5\n", encoding="utf-8")

    assert main(["policy", "--policy", str(bad)]) == EXIT_ERROR
