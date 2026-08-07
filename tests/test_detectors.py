"""
Detector tests.

The fake secrets here are syntactically valid but not real credentials -
they exist so the regexes are exercised against realistic shapes.
"""

from __future__ import annotations

import pytest

from guardrail_core.detectors import pii

# A well-known Visa *test* number - published by payment providers
# precisely so test suites can use it. Passes Luhn, is not a real card.
TEST_CARD = "4242424242424242"


def kinds(findings):
    return {f.detector for f in findings}


# -- email ------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "write to ada@example.com please",
        "ada.lovelace+tag@sub.example.co.uk",
        "<grace@example.org>",
    ],
)
def test_email_detected(text):
    assert "email" in kinds(pii.scan_text(text, ["email"]))


def test_email_not_detected_in_plain_text():
    assert pii.scan_text("no address here @ all", ["email"]) == []


# -- api keys ---------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "sk-abcdefghij0123456789",
        "sk-proj-abcdefghij0123456789ABCDEF",
        "sk-ant-api03abcdefghij0123456789",
        "AKIAIOSFODNN7EXAMPLE",
        "ASIAIOSFODNN7EXAMPLE",
        "ghp_abcdefghij0123456789abcdefghij",
        "github_pat_abcdefghij0123456789abcd",
        "xoxb-1234567890-abcdefghij",
        "AIzaSyA1234567890abcdefghij1234567890ab",  # AIza + exactly 35 chars
        "glpat-abcdefghij0123456789",
        "hf_abcdefghij0123456789abcd",
    ],
)
def test_api_key_formats_detected(secret):
    findings = pii.scan_text(f"the key is {secret} ok", ["api_key"])
    assert kinds(findings) == {"api_key"}
    assert findings[0].value == secret


def test_api_key_not_detected_in_ordinary_words():
    assert pii.scan_text("sk-short and a plain sentence", ["api_key"]) == []


def test_masked_shows_only_the_last_four():
    finding = pii.scan_text("AKIAIOSFODNN7EXAMPLE", ["api_key"])[0]
    masked = finding.masked()
    assert masked.endswith("MPLE")
    assert "AKIA" not in masked


# -- crypto wallet ----------------------------------------------------------


def test_evm_address_detected():
    address = "0x" + "ab12" * 10  # 40 hex chars
    findings = pii.scan_text(f"pay {address} now", ["crypto_wallet"])
    assert [f.value for f in findings] == [address]


def test_private_key_length_hex_is_not_an_address():
    # 64 hex chars - a private key or tx hash, not a wallet address.
    assert pii.scan_text("0x" + "ab" * 32, ["crypto_wallet"]) == []


# -- card numbers / Luhn ----------------------------------------------------


def test_luhn_accepts_valid_and_rejects_invalid():
    assert pii.luhn_ok(TEST_CARD) is True
    assert pii.luhn_ok("4242424242424241") is False
    assert pii.luhn_ok("123") is False
    assert pii.luhn_ok("not-a-number") is False


@pytest.mark.parametrize(
    "text", [TEST_CARD, "4242 4242 4242 4242", "4242-4242-4242-4242"]
)
def test_card_number_detected_with_separators(text):
    findings = pii.scan_text(f"card: {text}", ["card_number"])
    assert kinds(findings) == {"card_number"}


def test_luhn_failing_digits_are_not_flagged():
    # An order id that happens to be 16 digits must not trip the detector.
    assert pii.scan_text("order 1234567890123456", ["card_number"]) == []


# -- positions and redaction ------------------------------------------------


def test_findings_carry_usable_positions():
    text = "mail ada@example.com now"
    finding = pii.scan_text(text, ["email"])[0]
    assert text[finding.start : finding.end] == finding.value == "ada@example.com"


def test_redact_text_replaces_every_match():
    text = f"ada@example.com paid with {TEST_CARD}"
    findings = pii.scan_text(text)
    redacted = pii.redact_text(text, findings)

    assert "ada@example.com" not in redacted
    assert TEST_CARD not in redacted
    assert "[REDACTED:email]" in redacted
    assert "[REDACTED:card_number]" in redacted


def test_redact_text_handles_multiple_matches_in_order():
    text = "a@x.com and b@y.com"
    redacted = pii.redact_text(text, pii.scan_text(text, ["email"]))
    assert redacted == "[REDACTED:email] and [REDACTED:email]"


# -- structured payloads ----------------------------------------------------


def test_scan_payload_walks_nested_structures():
    payload = {
        "user": {"email": "ada@example.com"},
        "items": ["clean", {"note": "AKIAIOSFODNN7EXAMPLE"}],
        "count": 3,
    }
    findings = pii.scan_payload(payload)
    paths = {f.path for f in findings}

    assert kinds(findings) == {"email", "api_key"}
    assert "user.email" in paths
    assert "items[1].note" in paths


def test_scan_payload_respects_the_fields_filter():
    payload = {"query": "ada@example.com", "internal": "grace@example.com"}

    findings = pii.scan_payload(payload, fields=["query"])

    assert [f.path for f in findings] == ["query"]


def test_redact_payload_leaves_the_original_untouched():
    payload = {"prompt": "ada@example.com", "n": 1}

    redacted = pii.redact_payload(payload)

    assert redacted["prompt"] == "[REDACTED:email]"
    assert redacted["n"] == 1
    assert payload["prompt"] == "ada@example.com"


def test_unknown_detector_raises():
    with pytest.raises(pii.UnknownDetector):
        pii.scan_text("x", ["not_a_detector"])
