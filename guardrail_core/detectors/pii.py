"""
Regex-based PII / secret detectors.

Every detector returns `Finding` objects carrying the match *positions*,
so the caller can redact precisely rather than re-running the regex. All
detection is local: no network calls, no model inference.

These are deliberately conservative pattern matchers, not a
classification system. They catch the leaks that actually show up in
agent tool-calls - a user's email pasted into a search query, an API key
echoed into a prompt, a wallet address, a card number - and they will
miss creative obfuscation. Treat a clean result as "no obvious leak",
never as "provably safe".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

REDACTION_PLACEHOLDER = "[REDACTED:{detector}]"


@dataclass(frozen=True)
class Finding:
    """One detector hit inside a single string.

    `start`/`end` are indices into the scanned string, so
    `text[finding.start:finding.end] == finding.value`.
    `path` is set when the string came from a structured payload
    (e.g. `"args.query"`); it is None for a bare string scan.
    """

    detector: str
    value: str
    start: int
    end: int
    path: str | None = None

    def masked(self) -> str:
        """The matched value with all but the last 4 characters hidden.

        Used in audit entries: enough to recognize *which* secret leaked
        without writing the secret itself into the log.
        """
        if len(self.value) <= 4:
            return "*" * len(self.value)
        return "*" * (len(self.value) - 4) + self.value[-4:]

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "path": self.path,
            "start": self.start,
            "end": self.end,
            "masked": self.masked(),
        }


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Vendor-prefixed key formats. Prefix-anchored on purpose: a generic
# "long random string" rule produces far too many false positives on
# ordinary agent payloads (hashes, ids, base64 blobs).
API_KEY_RE = re.compile(
    r"""(?x)
    \b(?:
        sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{16,}   # OpenAI / Anthropic / Stripe-style
      | pk-[A-Za-z0-9_-]{16,}
      | rk_(?:live|test)_[A-Za-z0-9]{16,}                  # Stripe restricted
      | AKIA[0-9A-Z]{16}                                   # AWS access key id
      | ASIA[0-9A-Z]{16}                                   # AWS temporary key id
      | gh[pousr]_[A-Za-z0-9]{20,}                         # GitHub tokens
      | github_pat_[A-Za-z0-9_]{20,}
      | xox[baprs]-[A-Za-z0-9-]{10,}                       # Slack
      | AIza[0-9A-Za-z_-]{35}                              # Google API key
      | glpat-[A-Za-z0-9_-]{20,}                           # GitLab
      | hf_[A-Za-z0-9]{20,}                                # Hugging Face
    )\b
    """
)

# EVM-style address: exactly 40 hex chars after 0x. The trailing lookahead
# stops a 64-char private key or tx hash from matching as an address.
CRYPTO_WALLET_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b(?![a-fA-F0-9])")

# Card-like: 13-19 digits, optionally grouped by spaces or hyphens.
# Luhn is applied afterwards - the regex alone matches far too much.
CARD_CANDIDATE_RE = re.compile(r"(?<![\dxX])(?:\d[ -]?){12,18}\d(?![\d-])")


def luhn_ok(digits: str) -> bool:
    """Standard Luhn (mod-10) checksum over a digits-only string."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    # Double every second digit counting from the right.
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------


def _regex_detector(name: str, pattern: re.Pattern[str]):
    def detect(text: str, path: str | None = None) -> list[Finding]:
        return [
            Finding(name, m.group(0), m.start(), m.end(), path)
            for m in pattern.finditer(text)
        ]

    detect.__name__ = f"detect_{name}"
    return detect


detect_email = _regex_detector("email", EMAIL_RE)
detect_api_key = _regex_detector("api_key", API_KEY_RE)
detect_crypto_wallet = _regex_detector("crypto_wallet", CRYPTO_WALLET_RE)


def detect_card_number(text: str, path: str | None = None) -> list[Finding]:
    """Card-like numbers that pass a Luhn check.

    The Luhn gate is what keeps this usable: without it, any order id or
    phone number would trip the detector.
    """
    findings: list[Finding] = []
    for match in CARD_CANDIDATE_RE.finditer(text):
        raw = match.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if luhn_ok(digits):
            findings.append(Finding("card_number", raw, match.start(), match.end(), path))
    return findings


DETECTORS: dict[str, Callable[..., list[Finding]]] = {
    "email": detect_email,
    "api_key": detect_api_key,
    "crypto_wallet": detect_crypto_wallet,
    "card_number": detect_card_number,
}


class UnknownDetector(KeyError):
    """Raised when a policy names a detector that is not registered."""


def resolve_detectors(names: Iterable[str]) -> list[Callable[..., list[Finding]]]:
    resolved = []
    for name in names:
        if name not in DETECTORS:
            raise UnknownDetector(
                f"unknown detector {name!r}; available: {sorted(DETECTORS)}"
            )
        resolved.append(DETECTORS[name])
    return resolved


# --------------------------------------------------------------------------
# Scanning and redaction
# --------------------------------------------------------------------------


def scan_text(
    text: str,
    detectors: Iterable[str] | None = None,
    path: str | None = None,
) -> list[Finding]:
    """Run the named detectors over one string, sorted by position."""
    names = list(detectors) if detectors is not None else list(DETECTORS)
    findings: list[Finding] = []
    for detect in resolve_detectors(names):
        findings.extend(detect(text, path))
    return sorted(findings, key=lambda f: (f.start, f.detector))


def scan_payload(
    payload: Any,
    detectors: Iterable[str] | None = None,
    fields: Iterable[str] | None = None,
) -> list[Finding]:
    """Walk a nested payload (dict/list/str) and collect all findings.

    `fields`, when given, restricts scanning to those top-level keys of a
    dict payload - useful when only one argument of a tool-call can
    plausibly carry user data.
    """
    allowed = set(fields) if fields else None
    findings: list[Finding] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, str):
            findings.extend(scan_text(node, detectors, path or None))
        elif isinstance(node, dict):
            for key, value in node.items():
                child = f"{path}.{key}" if path else str(key)
                if allowed is not None and not path and key not in allowed:
                    continue
                walk(value, child)
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")
        # Numbers, bools and None cannot carry a regex match - skip them.
        # A card number stored as an int is out of scope by design: JSON
        # payloads from agents carry these as strings.

    walk(payload, "")
    return findings


def redact_text(text: str, findings: Iterable[Finding]) -> str:
    """Replace each finding's span with a placeholder naming the detector.

    Replacement runs right-to-left so earlier offsets stay valid.
    """
    result = text
    for finding in sorted(findings, key=lambda f: f.start, reverse=True):
        placeholder = REDACTION_PLACEHOLDER.format(detector=finding.detector)
        result = result[: finding.start] + placeholder + result[finding.end :]
    return result


def redact_payload(
    payload: Any,
    detectors: Iterable[str] | None = None,
    fields: Iterable[str] | None = None,
) -> Any:
    """Return a redacted deep copy of `payload`; the original is untouched."""
    allowed = set(fields) if fields else None

    def walk(node: Any, depth: int, key: str | None = None) -> Any:
        if isinstance(node, str):
            return redact_text(node, scan_text(node, detectors))
        if isinstance(node, dict):
            return {
                k: (
                    v
                    if allowed is not None and depth == 0 and k not in allowed
                    else walk(v, depth + 1, k)
                )
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [walk(v, depth + 1) for v in node]
        if isinstance(node, tuple):
            return tuple(walk(v, depth + 1) for v in node)
        return node

    return walk(payload, 0)
