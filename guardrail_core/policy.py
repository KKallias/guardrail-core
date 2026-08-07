"""
Policy definitions for guardrail-core.

A `Policy` is a plain, serializable description of what an agent is
allowed to do: how much it may spend, how often it may call tools, and
what kinds of sensitive data may leave the process. It contains no
enforcement logic - `guard.Guard` interprets it.

Policies can be built in code or loaded from YAML:

    policy = Policy.from_yaml("policy.yaml")

    # policy.yaml
    name: default
    spend_cap:
      per_call: 1.00
      window_amount: 5.00
      window_seconds: 3600
      currency: USD
    rate_limit:
      max_calls: 10
      window_seconds: 60
    pii_rules:
      detectors: [email, api_key, crypto_wallet, card_number]
      action: redact        # redact | block
      fields: null          # null = scan every payload field
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Kept as a module-level constant so the CLI and README can quote the same
# list the detectors module actually implements.
DEFAULT_DETECTORS = ("email", "api_key", "crypto_wallet", "card_number")

PII_ACTIONS = ("redact", "block")


class PolicyError(ValueError):
    """Raised when a policy is structurally invalid (bad YAML, bad values)."""


@dataclass(frozen=True)
class SpendCap:
    """Spend limits, in the policy's currency.

    Two independent limits, either of which may be omitted (None = no cap):

    - `per_call`: the largest single charge allowed.
    - `window_amount` over `window_seconds`: a rolling-window total, the
      generalization of x402-spend-guard's `spend_limit_usdc` /
      `window_hours` and mpp-spend-guard's `sessionCapMinor`.

    Amounts are compared with `>`, so a call that lands exactly on the cap
    is allowed - the cap is the maximum permitted total, not the first
    forbidden one.
    """

    per_call: float | None = None
    window_amount: float | None = None
    window_seconds: float = 3600.0
    currency: str = "USD"

    def __post_init__(self) -> None:
        for name in ("per_call", "window_amount"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise PolicyError(f"spend_cap.{name} must be >= 0, got {value!r}")
        if self.window_seconds <= 0:
            raise PolicyError(
                f"spend_cap.window_seconds must be > 0, got {self.window_seconds!r}"
            )


@dataclass(frozen=True)
class RateLimit:
    """At most `max_calls` guarded calls per rolling `window_seconds`."""

    max_calls: int
    window_seconds: float = 60.0

    def __post_init__(self) -> None:
        if self.max_calls < 0:
            raise PolicyError(f"rate_limit.max_calls must be >= 0, got {self.max_calls!r}")
        if self.window_seconds <= 0:
            raise PolicyError(
                f"rate_limit.window_seconds must be > 0, got {self.window_seconds!r}"
            )


@dataclass(frozen=True)
class PiiRules:
    """Which detectors run, and what a match means.

    `action="redact"` replaces matches in the payload and lets the call
    through; `action="block"` refuses it. `fields=None` scans the whole
    payload; a list restricts scanning to those top-level keys.
    """

    detectors: tuple[str, ...] = DEFAULT_DETECTORS
    action: str = "redact"
    fields: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if self.action not in PII_ACTIONS:
            raise PolicyError(
                f"pii_rules.action must be one of {PII_ACTIONS}, got {self.action!r}"
            )
        # Detector names are validated lazily by detectors.pii so that a
        # policy file can be loaded by tooling that has no detector registry.


@dataclass(frozen=True)
class Allowlist:
    """Who a call may be directed at.

    `recipients` is the set of counterparty identifiers a call may name -
    an MPP account id, an x402 `pay_to` address, an API vendor. An empty
    tuple means "no restriction", so an allowlist section that exists but
    is empty is a no-op rather than a deny-all: a policy file that
    accidentally loses its entries should not silently block every call.
    Use `pii_rules`/`spend_cap` to refuse, not an empty allowlist.

    A call with `recipient=None` skips this rule entirely - most tool
    calls have no counterparty, and they should not all need one.
    """

    recipients: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for entry in self.recipients:
            if not isinstance(entry, str):
                raise PolicyError(
                    f"allowlist.recipients entries must be strings, got "
                    f"{type(entry).__name__}: {entry!r}"
                )

    def permits(self, recipient: str | None) -> bool:
        """True when `recipient` is acceptable under this allowlist."""
        if not self.recipients or recipient is None:
            return True
        return recipient in self.recipients


@dataclass(frozen=True)
class Policy:
    """A complete guardrail policy. Every section is optional."""

    name: str = "default"
    allowlist: Allowlist | None = None
    spend_cap: SpendCap | None = None
    rate_limit: RateLimit | None = None
    pii_rules: PiiRules | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- construction ----------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        if not isinstance(data, dict):
            raise PolicyError(f"policy must be a mapping, got {type(data).__name__}")

        unknown = set(data) - {
            "name",
            "allowlist",
            "spend_cap",
            "rate_limit",
            "pii_rules",
            "metadata",
        }
        if unknown:
            raise PolicyError(f"unknown policy keys: {sorted(unknown)}")

        allowlist = data.get("allowlist")
        spend_cap = data.get("spend_cap")
        rate_limit = data.get("rate_limit")
        pii_rules = data.get("pii_rules")

        try:
            return cls(
                name=data.get("name", "default"),
                allowlist=_allowlist_from_dict(allowlist) if allowlist else None,
                spend_cap=SpendCap(**spend_cap) if spend_cap else None,
                rate_limit=RateLimit(**rate_limit) if rate_limit else None,
                pii_rules=_pii_rules_from_dict(pii_rules) if pii_rules else None,
                metadata=data.get("metadata") or {},
            )
        except TypeError as exc:
            # e.g. an unexpected or missing key inside a policy section.
            raise PolicyError(f"invalid policy: {exc}") from exc

    @classmethod
    def from_yaml(cls, path: Path | str) -> "Policy":
        """Load a policy from a YAML file."""
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise PolicyError(
                "PyYAML is required to load policies from YAML: pip install pyyaml"
            ) from exc

        path = Path(path)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise PolicyError(f"could not parse {path}: {exc}") from exc

        if data is None:
            raise PolicyError(f"{path} is empty")
        try:
            return cls.from_dict(data)
        except PolicyError as exc:
            raise PolicyError(f"invalid policy in {path}: {exc}") from exc

    # -- serialization ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        allowlist = data.get("allowlist")
        if allowlist is not None:
            # Tuples would serialize to YAML/JSON as something unloadable.
            allowlist["recipients"] = list(allowlist["recipients"])
        pii = data.get("pii_rules")
        if pii:
            pii["detectors"] = list(pii["detectors"])
            if pii["fields"] is not None:
                pii["fields"] = list(pii["fields"])
        return {k: v for k, v in data.items() if v not in (None, {})}


def _allowlist_from_dict(data: dict[str, Any]) -> Allowlist:
    if not isinstance(data, dict):
        raise PolicyError(f"allowlist must be a mapping, got {type(data).__name__}")
    unknown = set(data) - {"recipients"}
    if unknown:
        raise PolicyError(f"unknown allowlist keys: {sorted(unknown)}")

    recipients = data.get("recipients") or ()
    if isinstance(recipients, str) or not isinstance(recipients, (list, tuple)):
        # A bare string is the likely YAML slip ("recipients: acct_a"); it
        # would otherwise be accepted as a tuple of single characters.
        raise PolicyError(
            f"allowlist.recipients must be a list, got {type(recipients).__name__}"
        )
    return Allowlist(recipients=tuple(recipients))


def _pii_rules_from_dict(data: dict[str, Any]) -> PiiRules:
    detectors = data.get("detectors", DEFAULT_DETECTORS)
    fields_ = data.get("fields")
    return PiiRules(
        detectors=tuple(detectors),
        action=data.get("action", "redact"),
        fields=tuple(fields_) if fields_ else None,
    )
