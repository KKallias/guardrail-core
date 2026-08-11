"""
Short-lived, scoped credential minting.

Every guarded adapter in this package answers "should this call run?".
None of them answer a related but different question: when the call is
allowed to run, what secret does it authenticate with, and does the
agent ever get to see that secret directly?

The common pattern in production agent setups today is redaction --
hide the real key from the model's context, mask it in logs, strip it
from prompts. That protects against the key leaking into a transcript,
but the process still holds one long-lived, unscoped secret for the
entire session: anything that can make the process issue a request can
use it, for as long as the process runs.

`CredentialBroker` mints a different kind of thing: an opaque,
random token with its own expiry and use-count, handed to the *tool
call*, never to the model's context. The real secret is exchanged for
that token only at the moment an approved outbound call is actually
made -- by your adapter or egress proxy, not by anything the model can
reach -- and the token stops working after its TTL or use budget is
spent, whichever comes first. A leaked token is worth at most a few
calls to one service for a few minutes; a leaked long-lived key is
worth everything it was scoped to, indefinitely.

    secrets = {"stripe": os.environ["STRIPE_SECRET_KEY"]}
    broker = CredentialBroker(secrets, audit_log="logs/guardrail-audit.jsonl")

    cred = broker.mint(Scope(service="stripe", ttl_seconds=60, max_uses=1))
    # cred.token is what the agent / tool call carries around.
    # broker.resolve(cred.token) is called by the code that makes the
    # actual HTTP request -- never by anything the model can invoke.
    api_key = broker.resolve(cred.token)

This is not a replacement for `Guard` -- pair the two. A typical flow is
`Guard.check()` decides whether a call may happen at all; if it can,
`CredentialBroker.mint()` produces the one-shot credential that call
uses, scoped tighter than the session's real key ever needs to be.

Sharing the audit log's `AuditLog` with a `Guard` puts every mint /
resolve / revoke / expiry in the same append-only trail as every policy
decision, in call-id order, without a second log file to correlate.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from .audit import AuditEntry, AuditLog, utcnow

__all__ = [
    "CredentialBroker",
    "CredentialError",
    "CredentialExhausted",
    "CredentialExpired",
    "CredentialNotFound",
    "IssuedCredential",
    "Scope",
]


class CredentialError(Exception):
    """Base class for credential broker errors."""


class CredentialNotFound(CredentialError):
    """No base secret is registered for a service, or a token is unknown/revoked."""


class CredentialExpired(CredentialError):
    """The token's TTL has elapsed."""


class CredentialExhausted(CredentialError):
    """The token's use budget has been spent."""


@dataclass(frozen=True)
class Scope:
    """What a minted credential is allowed to be used for.

    `permissions` is not enforced by the broker itself -- it has no way
    to know what a given API key can actually do upstream. It is
    recorded in the audit trail and is there for your own code (or a
    reviewer reading the log) to check a mint request against what the
    calling code claims it needs.
    """

    service: str
    ttl_seconds: float = 300.0
    max_uses: int | None = 1
    permissions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.service:
            raise ValueError("Scope.service must be non-empty")
        if self.ttl_seconds <= 0:
            raise ValueError(f"Scope.ttl_seconds must be > 0, got {self.ttl_seconds!r}")
        if self.max_uses is not None and self.max_uses <= 0:
            raise ValueError(f"Scope.max_uses must be > 0 or None, got {self.max_uses!r}")


@dataclass
class IssuedCredential:
    """A minted, opaque handle. `token` is safe to log and to hand to a
    tool call; it is not the underlying secret and cannot be turned back
    into one except by the broker that issued it."""

    token: str
    service: str
    issued_at: datetime
    expires_at: datetime
    max_uses: int | None
    uses_remaining: int | None
    permissions: tuple[str, ...] = field(default_factory=tuple)

    def expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at

    def exhausted(self) -> bool:
        return self.uses_remaining is not None and self.uses_remaining <= 0


class CredentialBroker:
    """Mints and resolves short-lived, scoped, limited-use credentials.

    Parameters
    ----------
    secrets:
        Either a `{service_name: secret_value}` mapping, or a callable
        `(service_name) -> secret_value` for looking a secret up lazily
        (an OS keychain, a secrets manager, `keyring.get_password`).
        Base secrets are never written to the audit log, never returned
        by `mint`, and only ever leave the broker through `resolve`.
    audit_log:
        An `AuditLog`, a path, or None (defaults to
        `logs/guardrail-audit.jsonl`, same as `Guard`). Pass the same
        `AuditLog` instance a `Guard` in the same process uses to keep
        mints and policy decisions in one trail.
    """

    def __init__(
        self,
        secrets: dict[str, str] | Callable[[str], str],
        *,
        audit_log: AuditLog | Path | str | None = None,
    ) -> None:
        if callable(secrets):
            self._lookup = secrets
        else:
            store = dict(secrets)
            self._lookup = _dict_lookup(store)

        self.audit_log = audit_log if isinstance(audit_log, AuditLog) else AuditLog(audit_log)
        self._issued: dict[str, IssuedCredential] = {}
        self._lock = threading.Lock()

    # -- minting -----------------------------------------------------

    def mint(self, scope: Scope) -> IssuedCredential:
        """Issue a new credential for `scope`.

        Raises `CredentialNotFound` immediately -- before minting
        anything -- if no base secret is registered for
        `scope.service`, so a typo'd service name fails at mint time,
        not three calls later when the real request goes out.
        """
        try:
            self._lookup(scope.service)
        except KeyError as exc:
            raise CredentialNotFound(
                f"no base secret registered for service {scope.service!r}"
            ) from exc

        now = utcnow()
        token = f"gcred_{uuid.uuid4().hex}"
        cred = IssuedCredential(
            token=token,
            service=scope.service,
            issued_at=now,
            expires_at=now + timedelta(seconds=scope.ttl_seconds),
            max_uses=scope.max_uses,
            uses_remaining=scope.max_uses,
            permissions=scope.permissions,
        )
        with self._lock:
            self._issued[token] = cred

        self._audit(
            "ISSUE",
            cred,
            reason=(
                f"minted for {scope.service!r}: ttl={scope.ttl_seconds:g}s, "
                f"max_uses={scope.max_uses}"
            ),
        )
        return cred

    # -- resolving -----------------------------------------------------

    def resolve(self, token: str) -> str:
        """Exchange `token` for the real secret, consuming one use.

        Call this only from the code path that makes the actual
        outbound request -- an HTTP client, an egress proxy, an SDK
        wrapper -- never from anything the model's tool-call arguments
        can reach. The whole point of minting a token instead of
        handing out the real secret is that resolution happens on your
        side of that boundary.

        Raises
        ------
        CredentialNotFound
            `token` was never issued, or was already revoked / consumed
            past its last use.
        CredentialExpired
            The token's TTL has elapsed. The token is discarded.
        CredentialExhausted
            The token's use budget was already spent by a previous
            `resolve` call. The token is discarded.
        """
        with self._lock:
            cred = self._issued.get(token)
            if cred is None:
                raise CredentialNotFound(f"unknown or already-revoked credential {token!r}")

            now = utcnow()
            if cred.expired(now):
                del self._issued[token]
                self._audit("EXPIRE", cred, reason="expired at resolve time")
                raise CredentialExpired(
                    f"credential for {cred.service!r} expired at {cred.expires_at.isoformat()}"
                )
            if cred.exhausted():
                del self._issued[token]
                self._audit("EXHAUST", cred, reason="no uses remaining")
                raise CredentialExhausted(
                    f"credential for {cred.service!r} has no uses remaining"
                )

            if cred.uses_remaining is not None:
                cred.uses_remaining -= 1
                # Left in place even at 0, rather than deleted here: a
                # *subsequent* resolve() attempt should see "this token
                # existed and its budget is spent" (CredentialExhausted)
                # instead of the less informative "never heard of this
                # token" (CredentialNotFound) that a proactive delete
                # would produce.

            secret = self._lookup(cred.service)

        self._audit("RESOLVE", cred, reason="resolved for an outbound call")
        return secret

    # -- revocation ------------------------------------------------------

    def revoke(self, token: str) -> None:
        """Invalidate `token` immediately, regardless of TTL or uses left.

        A no-op (not an error) if `token` is unknown or already gone --
        revoking twice, or revoking something that just expired under
        you, should not raise.
        """
        with self._lock:
            cred = self._issued.pop(token, None)
        if cred is not None:
            self._audit("REVOKE", cred, reason="revoked before expiry")

    def revoke_all(self, service: str | None = None) -> int:
        """Revoke every outstanding credential, or every one for `service`.

        Returns the number revoked. Useful as a kill switch: on a
        detected policy violation, cut off every token in flight rather
        than waiting out their TTLs.
        """
        with self._lock:
            tokens = [
                t for t, c in self._issued.items() if service is None or c.service == service
            ]
            revoked = [self._issued.pop(t) for t in tokens]
        for cred in revoked:
            self._audit("REVOKE", cred, reason="revoked by revoke_all")
        return len(revoked)

    def active_count(self, service: str | None = None) -> int:
        """Outstanding credentials that are neither expired nor exhausted.

        No background sweep runs to evict expired/exhausted entries as
        they age out -- `resolve()` evicts them lazily on next use, and
        this method filters them out of the count without evicting them
        itself (a read should not have a side effect)."""
        now = utcnow()
        with self._lock:
            return sum(
                1
                for c in self._issued.values()
                if (service is None or c.service == service)
                and not c.expired(now)
                and not c.exhausted()
            )

    # -- audit -----------------------------------------------------------

    def _audit(self, action: str, cred: IssuedCredential, *, reason: str) -> None:
        self.audit_log.append(
            AuditEntry(
                timestamp=utcnow(),
                call_id=cred.token,
                tool=f"credential:{cred.service}",
                decision=action,
                reason=reason,
                metadata={
                    "expires_at": cred.expires_at.isoformat(),
                    "max_uses": cred.max_uses,
                    "uses_remaining": cred.uses_remaining,
                    "permissions": list(cred.permissions),
                },
            )
        )


def _dict_lookup(store: dict[str, str]) -> Callable[[str], str]:
    def lookup(service: str) -> str:
        return store[service]

    return lookup
