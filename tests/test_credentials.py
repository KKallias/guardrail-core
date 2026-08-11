"""
CredentialBroker tests.

No real secret store or upstream API involved: `secrets` is a plain
dict, matching the fixture style the rest of the suite uses for audit
logs and policies.
"""

from __future__ import annotations

import time

import pytest

from guardrail_core.audit import AuditLog
from guardrail_core.credentials import (
    CredentialBroker,
    CredentialExhausted,
    CredentialExpired,
    CredentialNotFound,
    Scope,
)


@pytest.fixture
def log(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def broker(log) -> CredentialBroker:
    return CredentialBroker({"stripe": "sk_live_real_secret", "notion": "secret_notion"}, audit_log=log)


# -- minting -------------------------------------------------------------


def test_minted_token_is_not_the_real_secret(broker):
    cred = broker.mint(Scope(service="stripe"))

    assert cred.token.startswith("gcred_")
    assert cred.token != "sk_live_real_secret"
    assert cred.service == "stripe"


def test_minting_for_an_unregistered_service_raises_before_issuing_anything(broker):
    with pytest.raises(CredentialNotFound):
        broker.mint(Scope(service="does-not-exist"))

    assert broker.active_count() == 0


def test_scope_rejects_non_positive_ttl():
    with pytest.raises(ValueError):
        Scope(service="stripe", ttl_seconds=0)


def test_scope_rejects_non_positive_max_uses():
    with pytest.raises(ValueError):
        Scope(service="stripe", max_uses=0)


def test_scope_allows_unlimited_uses_via_none():
    scope = Scope(service="stripe", max_uses=None)
    assert scope.max_uses is None


# -- resolving -------------------------------------------------------------


def test_resolve_returns_the_real_secret(broker):
    cred = broker.mint(Scope(service="stripe"))

    assert broker.resolve(cred.token) == "sk_live_real_secret"


def test_resolve_of_unknown_token_raises(broker):
    with pytest.raises(CredentialNotFound):
        broker.resolve("gcred_never_issued")


def test_max_uses_one_is_consumed_after_first_resolve(broker):
    cred = broker.mint(Scope(service="stripe", max_uses=1))

    broker.resolve(cred.token)

    with pytest.raises(CredentialExhausted):
        broker.resolve(cred.token)


def test_max_uses_three_allows_exactly_three_resolves(broker):
    cred = broker.mint(Scope(service="notion", max_uses=3))

    for _ in range(3):
        assert broker.resolve(cred.token) == "secret_notion"

    with pytest.raises(CredentialExhausted):
        broker.resolve(cred.token)


def test_unlimited_uses_never_exhausts_within_ttl(broker):
    cred = broker.mint(Scope(service="stripe", ttl_seconds=60, max_uses=None))

    for _ in range(10):
        broker.resolve(cred.token)  # should not raise


def test_expired_token_raises_and_is_evicted(broker):
    cred = broker.mint(Scope(service="stripe", ttl_seconds=0.05, max_uses=None))
    time.sleep(0.1)

    with pytest.raises(CredentialExpired):
        broker.resolve(cred.token)

    # Evicted on the failed resolve, not just logically expired.
    assert broker.active_count() == 0
    with pytest.raises(CredentialNotFound):
        broker.resolve(cred.token)


# -- revocation -------------------------------------------------------------


def test_revoke_prevents_further_resolution(broker):
    cred = broker.mint(Scope(service="stripe", max_uses=None, ttl_seconds=60))
    broker.revoke(cred.token)

    with pytest.raises(CredentialNotFound):
        broker.resolve(cred.token)


def test_revoke_is_idempotent(broker):
    cred = broker.mint(Scope(service="stripe"))
    broker.revoke(cred.token)
    broker.revoke(cred.token)  # should not raise


def test_revoke_all_for_one_service_leaves_others_untouched(broker):
    a = broker.mint(Scope(service="stripe", max_uses=None, ttl_seconds=60))
    b = broker.mint(Scope(service="notion", max_uses=None, ttl_seconds=60))

    revoked = broker.revoke_all(service="stripe")

    assert revoked == 1
    with pytest.raises(CredentialNotFound):
        broker.resolve(a.token)
    assert broker.resolve(b.token) == "secret_notion"


def test_revoke_all_with_no_service_is_a_kill_switch(broker):
    broker.mint(Scope(service="stripe", max_uses=None, ttl_seconds=60))
    broker.mint(Scope(service="notion", max_uses=None, ttl_seconds=60))

    revoked = broker.revoke_all()

    assert revoked == 2
    assert broker.active_count() == 0


# -- audit trail -------------------------------------------------------------


def test_every_lifecycle_event_is_audited(broker, log):
    cred = broker.mint(Scope(service="stripe", max_uses=1))
    broker.resolve(cred.token)
    try:
        broker.resolve(cred.token)
    except CredentialExhausted:
        pass

    decisions = [e.decision for e in log.read_all()]
    assert decisions == ["ISSUE", "RESOLVE", "EXHAUST"]


def test_audit_entries_never_contain_the_real_secret(broker, log):
    cred = broker.mint(Scope(service="stripe", permissions=("charge:create",)))
    broker.resolve(cred.token)

    raw = (log.path).read_text()
    assert "sk_live_real_secret" not in raw
    assert cred.token in raw  # the opaque handle is fine to log


def test_credential_lookup_supports_a_callable_instead_of_a_dict(log):
    calls = []

    def lookup(service: str) -> str:
        calls.append(service)
        return f"resolved-{service}"

    broker = CredentialBroker(lookup, audit_log=log)
    cred = broker.mint(Scope(service="anything"))

    assert broker.resolve(cred.token) == "resolved-anything"
    assert calls == ["anything", "anything"]  # once at mint (existence check), once at resolve
