"""
guardrail-core: policy enforcement for AI agent tool-calls.

Intercept a tool-call before it executes, enforce spend caps, rate
limits and PII/secret rules against a declarative policy, and append the
decision to a tamper-evident JSONL audit log.

    from guardrail_core import Guard, Policy, ToolCall

    guard = Guard(Policy.from_yaml("policy.yaml"))
    result = guard.check(ToolCall(tool="search", payload={"q": "..."}, amount=0.25))
    if result.blocked:
        ...
"""

from .audit import AuditEntry, AuditLog
from .detectors.pii import Finding
from .guard import BlockedByPolicy, Decision, Guard, GuardResult, ToolCall
from .policy import Allowlist, PiiRules, Policy, PolicyError, RateLimit, SpendCap

__version__ = "0.1.0"

__all__ = [
    "Allowlist",
    "AuditEntry",
    "AuditLog",
    "BlockedByPolicy",
    "Decision",
    "Finding",
    "Guard",
    "GuardResult",
    "PiiRules",
    "Policy",
    "PolicyError",
    "RateLimit",
    "SpendCap",
    "ToolCall",
    "__version__",
]
