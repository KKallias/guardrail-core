"""
LangChain adapter: a callback handler that guards tool execution.

LangChain is an optional dependency. If it is not installed, the handler
still imports and works standalone (useful for tests) - it just falls
back to a local no-op base class instead of `BaseCallbackHandler`.

    from guardrail_core.adapters.langchain import GuardrailCallbackHandler

    handler = GuardrailCallbackHandler(policy)
    agent.invoke({"input": "..."}, config={"callbacks": [handler]})

`on_tool_start` raises `BlockedByPolicy` on a BLOCK decision. LangChain
propagates callback exceptions out of the tool run, which is exactly the
behaviour we want: the tool never executes.

Note the limits of the callback surface: `on_tool_start` can refuse a
call, but LangChain gives a callback no way to rewrite the tool input.
A handler therefore cannot redact - it can only allow or refuse.

So REDACT blocks by default (`redact_as_block=True`). Failing closed is
the only safe default here: the alternative would let a payload the
policy just identified as containing a secret reach the tool unchanged,
while the audit log records "REDACT" - a log that claims a protection
that did not happen. For redaction that actually rewrites the payload,
wrap the tool function with `@guarded` from `adapters.generic`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
from uuid import UUID

from ..audit import AuditLog
from ..guard import BlockedByPolicy, Decision, Guard, GuardResult, ToolCall
from ..policy import Policy

try:  # pragma: no cover - depends on the host environment
    from langchain_core.callbacks import BaseCallbackHandler

    LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover
    try:
        from langchain.callbacks.base import BaseCallbackHandler  # type: ignore

        LANGCHAIN_AVAILABLE = True
    except ImportError:

        class BaseCallbackHandler:  # type: ignore[no-redef]
            """Stand-in used when LangChain is not installed."""

        LANGCHAIN_AVAILABLE = False


__all__ = ["GuardrailCallbackHandler", "BlockedByPolicy", "LANGCHAIN_AVAILABLE"]


class GuardrailCallbackHandler(BaseCallbackHandler):
    """Runs `Guard.check` on every tool start.

    Parameters
    ----------
    policy / guard:
        Either a policy to enforce, or an existing `Guard` to share
        budget with other adapters in the same process.
    amount_for:
        Callable `(tool_name, input_str, kwargs) -> float | None`
        returning what this tool call costs. Without it, calls are
        treated as free and only rate-limit and PII rules apply.
    redact_as_block:
        Treat a REDACT decision as a refusal. **Defaults to True**, and
        should stay that way for most users.

        Setting it False is an advanced opt-out with a sharp edge: a
        LangChain callback cannot rewrite tool input, so with it
        disabled a REDACT is written to the audit log but the tool still
        receives the **original, unredacted** payload. The log will say
        the secret was redacted when it was not. If you disable this,
        you must also wrap the tool function itself with `@guarded` from
        `adapters.generic` - that is what performs real redaction. Only
        reasonable case for False: the tools are already `@guarded` and
        you want this handler for audit and spend/rate enforcement only.
    on_decision:
        Called with every `GuardResult`, for metrics or custom logging.
    """

    # LangChain checks this attribute to decide whether to run the
    # handler inline; guards must run inline to be able to refuse.
    raise_error = True
    run_inline = True

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        guard: Guard | None = None,
        audit_log: AuditLog | Path | str | None = None,
        amount_for: Callable[[str, str, dict[str, Any]], float | None] | None = None,
        redact_as_block: bool = True,
        on_decision: Callable[[GuardResult], None] | None = None,
    ):
        super().__init__()
        if guard is None:
            if policy is None:
                raise ValueError(
                    "GuardrailCallbackHandler requires either a policy or a guard"
                )
            guard = Guard(policy, audit_log)
        self.guard = guard
        self.amount_for = amount_for
        self.redact_as_block = redact_as_block
        self.on_decision = on_decision
        # Keyed by LangChain's run_id so callers can inspect the decision
        # for a specific tool run after the fact.
        self.results: dict[str, GuardResult] = {}

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        tool_name = (serialized or {}).get("name") or "unknown_tool"
        payload: Any = inputs if inputs is not None else {"input": input_str}

        amount = None
        if self.amount_for is not None:
            amount = self.amount_for(tool_name, input_str, kwargs)

        call = ToolCall(
            tool=tool_name,
            payload=payload,
            amount=amount,
            metadata={
                "run_id": str(run_id) if run_id else None,
                "parent_run_id": str(parent_run_id) if parent_run_id else None,
                "tags": tags or [],
                "source": "langchain",
                **(metadata or {}),
            },
        )

        result = self.guard.check(call)
        if run_id is not None:
            self.results[str(run_id)] = result
        if self.on_decision is not None:
            self.on_decision(result)

        if result.blocked or (
            self.redact_as_block and result.decision is Decision.REDACT
        ):
            raise BlockedByPolicy(result)
        return None
