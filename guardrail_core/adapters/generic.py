"""
Framework-agnostic adapter: the `@guarded` decorator.

Wrap any callable so that every invocation goes through `Guard.check`
first. This is the lowest-common-denominator integration - if a
framework has no adapter of its own, decorating the tool function works.

    policy = Policy(spend_cap=SpendCap(window_amount=5.0, window_seconds=3600))

    @guarded(policy, amount=0.75)
    def call_paid_api(query: str) -> str:
        ...

The decorated function gains a `.guard` attribute, so several tools can
share one budget by passing that guard to the next decorator:

    @guarded(guard=call_paid_api.guard)
    def another_tool(...): ...
"""

from __future__ import annotations

import functools
import inspect
from pathlib import Path
from typing import Any, Callable, TypeVar

from ..audit import AuditLog
from ..guard import BlockedByPolicy, Decision, Guard, GuardResult, ToolCall
from ..policy import Policy

F = TypeVar("F", bound=Callable[..., Any])

__all__ = ["guarded", "BlockedByPolicy"]


def guarded(
    policy: Policy | None = None,
    *,
    guard: Guard | None = None,
    audit_log: AuditLog | Path | str | None = None,
    tool: str | None = None,
    amount: float | Callable[..., float | None] | None = None,
    amount_arg: str | None = None,
    on_result: Callable[[GuardResult], None] | None = None,
    apply_redaction: bool = True,
):
    """Decorator factory enforcing `policy` before the function runs.

    Parameters
    ----------
    policy:
        The policy to enforce. Ignored when `guard` is given.
    guard:
        An existing `Guard` to share state with other decorated
        functions. One of `policy` or `guard` is required.
    tool:
        Name recorded in the audit log; defaults to the function's name.
    amount:
        Fixed charge per call, or a callable receiving the same
        arguments as the function and returning the charge. Use this for
        priced tools; leave it None for free ones.
    amount_arg:
        Name of the function argument that carries the charge, for tools
        whose price is passed in by the caller.
    on_result:
        Called with the `GuardResult` after every check, allowed or not -
        a hook for metrics or custom logging.
    apply_redaction:
        When a REDACT decision fires and the wrapped function takes
        keyword arguments matching the redacted payload keys, call it
        with the redacted values instead of the originals. Set False to
        run the function with its original arguments and treat redaction
        as audit-only.

    Raises
    ------
    BlockedByPolicy
        When the guard returns BLOCK. The function is not executed.
    """
    if guard is None:
        if policy is None:
            raise ValueError("guarded() requires either a policy or an existing guard")
        guard = Guard(policy, audit_log)

    def decorate(func: F) -> F:
        signature = inspect.signature(func)
        tool_name = tool or func.__name__

        def build_call(args: tuple, kwargs: dict) -> ToolCall:
            bound = signature.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            payload = dict(bound.arguments)

            charge: float | None = None
            if callable(amount):
                charge = amount(*args, **kwargs)
            elif amount is not None:
                charge = float(amount)
            elif amount_arg is not None:
                raw = payload.get(amount_arg)
                charge = float(raw) if raw is not None else None

            # The price argument is bookkeeping, not tool input - keep it
            # out of the scanned payload so it can't trip a detector.
            if amount_arg is not None:
                payload.pop(amount_arg, None)

            return ToolCall(tool=tool_name, payload=payload, amount=charge)

        def apply(result: GuardResult, args: tuple, kwargs: dict) -> tuple[tuple, dict]:
            """Rebuild call arguments from the redacted payload."""
            if not apply_redaction or result.decision is not Decision.REDACT:
                return args, kwargs
            redacted = result.redacted_payload or {}
            bound = signature.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            for name, value in redacted.items():
                if name in bound.arguments:
                    bound.arguments[name] = value
            return bound.args, bound.kwargs

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = guard.check(build_call(args, kwargs))
                if on_result is not None:
                    on_result(result)
                result.raise_if_blocked()
                new_args, new_kwargs = apply(result, args, kwargs)
                return await func(*new_args, **new_kwargs)

            wrapper: Any = async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = guard.check(build_call(args, kwargs))
                if on_result is not None:
                    on_result(result)
                result.raise_if_blocked()
                new_args, new_kwargs = apply(result, args, kwargs)
                return func(*new_args, **new_kwargs)

            wrapper = sync_wrapper

        wrapper.guard = guard  # type: ignore[attr-defined]
        wrapper.policy = guard.policy  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorate
