"""
Claude Code (and Claude Agent SDK) hook adapter.

Wires guardrail-core's `Guard` into Claude Code's `PreToolUse` /
`PostToolUse` hook protocol: https://code.claude.com/docs/en/hooks

Claude Code invokes a hook command once per tool call, feeding it a JSON
object on stdin and reading a JSON decision back from stdout (exit 0).
This module implements both sides of that contract:

    guard = ClaudeCodeGuard(Policy.from_yaml("policy.yaml"))

    # inside a hook script, or via `python -m guardrail_core.adapters.claude_code`
    output = guard.handle_pretooluse(json.load(sys.stdin))
    print(json.dumps(output))

No dependency on the Claude Code SDK: input and output are plain dicts,
in the same style as the MCP, x402 and MPP adapters.

## What becomes the ToolCall's `recipient`

Every built-in tool that reaches the network is mapped to a hostname, so
the existing `allowlist` policy rule doubles as a coarse network egress
allowlist -- independent of *which* tool the model used to reach that
host:

- `WebFetch` -> the URL's hostname
- `mcp__<server>__<tool>` -> the MCP server name
- `Bash` commands that shell out to curl/wget/http/gh/aws/gcloud/etc.
  and a URL -> that URL's hostname

A call with no discoverable network target (`Read`, `Edit`, an
`mcp__*` name that doesn't parse, a `Bash` command with no recognized
network verb) gets `recipient=None` and skips the allowlist rule, same
as guardrail-core's other adapters.

This is defense in depth, not a sandbox: it only sees what the model
told the tool to do, so a command that builds a URL at runtime from a
variable guardrail-core cannot resolve is invisible here. Pair it with
`guardrail_core.egress` for an enforcement point that does not depend on
parsing the model's command text.

## What guardrail-core cannot see from Claude Code

Claude Code does not expose a real dollar cost per tool call at
`PreToolUse` time, so `amount_for` is always an *estimate* you supply
(a flat price per tool, a price per MCP server) -- not metered usage.
Leave it unset to rely on `rate_limit` and `allowlist` alone.
"""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from ..audit import AuditLog
from ..guard import Decision, Guard, GuardResult, ToolCall
from ..policy import Policy

__all__ = ["ClaudeCodeGuard", "extract_recipient", "main"]

_NETWORK_VERB_RE = re.compile(
    r"\b(?:curl|wget|http|https|httpie|gh\s+api|aws|gcloud|az|kubectl|psql|mysql|redis-cli|nc)\b"
)
_URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"<>)]+")


def extract_recipient(tool_name: str, tool_input: dict[str, Any]) -> str | None:
    """Best-effort hostname/server this call is directed at, or None.

    Used as `ToolCall.recipient`. See the module docstring for what this
    can and cannot see -- it is a hook-layer heuristic, not a sandbox.
    """
    if tool_name == "WebFetch":
        url = tool_input.get("url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            host = urlparse(url).hostname
            return host or None
        return None

    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        return parts[1] if len(parts) >= 2 and parts[1] else None

    if tool_name == "Bash":
        command = tool_input.get("command") or ""
        if _NETWORK_VERB_RE.search(command):
            match = _URL_IN_TEXT_RE.search(command)
            if match:
                host = urlparse(match.group(0)).hostname
                return host or None
        return None

    return None


class ClaudeCodeGuard:
    """Evaluates Claude Code tool calls against a `Policy`.

    Parameters
    ----------
    policy / guard:
        A policy to enforce, or an existing `Guard` to share spend and
        rate-limit budget with other adapters in the same process (e.g.
        an MCP proxy adapter for the same session).
    amount_for:
        Callable `(tool_name, tool_input) -> float | None` returning
        what this call should count against the spend cap. See the
        module docstring -- this is always an estimate you supply.
    recipient_for:
        Override for `extract_recipient`, in case a policy needs a
        different notion of "who this call is directed at".
    deny_is_ask:
        When True, a BLOCK decision is reported as
        `permissionDecision: "ask"` (escalate to a human) instead of
        `"deny"` (hard refusal). Default False: an unattended/CI run has
        nobody to answer "ask", so refusing outright is the safer
        default. Flip to True for interactive sessions where a human is
        at the keyboard.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        guard: Guard | None = None,
        audit_log: AuditLog | Path | str | None = None,
        amount_for: Callable[[str, dict[str, Any]], float | None] | None = None,
        recipient_for: Callable[[str, dict[str, Any]], str | None] = extract_recipient,
        deny_is_ask: bool = False,
    ) -> None:
        if guard is None:
            if policy is None:
                raise ValueError("ClaudeCodeGuard requires either a policy or a guard")
            guard = Guard(policy, audit_log)
        self.guard = guard
        self.amount_for = amount_for
        self.recipient_for = recipient_for
        self.deny_is_ask = deny_is_ask

    # -- mapping -----------------------------------------------------

    def to_call(self, hook_input: dict[str, Any]) -> ToolCall:
        """Map a `PreToolUse`/`PostToolUse` hook payload onto a `ToolCall`."""
        tool_name = hook_input.get("tool_name") or "unknown"
        tool_input = hook_input.get("tool_input") or {}
        amount = self.amount_for(tool_name, tool_input) if self.amount_for else None
        recipient = self.recipient_for(tool_name, tool_input)
        call_id = hook_input.get("tool_use_id") or uuid.uuid4().hex[:12]

        return ToolCall(
            tool=tool_name,
            payload=tool_input,
            amount=amount,
            recipient=recipient,
            call_id=call_id,
            metadata={
                "protocol": "claude-code",
                "session_id": hook_input.get("session_id"),
                "cwd": hook_input.get("cwd"),
                "permission_mode": hook_input.get("permission_mode"),
            },
        )

    # -- PreToolUse --------------------------------------------------

    def handle_pretooluse(self, hook_input: dict[str, Any]) -> dict[str, Any]:
        """Evaluate a `PreToolUse` event. Returns the JSON to print to stdout."""
        call = self.to_call(hook_input)
        result = self.guard.check(call)
        return self._pretooluse_output(result)

    def _pretooluse_output(self, result: GuardResult) -> dict[str, Any]:
        spec: dict[str, Any] = {
            "hookEventName": "PreToolUse",
            "permissionDecisionReason": (
                f"guardrail-core[{result.rule or 'policy'}]: {result.reason}"
            ),
        }

        if result.decision is Decision.BLOCK:
            spec["permissionDecision"] = "ask" if self.deny_is_ask else "deny"
        elif result.decision is Decision.REDACT:
            # PreToolUse's `updatedInput` replaces the tool's arguments
            # before it runs -- exactly what REDACT means in guardrail-core.
            spec["permissionDecision"] = "allow"
            spec["updatedInput"] = result.redacted_payload
        else:
            spec["permissionDecision"] = "allow"

        return {"hookSpecificOutput": spec}

    # -- PostToolUse ---------------------------------------------------

    def handle_posttooluse(self, hook_input: dict[str, Any]) -> dict[str, Any]:
        """Best-effort reconciliation for a completed call.

        Claude Code does not guarantee a `tool_response` shape
        guardrail-core can price, so this only reconciles pass/fail --
        enough to flag, in the audit log, a call that was allowed but
        actually failed -- without inventing cost data Claude Code never
        gave us. Always returns `{}` (no decision control: PostToolUse
        cannot block a call that already ran).
        """
        call_id = hook_input.get("tool_use_id")
        if not call_id:
            return {}
        tool_response = hook_input.get("tool_response")
        is_error = tool_response.get("is_error") if isinstance(tool_response, dict) else None
        try:
            self.guard.reconcile(call_id, {"ok": is_error is not True})
        except Exception:
            # UnknownCallId (no PreToolUse decision for this call_id -- the
            # hook wasn't installed, or this call skipped guarding) or a
            # malformed audit entry. PostToolUse cannot block; never raise
            # out of a hook process.
            pass
        return {}


# -- CLI entry point, wired up by hooks.json ------------------------------


def main(argv: list[str] | None = None) -> int:
    """Read one hook event from stdin, write the decision JSON to stdout.

    Wire this up in `hooks.json`:

        {"type": "command", "command": "python3 -m guardrail_core.adapters.claude_code"}

    The policy path comes from `GUARDRAIL_POLICY`
    (default `guardrails/policy.yaml`) and the audit log from
    `GUARDRAIL_AUDIT_LOG` (default `logs/guardrail-audit.jsonl`), both
    resolved relative to the process's working directory -- Claude Code
    runs hooks with `cwd` set to the session's working directory.
    """
    raw = sys.stdin.read()
    try:
        hook_input = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # Malformed input: fail open on parse errors (there is nothing
        # to enforce against) rather than crash the hook process and
        # block every tool call on a transport glitch.
        print(json.dumps({}))
        return 0

    policy_path = os.environ.get("GUARDRAIL_POLICY", "guardrails/policy.yaml")
    audit_path = os.environ.get("GUARDRAIL_AUDIT_LOG", "logs/guardrail-audit.jsonl")

    try:
        policy = Policy.from_yaml(policy_path)
    except Exception as exc:
        # No usable policy: fail closed via exit 2 (PreToolUse blocks on
        # exit 2) rather than silently running the session unguarded.
        print(
            f"guardrail-core: could not load policy {policy_path!r}: {exc}",
            file=sys.stderr,
        )
        return 2

    guard = Guard(policy, audit_log=audit_path)
    adapter = ClaudeCodeGuard(guard=guard)

    event = hook_input.get("hook_event_name")
    if event == "PreToolUse":
        output = adapter.handle_pretooluse(hook_input)
    elif event == "PostToolUse":
        output = adapter.handle_posttooluse(hook_input)
    else:
        output = {}

    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
