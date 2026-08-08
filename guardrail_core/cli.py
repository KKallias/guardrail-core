"""
`guardrail` command-line interface.

    guardrail check   --policy policy.yaml --tool search --amount 0.25 --payload '{"q": "hi"}'
    guardrail scan    --file notes.txt
    guardrail audit   --log logs/guardrail-audit.jsonl --tail 20
    guardrail policy  --policy policy.yaml       # validate and echo

Exit codes: 0 = allowed, 1 = blocked by policy, 2 = usage/config error.
That makes `guardrail check` usable directly in a shell pipeline or a
CI step.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .audit import AuditLog
from .detectors import pii
from .guard import Decision, Guard, ToolCall
from .policy import Policy, PolicyError

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2


def _load_policy(path: str) -> Policy:
    return Policy.from_yaml(path)


def _parse_payload(raw: str | None, payload_file: str | None) -> Any:
    if payload_file:
        raw = Path(payload_file).read_text(encoding="utf-8")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # A plain string payload is a perfectly reasonable thing to check.
        return {"input": raw}


def cmd_check(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    guard = Guard(policy, args.log, load_history=not args.no_history)
    call = ToolCall(
        tool=args.tool,
        payload=_parse_payload(args.payload, args.payload_file),
        amount=args.amount,
        currency=args.currency,
    )
    result = guard.check(call, commit=not args.dry_run)

    if args.json:
        print(
            json.dumps(
                {
                    "decision": result.decision.value,
                    "reason": result.reason,
                    "rule": result.rule,
                    "call_id": call.call_id,
                    "findings": [f.to_dict() for f in result.findings],
                    "redacted_payload": result.redacted_payload,
                },
                indent=2,
                default=str,
            )
        )
    else:
        print(f"{result.decision.value}: {result.reason}")
        if result.decision is Decision.REDACT:
            print(json.dumps(result.redacted_payload, indent=2, default=str))

    return EXIT_BLOCKED if result.blocked else EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    elif args.text:
        text = args.text
    else:
        text = sys.stdin.read()

    detectors = args.detectors.split(",") if args.detectors else None
    findings = pii.scan_text(text, detectors)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif args.redact:
        print(pii.redact_text(text, findings))
    elif not findings:
        print("no findings")
    else:
        for finding in findings:
            print(f"{finding.detector:14} {finding.start}-{finding.end}  {finding.masked()}")

    # Findings are not a policy decision on their own, so scanning stays
    # exit code 0 unless --fail-on-finding asks otherwise.
    return EXIT_BLOCKED if (findings and args.fail_on_finding) else EXIT_OK


def cmd_audit(args: argparse.Namespace) -> int:
    log = AuditLog(args.log)
    entries = log.read_all()

    if args.decision:
        wanted = args.decision.upper()
        entries = [e for e in entries if e.decision == wanted]
    if args.tail:
        entries = entries[-args.tail :]

    if args.json:
        print(json.dumps([e.to_dict() for e in entries], indent=2, default=str))
    else:
        for entry in entries:
            amount = f" {entry.amount} {entry.currency or ''}".rstrip() if entry.amount else ""
            print(
                f"{entry.timestamp.isoformat()}  {entry.decision:6}  "
                f"{entry.tool}{amount}  {entry.reason}"
            )
        if not entries:
            print(f"no entries in {log.path}")

    # Only decisions that actually consumed budget count toward the total.
    # A BLOCK spent nothing, and a RECONCILE restates a call already
    # counted from its ALLOW - summing it would double the reported spend.
    total = sum(e.amount or 0 for e in entries if e.decision in Guard.REPLAYED_DECISIONS)
    if args.summary:
        blocked = sum(1 for e in entries if e.decision == Decision.BLOCK.value)
        print(f"\n{len(entries)} entries, {blocked} blocked, {total:.4f} spent")
    return EXIT_OK


def cmd_policy(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    print(json.dumps(policy.to_dict(), indent=2, default=str))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrail",
        description="Policy enforcement for AI agent tool-calls.",
    )
    parser.add_argument("--version", action="version", version=f"guardrail-core {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="evaluate a single tool-call against a policy")
    check.add_argument("--policy", required=True, help="path to a policy YAML file")
    check.add_argument("--tool", required=True, help="tool name")
    check.add_argument("--amount", type=float, default=None, help="charge for this call")
    check.add_argument("--currency", default=None)
    check.add_argument("--payload", default=None, help="JSON payload (or a plain string)")
    check.add_argument("--payload-file", default=None)
    check.add_argument("--log", default=None, help="audit log path")
    check.add_argument(
        "--dry-run",
        action="store_true",
        help="evaluate without consuming spend/rate budget",
    )
    check.add_argument(
        "--no-history",
        action="store_true",
        help="ignore previous entries in the audit log",
    )
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=cmd_check)

    scan = sub.add_parser("scan", help="run PII/secret detectors over text")
    scan.add_argument("--file", default=None)
    scan.add_argument("--text", default=None)
    scan.add_argument("--detectors", default=None, help="comma-separated detector names")
    scan.add_argument("--redact", action="store_true", help="print the redacted text")
    scan.add_argument("--fail-on-finding", action="store_true", help="exit 1 if anything matches")
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=cmd_scan)

    audit = sub.add_parser("audit", help="read the audit log")
    audit.add_argument("--log", default=None, help="audit log path")
    audit.add_argument("--tail", type=int, default=None)
    audit.add_argument(
        "--decision",
        default=None,
        help="filter: allow | block | redact | reconcile (case-insensitive)",
    )
    audit.add_argument("--summary", action="store_true")
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit)

    policy_cmd = sub.add_parser("policy", help="validate a policy file and print it")
    policy_cmd.add_argument("--policy", required=True)
    policy_cmd.set_defaults(func=cmd_policy)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (PolicyError, pii.UnknownDetector) as exc:
        print(f"guardrail: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as exc:
        print(f"guardrail: file not found: {exc.filename}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
