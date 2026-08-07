"""
Append-only JSONL audit log.

One JSON object per line, one line per guard decision. The format is
deliberately boring: grep-able, diffable, trivially replayable, and safe
to ship to any log collector. Nothing here ever rewrites or truncates an
existing line - the file is opened in append mode only.

The log is also the guard's memory. A fresh process has no in-memory
spend history, so `Guard` reloads its rolling window from this file on
start-up; without that, a per-run agent would reset its own spend cap on
every invocation.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("guardrail_core.audit")

DEFAULT_AUDIT_PATH = Path("logs") / "guardrail-audit.jsonl"

SCHEMA_VERSION = 1


@dataclass
class AuditEntry:
    """One recorded decision.

    `payload` holds the redacted payload when redaction happened, and is
    omitted otherwise - raw payloads are never written to the log, since
    the whole point of the PII rules is to keep that data out of files.
    """

    timestamp: datetime
    call_id: str
    tool: str
    decision: str
    reason: str
    policy: str | None = None
    rule: str | None = None
    amount: float | None = None
    currency: str | None = None
    recipient: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    payload: Any | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "v": SCHEMA_VERSION,
            "timestamp": self.timestamp.isoformat(),
            "call_id": self.call_id,
            "tool": self.tool,
            "decision": self.decision,
            "reason": self.reason,
        }
        if self.policy is not None:
            entry["policy"] = self.policy
        if self.rule is not None:
            entry["rule"] = self.rule
        if self.amount is not None:
            entry["amount"] = self.amount
            entry["currency"] = self.currency
        if self.recipient is not None:
            entry["recipient"] = self.recipient
        if self.findings:
            entry["findings"] = self.findings
        if self.payload is not None:
            entry["redacted_payload"] = self.payload
        if self.metadata:
            entry["metadata"] = self.metadata
        return entry

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEntry":
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            call_id=data.get("call_id", ""),
            tool=data.get("tool", ""),
            decision=data["decision"],
            reason=data.get("reason", ""),
            policy=data.get("policy"),
            rule=data.get("rule"),
            amount=data.get("amount"),
            currency=data.get("currency"),
            recipient=data.get("recipient"),
            findings=data.get("findings", []),
            payload=data.get("redacted_payload"),
            metadata=data.get("metadata", {}),
        )


class AuditLog:
    """Append-only JSONL sink.

    Thread-safe for appends within one process (a lock plus a single
    `write` of a line that ends in a newline). Across processes, appends
    to the same file are ordered by the OS; each write is one line, so
    interleaving cannot corrupt a record in practice for the line sizes
    involved here.
    """

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path is not None else DEFAULT_AUDIT_PATH
        self._lock = threading.Lock()

    def append(self, entry: AuditEntry) -> dict[str, Any]:
        """Write one entry and return the dict that was serialized."""
        data = entry.to_dict()
        line = json.dumps(data, ensure_ascii=False, default=str)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return data

    def read_all(self) -> list[AuditEntry]:
        return list(self.iter_entries())

    def iter_entries(self) -> Iterator[AuditEntry]:
        """Yield every well-formed entry, skipping corrupted lines.

        A truncated final line (killed process mid-write) must not make
        the whole history unreadable, so parse failures are logged and
        skipped rather than raised.
        """
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield AuditEntry.from_dict(json.loads(line))
                except (json.JSONDecodeError, KeyError, ValueError):
                    logger.warning("Skipping corrupted audit line %s:%d", self.path, number)

    def tail(self, count: int = 10) -> list[AuditEntry]:
        entries = self.read_all()
        return entries[-count:]


def utcnow() -> datetime:
    """Timezone-aware UTC now - used everywhere so entries sort correctly."""
    return datetime.now(timezone.utc)
