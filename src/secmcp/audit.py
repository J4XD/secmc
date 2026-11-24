"""Append-only JSONL audit log of every tool call."""

import os
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError


class AuditRecord(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tool: str
    target: str
    argv: list[str] = []
    dry_run: bool = False
    decision: Literal["allowed", "blocked"]
    reason: str
    exit_code: int | None = None
    timed_out: bool = False
    duration_s: float | None = None
    raw_output_path: str | None = None


def append_record(path: Path, record: AuditRecord) -> None:
    """Append one record as a single JSON line."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    line = (record.model_dump_json() + "\n").encode()
    # One write on an O_APPEND descriptor keeps concurrent lines from interleaving.
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def read_records(path: Path, limit: int) -> list[AuditRecord]:
    """Return the last limit records, oldest first, skipping unreadable lines."""
    if limit <= 0 or not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        lines = deque(handle, maxlen=limit)
    records = []
    for line in lines:
        try:
            records.append(AuditRecord.model_validate_json(line))
        except ValidationError:
            continue
    return records
