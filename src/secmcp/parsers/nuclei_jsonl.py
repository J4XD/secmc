"""Parse nuclei JSON lines output into findings."""

import json
from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

Severity = Literal["info", "low", "medium", "high", "critical", "unknown"]
SEVERITY_ORDER: tuple[Severity, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "unknown",
)


class NucleiParseError(ValueError):
    pass


class Finding(BaseModel):
    template_id: str
    name: str
    severity: Severity
    tags: list[str] = Field(default_factory=list)
    type: str
    host: str
    matched_at: str
    matcher_name: str | None = None
    extracted_results: list[str] = Field(default_factory=list)
    timestamp: str | None = None


def _finding(raw: dict[str, Any]) -> Finding:
    info = raw.get("info") or {}
    severity = info.get("severity") or "unknown"
    return Finding.model_validate(
        {
            "template_id": raw["template-id"],
            "name": info.get("name", raw["template-id"]),
            "severity": severity if severity in SEVERITY_ORDER else "unknown",
            "tags": info.get("tags") or [],
            "type": raw.get("type", ""),
            "host": raw.get("host", ""),
            "matched_at": raw.get("matched-at", ""),
            "matcher_name": raw.get("matcher-name"),
            "extracted_results": raw.get("extracted-results") or [],
            "timestamp": raw.get("timestamp"),
        }
    )


def parse_nuclei_jsonl(data: bytes) -> list[Finding]:
    """Parse one finding per line, as written by nuclei -jsonl."""
    findings = []
    for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            findings.append(_finding(json.loads(line)))
        except (
            json.JSONDecodeError,
            ValidationError,
            AttributeError,
            KeyError,
            TypeError,
        ) as exc:
            raise NucleiParseError(
                f"invalid nuclei output on line {number}: {exc!r}"
            ) from None
    return findings


def summarize(findings: list[Finding]) -> str:
    if not findings:
        return "no findings"
    counts = Counter(finding.severity for finding in findings)
    shown = ", ".join(
        f"{severity} x{counts[severity]}"
        for severity in SEVERITY_ORDER
        if counts[severity]
    )
    return f"{len(findings)} findings ({shown})"
