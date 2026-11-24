"""Parse httpx JSON lines output into probe results."""

import json
from collections import Counter

from pydantic import BaseModel, Field, ValidationError


class HttpxParseError(ValueError):
    pass


class Probe(BaseModel):
    input: str
    url: str
    failed: bool = False
    error: str | None = None
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    location: str | None = None
    tech: list[str] = Field(default_factory=list)
    host_ip: str | None = None
    port: str | None = None
    scheme: str | None = None


def parse_httpx_jsonl(data: bytes) -> list[Probe]:
    """Parse one JSON object per line, as written by httpx -json."""
    probes = []
    for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            probe = Probe.model_validate(json.loads(line))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise HttpxParseError(
                f"invalid httpx output on line {number}: {exc}"
            ) from None
        if probe.failed:
            probe.status_code = None
            probe.content_length = None
        probes.append(probe)
    return probes


def summarize(probes: list[Probe]) -> str:
    alive = [probe for probe in probes if not probe.failed]
    summary = f"{len(alive)} of {len(probes)} targets responded"
    codes = Counter(probe.status_code for probe in alive if probe.status_code)
    if codes:
        counts = ", ".join(f"{code} x{count}" for code, count in sorted(codes.items()))
        summary += f" ({counts})"
    return summary
