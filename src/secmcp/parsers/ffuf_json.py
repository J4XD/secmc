"""Parse ffuf JSON output into matches."""

import json
from collections import Counter
from typing import Any

from pydantic import BaseModel, ValidationError


class FfufParseError(ValueError):
    pass


class FfufMatch(BaseModel):
    word: str
    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str = ""
    redirect_location: str = ""
    duration_ms: int


def _match(result: dict[str, Any]) -> FfufMatch:
    return FfufMatch(
        word=result.get("input", {}).get("FUZZ", ""),
        url=result["url"],
        status=result["status"],
        length=result["length"],
        words=result["words"],
        lines=result["lines"],
        content_type=result.get("content-type", ""),
        redirect_location=result.get("redirectlocation", ""),
        duration_ms=result.get("duration", 0) // 1_000_000,
    )


def parse_ffuf_json(data: bytes) -> list[FfufMatch]:
    """Parse the document written by ffuf -of json."""
    try:
        document = json.loads(data)
        return [_match(result) for result in document.get("results") or []]
    except (json.JSONDecodeError, ValidationError) as exc:
        raise FfufParseError(f"invalid ffuf output: {exc}") from None
    except (AttributeError, KeyError, TypeError) as exc:
        raise FfufParseError(f"unexpected ffuf output: {exc!r}") from None


def summarize(matches: list[FfufMatch]) -> str:
    if not matches:
        return "no matches"
    codes = Counter(match.status for match in matches)
    counts = ", ".join(f"{code} x{count}" for code, count in sorted(codes.items()))
    return f"{len(matches)} matches ({counts})"
