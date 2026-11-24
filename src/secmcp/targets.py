"""URL and host targets for the HTTP tools."""

import ipaddress
from urllib.parse import urlsplit

from secmcp.scope import Resolver, Scope, ScopeDecision, check_target

MAX_TARGETS = 100


class UrlDecision(ScopeDecision):
    url: str | None = None


def normalize_url(raw: str, require_scheme: bool = False) -> tuple[str, str]:
    """Return the URL to hand to a tool and the host to check, or raise ValueError.

    The URL is rebuilt from the parsed parts so the tool sees exactly the host
    that was checked.
    """
    text = raw.strip()
    if not text:
        raise ValueError("empty target")
    if text.startswith("-"):
        raise ValueError("target must not start with '-'")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"whitespace or control characters in target {raw!r}")
    if "\\" in text:
        raise ValueError(f"backslashes are not allowed in target {raw!r}")
    has_scheme = "://" in text
    if not has_scheme:
        if require_scheme:
            raise ValueError("expected a url starting with http:// or https://")
        text = "//" + text
    parts = urlsplit(text)
    if has_scheme and parts.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {parts.scheme!r}, use http or https")
    if "@" in parts.netloc:
        raise ValueError("credentials in urls are not allowed")
    host = parts.hostname
    if not host:
        raise ValueError(f"missing host in {raw!r}")
    try:
        port = parts.port
    except ValueError:
        raise ValueError(f"invalid port in {raw!r}") from None
    netloc = f"[{host}]" if _is_ipv6(host) else host
    if port is not None:
        netloc += f":{port}"
    url = f"{parts.scheme}://{netloc}" if has_scheme else netloc
    url += parts.path
    if parts.query:
        url += "?" + parts.query
    return url, host


def _is_ipv6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


def check_url(
    raw: str, scope: Scope, resolve: Resolver, require_scheme: bool = False
) -> UrlDecision:
    """Check the host of a URL or host[:port] target against the scope."""
    try:
        url, host = normalize_url(raw, require_scheme)
    except ValueError as exc:
        return UrlDecision(target=raw, allowed=False, reason=str(exc))
    decision = check_target(host, scope, resolve)
    fields = decision.model_dump(exclude={"target"})
    return UrlDecision(target=raw, url=url if decision.allowed else None, **fields)


def check_urls(
    raws: list[str], scope: Scope, resolve: Resolver
) -> tuple[list[UrlDecision], str | None]:
    """Check every target; the reason is set if any of them is refused."""
    if not raws:
        return [], "no targets given"
    if len(raws) > MAX_TARGETS:
        return [], f"too many targets: {len(raws)}, the limit is {MAX_TARGETS}"
    decisions = [check_url(raw, scope, resolve) for raw in raws]
    refused = [d for d in decisions if not d.allowed]
    if not refused:
        return decisions, None
    shown = "; ".join(f"{d.target}: {d.reason}" for d in refused[:5])
    more = f" and {len(refused) - 5} more" if len(refused) > 5 else ""
    return decisions, f"{len(refused)} target(s) refused: {shown}{more}"
