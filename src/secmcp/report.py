"""Build a Markdown bug bounty report draft from the audit log and saved tool output."""

import ipaddress
import re
import shlex
import uuid
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel

from secmcp.audit import AuditRecord, append_record, iter_records
from secmcp.config import Config
from secmcp.parsers.ffuf_json import parse_ffuf_json
from secmcp.parsers.httpx_json import parse_httpx_jsonl
from secmcp.parsers.nmap_xml import parse_nmap_xml
from secmcp.parsers.nuclei_jsonl import SEVERITY_ORDER, Severity, parse_nuclei_jsonl
from secmcp.tools import PLUGINS

# Each tool saves its parsed output next to the raw log, under the same run id.
OUTPUT_SUFFIXES: dict[str, str] = {
    plugin.name: plugin.output_suffix for plugin in PLUGINS
}
PARSE_ERRORS = tuple(plugin.parse_error for plugin in PLUGINS)
MAX_VALUE = 300
_LABEL = r"[a-z0-9_][a-z0-9_-]{0,62}"
_DOMAIN = re.compile(rf"(\*\.)?{_LABEL}(\.{_LABEL})*\.?")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MARKDOWN = re.compile(r"([\\`*_\[\]<>|~#])")


class ReportError(ValueError):
    pass


@dataclass(frozen=True)
class Item:
    host: str
    severity: Severity
    text: str


class ReportResult(BaseModel):
    report_path: str
    runs: int
    findings: int
    markdown: str
    truncated: bool = False


@dataclass
class Draft:
    markdown: str
    runs: int
    findings: int


def _clean(value: str) -> str:
    text = _CONTROL.sub("", " ".join(value.split()))
    return text[:MAX_VALUE] + "..." if len(text) > MAX_VALUE else text


def _fence(text: str, minimum: int) -> str:
    """Return a backtick fence longer than any backtick run in text."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(minimum, longest + 1)


def code(value: str) -> str:
    """Render untrusted text as a single-line inline code span."""
    text = _clean(value)
    if not text:
        return "(empty)"
    fence = _fence(text, 1)
    pad = " " if text[0] == "`" or text[-1] == "`" else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def escape(value: str) -> str:
    """Render untrusted text as single-line Markdown with special characters escaped."""
    return _MARKDOWN.sub(r"\\\1", _clean(value))


def parse_target(value: str) -> str:
    """Normalize a target filter: an ip, a cidr, or a domain and its subdomains."""
    value = value.strip().lower()
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        pass
    if not _DOMAIN.fullmatch(value):
        raise ReportError(f"invalid target {value!r}: expected a domain, ip or cidr")
    return value.removeprefix("*.").rstrip(".")


def host_of(value: str) -> str:
    """Return the lowercase host of a url, host[:port], ip or cidr."""
    value = value.strip()
    for parse in (ipaddress.ip_address, ipaddress.ip_network):
        try:
            return str(parse(value))
        except ValueError:
            continue
    parsed = urlsplit(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).lower().rstrip(".")


def host_matches(host: str, wanted: str) -> bool:
    """Check a host against a filter from parse_target."""
    try:
        network = ipaddress.ip_network(wanted)
    except ValueError:
        return host == wanted or host.endswith("." + wanted)
    try:
        candidate = ipaddress.ip_network(host, strict=False)
    except ValueError:
        return False
    return candidate.version == network.version and network.overlaps(candidate)


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def select_records(
    records: Iterable[AuditRecord],
    wanted: str | None,
    since: datetime | None,
    until: datetime | None,
) -> list[AuditRecord]:
    """Keep tool calls in the time range whose target matches the filter."""
    selected = []
    for record in records:
        if record.tool not in OUTPUT_SUFFIXES:
            continue
        moment = _utc(record.timestamp)
        if (since and moment < since) or (until and moment >= until):
            continue
        hosts = [host_of(token) for token in record.target.split()]
        if wanted is None or any(host_matches(host, wanted) for host in hosts):
            selected.append(record)
    return selected


def executed(record: AuditRecord) -> bool:
    return record.decision == "allowed" and not record.dry_run


def output_path(record: AuditRecord) -> Path | None:
    if record.raw_output_path is None:
        return None
    return Path(record.raw_output_path).with_suffix(OUTPUT_SUFFIXES[record.tool])


def read_output(path: Path, runs_dir: Path) -> bytes | None:
    """Read a saved output file, refusing paths outside runs_dir; None if missing."""
    # The audit log is only append-only by convention, so its paths are not trusted.
    if not path.resolve().is_relative_to(runs_dir.resolve()):
        raise ReportError("outside the runs directory, not read")
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ReportError(f"cannot read: {exc.strerror}") from None


def nmap_items(data: bytes, target: str) -> list[Item]:
    """Open ports, grouped under the scanned hostname when the target was one."""
    named = not _is_address(target)
    items = []
    for host in parse_nmap_xml(data).hosts:
        if host.state != "up":
            continue
        group = host_of(target) if named else host.address
        for port in host.ports:
            if port.state != "open":
                continue
            text = f"Open port {port.port}/{port.protocol} on {code(host.address)}"
            service = [port.service, port.product, port.version, port.extra_info]
            if any(service):
                text += f": {code(' '.join(part for part in service if part))}"
            if port.scripts:
                scripts = ", ".join(script.id for script in port.scripts)
                text += f", script output from {code(scripts)}"
            items.append(Item(group, "info", text))
    return items


def _is_address(target: str) -> bool:
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return True


def httpx_items(data: bytes) -> list[Item]:
    items = []
    for probe in parse_httpx_jsonl(data):
        if probe.failed:
            continue
        details = []
        if probe.status_code:
            details.append(f"status {probe.status_code}")
        if probe.title:
            details.append(f"title {code(probe.title)}")
        if probe.webserver:
            details.append(f"server {code(probe.webserver)}")
        if probe.tech:
            details.append(f"tech {code(', '.join(probe.tech))}")
        text = f"Web server at {code(probe.url)}"
        if details:
            text += ": " + ", ".join(details)
        items.append(Item(host_of(probe.url), "info", text))
    return items


def ffuf_items(data: bytes) -> list[Item]:
    items = []
    for match in parse_ffuf_json(data):
        text = (
            f"Content found at {code(match.url)} "
            f"(status {match.status}, {match.length} bytes)"
        )
        if match.redirect_location:
            text += f", redirects to {code(match.redirect_location)}"
        items.append(Item(host_of(match.url), "info", text))
    return items


def nuclei_items(data: bytes) -> list[Item]:
    items = []
    for finding in parse_nuclei_jsonl(data):
        location = finding.matched_at or finding.host
        text = (
            f"{escape(finding.name)} ({code(finding.template_id)}) at {code(location)}"
        )
        if finding.extracted_results:
            text += f", extracted {code(', '.join(finding.extracted_results[:5]))}"
        host = host_of(finding.host or finding.matched_at)
        items.append(Item(host, finding.severity, text))
    return items


def run_items(record: AuditRecord, data: bytes, wanted: str | None) -> list[Item]:
    """Parse a run's output into report items, dropping hosts outside the filter."""
    if record.tool == "nmap":
        # nmap takes one target, and the record already matched the filter.
        return nmap_items(data, record.target)
    parse = {"httpx": httpx_items, "ffuf": ffuf_items, "nuclei": nuclei_items}
    items = parse[record.tool](data)
    return [i for i in items if wanted is None or host_matches(i.host, wanted)]


def _when(moment: datetime) -> str:
    return f"{_utc(moment).astimezone(UTC):%Y-%m-%d %H:%M:%S} UTC"


def _status(record: AuditRecord) -> str:
    parts = [escape(record.reason)]
    if record.exit_code is not None:
        parts.append(f"exit {record.exit_code}")
    if record.duration_s is not None:
        parts.append(f"{record.duration_s:g} s")
    return ", ".join(parts)


def _summary(
    runs: list[AuditRecord],
    skipped: list[AuditRecord],
    findings: dict[Item, list[str]],
    period: str,
    target: str | None,
    now: datetime,
) -> list[str]:
    tools = Counter(record.tool for record in runs)
    severities = Counter(item.severity for item in findings)
    lines = [
        "## Summary",
        "",
        f"Draft generated {_when(now)} from the secmcp audit log.",
        "",
        f"- Period: {period}",
        f"- Target filter: {code(target) if target else 'none'}",
        f"- Tool runs: {len(runs)}"
        + (
            f" ({', '.join(f'{t} x{n}' for t, n in sorted(tools.items()))})"
            if runs
            else ""
        ),
    ]
    if skipped:
        blocked = sum(1 for record in skipped if record.decision == "blocked")
        lines.append(
            f"- Not listed: {blocked} calls refused by policy, "
            f"{len(skipped) - blocked} dry runs"
        )
    shown = ", ".join(f"{s} x{severities[s]}" for s in SEVERITY_ORDER if severities[s])
    hosts = len({item.host for item in findings})
    lines.append(
        f"- Findings: {len(findings)} on {hosts} host{'s' if hosts != 1 else ''} "
        f"({shown})"
        if findings
        else "- Findings: none"
    )
    return lines


def _scope(config: Config, runs: list[AuditRecord]) -> list[str]:
    lines = ["## Scope", "", "Targets tested:", ""]
    targets = dict.fromkeys(record.target for record in runs)
    lines += [f"- {code(target)}" for target in targets] or ["- none"]
    lines += ["", "In scope according to scope.yaml:", ""]
    lines += [f"- {code(entry)}" for entry in config.allow]
    if config.exclude:
        lines += ["", "Excluded:", ""]
        lines += [f"- {code(entry)}" for entry in config.exclude]
    return lines


def _methodology(runs: list[AuditRecord]) -> list[str]:
    lines = [
        "## Methodology",
        "",
        "Every tool ran through secmcp, which checked each target against the scope "
        "file and each flag against a per-tool allowlist before running it. "
        "Commands, in order:",
        "",
    ]
    if not runs:
        return [*lines, "No tools were run in this period."]
    for number, record in enumerate(runs, 1):
        command = shlex.join(record.argv)
        fence = _fence(command, 3)
        lines += [
            f"{number}. {_when(record.timestamp)}, {record.tool} against "
            f"{code(record.target)}: {_status(record)}",
            "",
            f"   {fence}sh",
            f"   {command}",
            f"   {fence}",
            "",
        ]
    return lines[:-1]


def _rank(host: str, findings: dict[Item, list[str]]) -> tuple[int, str]:
    worst = min(SEVERITY_ORDER.index(i.severity) for i in findings if i.host == host)
    return worst, host


def _findings(findings: dict[Item, list[str]]) -> list[str]:
    lines = ["## Findings", ""]
    if not findings:
        return [*lines, "No findings were parsed from the selected runs."]
    hosts = sorted({item.host for item in findings}, key=lambda h: _rank(h, findings))
    for host in hosts:
        lines += [f"### {code(host)}", ""]
        for severity in SEVERITY_ORDER:
            items = [i for i in findings if i.host == host and i.severity == severity]
            if not items:
                continue
            lines += [f"**{severity.capitalize()}**", ""]
            for item in items:
                evidence = ", ".join(code(path) for path in findings[item])
                lines += [f"- {item.text}  ", f"  Evidence: {evidence}"]
            lines.append("")
    return lines[:-1]


def _evidence(runs: list[AuditRecord], problems: list[tuple[Path, str]]) -> list[str]:
    lines = ["## Evidence", "", "Raw and parsed output saved by secmcp:", ""]
    for record in runs:
        files = []
        output = output_path(record)
        if output is not None:
            files.append(f"output {code(str(output))}")
        if record.raw_output_path is not None:
            files.append(f"raw log {code(record.raw_output_path)}")
        listed = ", ".join(files) or "no files saved"
        lines.append(f"- {_when(record.timestamp)}, {record.tool}: {listed}")
    if not runs:
        lines.append("- none")
    if problems:
        lines += ["", "Not included in the findings:", ""]
        lines += [f"- {code(str(path))}: {escape(error)}" for path, error in problems]
    return lines


def _period(since: datetime | None, until: datetime | None) -> str:
    if since and until:
        return f"{_when(since)} to {_when(until)}"
    if since:
        return f"from {_when(since)}"
    if until:
        return f"until {_when(until)}"
    return "all records"


def build_report(
    config: Config,
    target: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    now: datetime | None = None,
) -> Draft:
    """Build a report draft for the target and time range; until is exclusive."""
    wanted = parse_target(target) if target else None
    since = _utc(since) if since else None
    until = _utc(until) if until else None
    if since and until and since >= until:
        raise ReportError("since must be earlier than until")
    selected = select_records(iter_records(config.audit_log_path), wanted, since, until)
    runs = [record for record in selected if executed(record)]
    findings: dict[Item, list[str]] = {}
    problems: list[tuple[Path, str]] = []
    for record in runs:
        path = output_path(record)
        if path is None:
            continue
        try:
            data = read_output(path, config.runs_dir)
            items = run_items(record, data, wanted) if data is not None else []
        except ReportError as exc:
            problems.append((path, str(exc)))
            continue
        except PARSE_ERRORS as exc:
            problems.append((path, str(exc)))
            continue
        for item in items:
            evidence = findings.setdefault(item, [])
            if str(path) not in evidence:
                evidence.append(str(path))
    skipped = [record for record in selected if not executed(record)]
    title = (
        f"Security testing report: {target}" if target else "Security testing report"
    )
    sections = [
        [f"# {escape(title)} (draft)"],
        _summary(
            runs,
            skipped,
            findings,
            _period(since, until),
            target,
            now or datetime.now(UTC),
        ),
        _scope(config, runs),
        _methodology(runs),
        _findings(findings),
        _evidence(runs, problems),
        ["## Impact"],
        ["## Remediation"],
    ]
    markdown = "\n\n".join("\n".join(section) for section in sections) + "\n"
    return Draft(markdown=markdown, runs=len(runs), findings=len(findings))


def save_report(config: Config, markdown: str) -> Path:
    """Write a report under data_dir/reports and return its path."""
    reports = config.data_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = (
        reports / f"report-{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}.md"
    )
    path.touch(mode=0o600)
    path.write_text(markdown, encoding="utf-8")
    return path


def write_report(
    config: Config,
    target: str | None,
    since: datetime | None,
    until: datetime | None,
) -> ReportResult:
    """Build and save a report draft, returning a capped copy of the markdown."""
    draft = build_report(config, target, since, until)
    path = save_report(config, draft.markdown)
    result = ReportResult(
        report_path=str(path),
        runs=draft.runs,
        findings=draft.findings,
        markdown=draft.markdown,
    )
    if len(draft.markdown) > config.max_output_bytes:
        result.markdown = (
            draft.markdown[: config.max_output_bytes]
            + f"\n\n[report truncated, full draft in {path}]\n"
        )
        result.truncated = True
    append_record(
        config.audit_log_path,
        AuditRecord(
            tool="generate_report",
            target=target or "*",
            decision="allowed",
            reason=f"report written with {draft.runs} runs, {draft.findings} findings",
            raw_output_path=str(path),
        ),
    )
    return result
