import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from secmcp.audit import AuditRecord, append_record, read_records
from secmcp.config import Config
from secmcp.report import (
    ReportError,
    build_report,
    code,
    escape,
    host_matches,
    host_of,
    parse_target,
    write_report,
)
from tests.helpers import FIXTURES

T0 = datetime(2026, 11, 24, 10, 0, tzinfo=UTC)


def nuclei_line(template: str, severity: str, host: str, matched: str) -> str:
    return json.dumps(
        {
            "template-id": template,
            "info": {"name": f"{template} check", "severity": severity},
            "type": "http",
            "host": host,
            "matched-at": matched,
        }
    )


def httpx_line(url: str, title: str) -> str:
    return json.dumps(
        {"input": url, "url": url, "status_code": 200, "title": title, "tech": []}
    )


def add_run(
    config: Config,
    tool: str,
    target: str,
    output: bytes | None,
    suffix: str,
    hour: int = 10,
    **fields: Any,
) -> Path:
    run_id = f"{tool}-{hour:02d}-{len(read_records(config.audit_log_path, 1000))}"
    log = config.runs_dir / f"{run_id}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("tool output\n")
    out = log.with_suffix(suffix)
    if output is not None:
        out.write_bytes(output)
    record = {
        "timestamp": T0.replace(hour=hour),
        "tool": tool,
        "target": target,
        "argv": [tool, "-o", str(out), target],
        "decision": "allowed",
        "reason": "scan completed",
        "exit_code": 0,
        "duration_s": 2.5,
        "raw_output_path": str(log),
    }
    append_record(config.audit_log_path, AuditRecord.model_validate(record | fields))
    return out


def nmap_run(config: Config, target: str = "www.example.com", **fields: Any) -> Path:
    data = (FIXTURES / "nmap_service_version.xml").read_bytes()
    return add_run(config, "nmap", target, data, ".xml", **fields)


def nuclei_run(config: Config, lines: list[str], target: str, **fields: Any) -> Path:
    data = "\n".join(lines).encode()
    return add_run(config, "nuclei", target, data, ".jsonl", **fields)


@pytest.mark.parametrize(
    ("value", "host"),
    [
        ("https://WWW.Example.com:8443/a?b", "www.example.com"),
        ("api.example.com:443", "api.example.com"),
        ("example.com.", "example.com"),
        ("203.0.113.10", "203.0.113.10"),
        ("203.0.113.0/24", "203.0.113.0/24"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("http://[2001:db8::1]/", "2001:db8::1"),
    ],
)
def test_host_of(value: str, host: str) -> None:
    assert host_of(value) == host


@pytest.mark.parametrize(
    ("host", "wanted", "expected"),
    [
        ("example.com", "example.com", True),
        ("api.example.com", "example.com", True),
        ("notexample.com", "example.com", False),
        ("example.com.evil.net", "example.com", False),
        ("203.0.113.10", "203.0.113.0/24", True),
        ("203.0.113.0/28", "203.0.113.0/24", True),
        ("198.51.100.7", "203.0.113.0/24", False),
        ("2001:db8::1", "203.0.113.0/24", False),
        ("www.example.com", "203.0.113.0/24", False),
        ("203.0.113.10", "example.com", False),
    ],
)
def test_host_matches(host: str, wanted: str, expected: bool) -> None:
    assert host_matches(host, parse_target(wanted)) is expected


def test_parse_target() -> None:
    assert parse_target("*.Example.com") == "example.com"
    assert parse_target("203.0.113.10") == "203.0.113.10/32"
    for bad in ("", "exa mple.com", "https://example.com", "-oX"):
        with pytest.raises(ReportError, match="invalid target"):
            parse_target(bad)


def test_code_and_escape_keep_tool_output_inert() -> None:
    assert code("a`b") == "``a`b``"
    assert code("`x`") == "`` `x` ``"
    assert code("line1\nline2\x1b[31m") == "`line1 line2[31m`"
    assert code("") == "(empty)"
    assert code("x" * 400).endswith("...`")
    assert escape("[click](http://evil) <img> # *") == (
        r"\[click\](http://evil) \<img\> \# \*"
    )


def test_report_sections_and_order(config: Config) -> None:
    nmap_run(config)
    nuclei_run(
        config,
        [
            nuclei_line(
                "tech-detect", "info", "www.example.com", "https://www.example.com"
            ),
            nuclei_line(
                "cve-x", "high", "www.example.com", "https://www.example.com/x"
            ),
        ],
        "https://www.example.com",
        hour=11,
    )
    markdown = build_report(config, now=T0).markdown

    headings = [line for line in markdown.splitlines() if line.startswith("## ")]
    assert headings == [
        "## Summary",
        "## Scope",
        "## Methodology",
        "## Findings",
        "## Evidence",
        "## Impact",
        "## Remediation",
    ]
    assert markdown.startswith("# Security testing report (draft)\n")
    assert markdown.endswith("## Impact\n\n## Remediation\n")
    assert "- Tool runs: 2 (nmap x1, nuclei x1)" in markdown
    assert "- Findings: 5 on 1 host (high x1, info x4)" in markdown
    assert "- `*.example.com`" in markdown


def test_methodology_lists_commands_in_order(config: Config) -> None:
    xml = nmap_run(config, hour=12)
    nuclei_run(config, [], "https://www.example.com", hour=13)
    markdown = build_report(config).markdown

    methodology = markdown.split("## Methodology")[1].split("## Findings")[0]
    assert "1. 2026-11-24 12:00:00 UTC, nmap against `www.example.com`" in methodology
    assert "scan completed, exit 0, 2.5 s" in methodology
    assert f"   nmap -o {xml} www.example.com" in methodology
    assert methodology.index("1. ") < methodology.index("2. ")


def test_findings_grouped_by_host_and_severity(config: Config) -> None:
    xml = nmap_run(config)
    jsonl = nuclei_run(
        config,
        [
            nuclei_line(
                "low-one", "low", "api.example.com", "https://api.example.com/"
            ),
            nuclei_line(
                "crit-one", "critical", "api.example.com", "https://api.example.com/a"
            ),
        ],
        "https://api.example.com",
    )
    markdown = build_report(config).markdown
    findings = markdown.split("## Findings")[1].split("## Evidence")[0]

    assert findings.index("### `api.example.com`") < findings.index(
        "### `www.example.com`"
    )
    api = findings.split("### `www.example.com`")[0]
    assert api.index("**Critical**") < api.index("**Low**")
    assert "crit-one check (`crit-one`) at `https://api.example.com/a`" in api
    assert f"Evidence: `{jsonl}`" in api
    www = findings.split("### `www.example.com`")[1]
    assert "Open port 22/tcp on `203.0.113.10`: `ssh OpenSSH" in www
    assert "3306" not in www
    assert f"Evidence: `{xml}`" in www


def test_target_filter_drops_other_targets_and_hosts(config: Config) -> None:
    nmap_run(config, target="198.51.100.7")
    nuclei_run(
        config,
        [
            nuclei_line("a", "medium", "app.example.com", "https://app.example.com/"),
            nuclei_line("b", "medium", "other.test", "https://other.test/"),
        ],
        "https://app.example.com https://other.test",
    )
    draft = build_report(config, target="example.com")

    assert draft.runs == 1
    assert draft.findings == 1
    assert "app.example.com" in draft.markdown
    assert "`other.test`" not in draft.markdown.split("## Findings")[1]
    assert (
        "198.51.100.7`" not in draft.markdown.split("## Scope")[1].split("In scope")[0]
    )


def test_ip_target_filter(config: Config) -> None:
    nmap_run(config, target="203.0.113.10")
    nmap_run(config, target="198.51.100.7")
    draft = build_report(config, target="203.0.113.0/24")
    assert draft.runs == 1
    assert "### `203.0.113.10`" in draft.markdown


def test_time_range(config: Config) -> None:
    for hour in (9, 10, 11):
        nmap_run(config, hour=hour)
    draft = build_report(config, since=T0, until=T0.replace(hour=11))
    assert draft.runs == 1
    assert "2026-11-24 10:00:00 UTC to 2026-11-24 11:00:00 UTC" in draft.markdown
    naive = build_report(config, since=datetime(2026, 11, 24, 10, 30))
    assert naive.runs == 1
    with pytest.raises(ReportError, match="earlier"):
        build_report(config, since=T0, until=T0)


def test_blocked_and_dry_runs_are_counted_not_listed(config: Config) -> None:
    nmap_run(config)
    add_run(config, "nmap", "www.example.com", None, ".xml", dry_run=True)
    add_run(config, "nmap", "evil.test", None, ".xml", decision="blocked")
    add_run(config, "check_scope", "www.example.com", None, ".x")
    draft = build_report(config)
    assert draft.runs == 1
    assert "- Not listed: 1 calls refused by policy, 1 dry runs" in draft.markdown
    assert "evil.test" not in draft.markdown


def test_duplicate_findings_merge_evidence(config: Config) -> None:
    first = nmap_run(config, hour=10)
    second = nmap_run(config, hour=11)
    draft = build_report(config)
    assert draft.findings == 3
    assert f"Evidence: `{first}`, `{second}`" in draft.markdown


def test_output_outside_runs_dir_is_not_read(config: Config, tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere" / "nmap-1.log"
    outside.parent.mkdir()
    outside.with_suffix(".xml").write_bytes(
        (FIXTURES / "nmap_service_version.xml").read_bytes()
    )
    append_record(
        config.audit_log_path,
        AuditRecord(
            tool="nmap",
            target="www.example.com",
            decision="allowed",
            reason="scan completed",
            exit_code=0,
            raw_output_path=str(outside),
        ),
    )
    draft = build_report(config)
    assert draft.findings == 0
    assert (
        f"`{outside.with_suffix('.xml')}`: outside the runs directory" in draft.markdown
    )


def test_unparseable_and_missing_output(config: Config) -> None:
    broken = add_run(config, "nmap", "www.example.com", b"<nope", ".xml")
    add_run(config, "ffuf", "https://www.example.com/FUZZ", None, ".json")
    draft = build_report(config)
    assert draft.runs == 2
    assert draft.findings == 0
    assert f"`{broken}`: invalid nmap xml" in draft.markdown


def test_web_tool_output_is_escaped(config: Config) -> None:
    title = "x](http://evil.test)\n# injected <script>"
    add_run(
        config,
        "httpx",
        "https://www.example.com",
        httpx_line("https://www.example.com", title).encode(),
        ".jsonl",
    )
    markdown = build_report(config).markdown
    assert "title `x](http://evil.test) # injected <script>`" in markdown
    assert "\n# injected" not in markdown


def test_ffuf_matches(config: Config) -> None:
    add_run(
        config,
        "ffuf",
        "https://www.example.com/FUZZ",
        (FIXTURES / "ffuf_results.json").read_bytes(),
        ".json",
    )
    markdown = build_report(config).markdown
    assert "Content found at `http://127.0.0.1:18080/admin` (status 301" in markdown


def test_write_report_saves_audits_and_caps(config: Config) -> None:
    nmap_run(config)
    small = config.model_copy(update={"max_output_bytes": 1000})
    result = write_report(small, "example.com", None, None)

    saved = Path(result.report_path)
    assert saved.parent == config.data_dir / "reports"
    assert saved.stat().st_mode & 0o777 == 0o600
    assert saved.read_text().endswith("## Remediation\n")
    assert result.truncated
    assert result.markdown.endswith(f"[report truncated, full draft in {saved}]\n")
    last = read_records(config.audit_log_path, 1)[0]
    assert (last.tool, last.target) == ("generate_report", "example.com")
    assert last.raw_output_path == str(saved)
    assert build_report(config).runs == 1
