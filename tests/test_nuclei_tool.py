from pathlib import Path

import pytest

from secmcp.audit import read_records
from secmcp.config import Config
from secmcp.parsers.nuclei_jsonl import (
    NucleiParseError,
    parse_nuclei_jsonl,
    summarize,
)
from secmcp.tools import common
from secmcp.tools.nuclei import DANGEROUS_TAGS, run_nuclei
from tests.helpers import FIXTURES, FakeRunner, make_ctx

pytestmark = pytest.mark.anyio

FINDINGS = (FIXTURES / "nuclei_findings.jsonl").read_bytes()


@pytest.fixture(autouse=True)
def _nuclei_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(common, "find_binary", lambda name: "/usr/bin/nuclei")


def value_of(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def test_parse_findings_fixture() -> None:
    findings = parse_nuclei_jsonl(FINDINGS)
    robots, server = findings
    assert (robots.template_id, robots.severity) == ("robots-txt-endpoint", "info")
    assert robots.matched_at == "http://127.0.0.1:18080/robots.txt"
    assert robots.extracted_results == ["User-agent: *"]
    assert server.tags == ["exposure", "python"]
    assert summarize(findings) == "2 findings (low x1, info x1)"
    assert summarize([]) == "no findings"


@pytest.mark.parametrize("data", [b"nope\n", b'{"info": {}}\n', b"[1]\n"])
def test_parse_rejects_bad_output(data: bytes) -> None:
    with pytest.raises(NucleiParseError, match="line 1"):
        parse_nuclei_jsonl(data)


async def test_dry_run_excludes_dangerous_tags_by_default(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nuclei(
        ctx,
        ["https://www.example.com"],
        severity=["high", "critical", "high"],
        tags=["cve", "exposure"],
        dry_run=True,
    )
    assert result.status == "dry_run"
    assert result.approval_required == []
    assert runner.calls == []
    argv = result.argv
    for flag in ("-ni", "-dr", "-duc", "-no-stdin"):
        assert flag in argv
    assert value_of(argv, "-etags").split(",") == list(DANGEROUS_TAGS)
    assert value_of(argv, "-s") == "high,critical"
    assert value_of(argv, "-tags") == "cve,exposure"
    assert value_of(argv, "-rl") == "50"
    # The test scope allows 10.0.5.0/24, so local network access stays possible.
    assert "-lna" not in argv


async def test_public_only_scope_restricts_local_network(config: Config) -> None:
    ctx, _ = make_ctx(config, allow=["*.example.com", "203.0.113.0/24"])
    result = await run_nuclei(ctx, ["https://www.example.com"], dry_run=True)
    assert "-lna" in result.argv


async def test_scan_parses_findings(config: Config) -> None:
    ctx, runner = make_ctx(config, runner=FakeRunner(output=FINDINGS))
    result = await run_nuclei(
        ctx,
        ["https://www.example.com", "203.0.113.10:8443"],
        template_ids=["CVE-2021-44228"],
        exclude_tags=["wordpress"],
        extra_args=["-pt", "http,ssl", "-timeout", "5"],
    )
    assert result.status == "completed"
    assert runner.calls == [result.argv]
    assert Path(value_of(result.argv, "-l")).read_text() == (
        "https://www.example.com\n203.0.113.10:8443\n"
    )
    assert value_of(result.argv, "-id") == "CVE-2021-44228"
    assert value_of(result.argv, "-etags").endswith(",wordpress")
    assert result.argv[-4:] == ["-pt", "http,ssl", "-timeout", "5"]
    assert result.summary == "2 findings (low x1, info x1)"
    record = read_records(config.audit_log_path, 1)[0]
    assert (record.tool, record.decision) == ("nuclei", "allowed")


async def test_dangerous_tags_need_config_and_confirm(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nuclei(
        ctx, ["https://www.example.com"], tags=["intrusive", "cve"], confirm=True
    )
    assert result.status == "needs_approval"
    assert result.approval_required == [
        "tag intrusive (may change state on the target)"
    ]
    assert "allow_dangerous: true" in result.reason
    assert runner.calls == []

    ctx, runner = make_ctx(
        config, runner=FakeRunner(output=FINDINGS), allow_dangerous=True
    )
    result = await run_nuclei(ctx, ["https://www.example.com"], tags=["intrusive"])
    assert result.status == "needs_approval"
    assert result.reason == "needs human approval: requires confirm=true on the call"
    assert runner.calls == []

    result = await run_nuclei(
        ctx, ["https://www.example.com"], tags=["intrusive"], confirm=True
    )
    assert result.status == "completed"
    excluded = value_of(result.argv, "-etags").split(",")
    assert "intrusive" not in excluded
    assert "dos" in excluded
    assert len(runner.calls) == 1


async def test_approval_does_not_unlock_unrequested_tags(config: Config) -> None:
    ctx, _ = make_ctx(config, allow_dangerous=True)
    result = await run_nuclei(
        ctx, ["https://www.example.com"], tags=["cve"], confirm=True, dry_run=True
    )
    assert value_of(result.argv, "-etags").split(",") == list(DANGEROUS_TAGS)


async def test_out_of_scope_target_blocks_call(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nuclei(ctx, ["https://www.example.com", "http://8.8.8.8"])
    assert result.status == "blocked"
    assert "8.8.8.8 is not in scope" in result.reason
    assert runner.calls == []


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"tags": ["cve,intrusive"]}, "invalid tag 'cve,intrusive'"),
        ({"tags": ["../x"]}, "invalid tag"),
        ({"exclude_tags": ["-itags"]}, "invalid tag"),
        ({"template_ids": ["/etc/passwd"]}, "invalid template id"),
        ({"rate_limit": 500}, "rate_limit must be from 1 to 50"),
    ],
)
async def test_argument_checks(
    config: Config, kwargs: dict[str, object], reason: str
) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nuclei(ctx, ["https://www.example.com"], **kwargs)  # type: ignore[arg-type]
    assert result.status == "blocked"
    assert reason in result.reason
    assert runner.calls == []


@pytest.mark.parametrize(
    ("extra_args", "reason"),
    [
        (["-t", "/tmp/evil.yaml"], "installed template set"),
        (["-turl", "https://evil.com/t.yaml"], "installed template set"),
        (["-itags", "intrusive"], "dangerous tags need approval"),
        (["-etags", "none"], "use the exclude_tags argument"),
        (["-code"], "code, file, headless and dast templates"),
        (["-dast"], "code, file, headless and dast templates"),
        (["-lfa"], "local file access is not allowed"),
        (["-esc"], "outside scope"),
        (["-u", "evil.com"], "targets come only from the targets argument"),
        (["-list", "hosts.txt"], "targets come only from the targets argument"),
        (["-uc", "-uq", "org:x"], "uncover adds targets"),
        (["-fr"], "redirects can leave scope"),
        (["-iserver", "oast.me"], "interactsh is disabled"),
        (["-pd"], "uploading results is not allowed"),
        (["-ev"], "environment variables"),
        (["-o", "/tmp/x"], "output paths are set by secmcp"),
        (["-pt", "code"], "expected a comma-separated list of dns"),
        (["-H", "X:1"], "custom headers are not supported"),
    ],
)
async def test_flag_policy(config: Config, extra_args: list[str], reason: str) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nuclei(ctx, ["https://www.example.com"], extra_args=extra_args)
    assert result.status == "blocked"
    assert reason in result.reason
    assert runner.calls == []


async def test_timeout_is_reported(config: Config) -> None:
    ctx, _ = make_ctx(config, runner=FakeRunner(output=b"", timed_out=True))
    result = await run_nuclei(ctx, ["https://www.example.com"])
    assert result.status == "timed_out"
    assert read_records(config.audit_log_path, 1)[0].timed_out
