from pathlib import Path

import pytest

from secmcp.audit import read_records
from secmcp.config import Config
from secmcp.parsers.httpx_json import HttpxParseError, parse_httpx_jsonl, summarize
from secmcp.tools import common
from secmcp.tools.httpx import run_httpx
from tests.helpers import FIXTURES, FakeRunner, make_ctx

pytestmark = pytest.mark.anyio

PROBES = (FIXTURES / "httpx_probe.jsonl").read_bytes()


@pytest.fixture(autouse=True)
def _httpx_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(common, "find_binary", lambda name: "/usr/bin/httpx")


def test_parse_probe_fixture() -> None:
    probes = parse_httpx_jsonl(PROBES)
    failed, alive = probes
    assert failed.failed
    assert failed.status_code is None
    assert "connection refused" in (failed.error or "")
    assert (alive.url, alive.status_code, alive.title) == (
        "http://127.0.0.1:18080",
        200,
        "Test Page",
    )
    assert alive.tech == ["Python:3.13.18", "SimpleHTTP:0.6"]
    assert alive.host_ip == "127.0.0.1"
    assert summarize(probes) == "1 of 2 targets responded (200 x1)"


def test_parse_rejects_garbage() -> None:
    with pytest.raises(HttpxParseError, match="line 2"):
        parse_httpx_jsonl(b'{"input": "a", "url": "b"}\nnot json\n')


async def test_dry_run_shows_argv_with_rate_and_denylist(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_httpx(
        ctx, ["https://www.example.com/login", "203.0.113.10:8080"], dry_run=True
    )
    assert result.status == "dry_run"
    assert runner.calls == []
    argv = result.argv
    assert argv[:2] == ["/usr/bin/httpx", "-l"]
    assert argv[argv.index("-rl") + 1] == "50"
    deny = argv[argv.index("-deny") + 1].split(",")
    assert {"203.0.113.66/32", "169.254.169.254", "127.0.0.0/8"} <= set(deny)
    assert "-fr" not in argv
    assert not Path(argv[2]).exists()


async def test_probe_writes_checked_targets_and_parses_output(config: Config) -> None:
    ctx, runner = make_ctx(config, runner=FakeRunner(output=PROBES))
    result = await run_httpx(
        ctx, ["HTTPS://WWW.example.com/a,b", "203.0.113.10"], rate_limit=5
    )
    assert result.status == "completed"
    assert runner.calls == [result.argv]
    list_path = Path(result.argv[2])
    # Written to a list file so commas cannot split one target into two.
    assert list_path.read_text() == "https://www.example.com/a,b\n203.0.113.10\n"
    assert result.argv[result.argv.index("-rl") + 1] == "5"
    assert result.summary == "1 of 2 targets responded (200 x1)"
    record = read_records(config.audit_log_path, 1)[0]
    assert record.tool == "httpx"
    assert record.target == "HTTPS://WWW.example.com/a,b 203.0.113.10"
    assert record.decision == "allowed"


async def test_any_out_of_scope_target_blocks_the_call(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_httpx(ctx, ["www.example.com", "https://admin.example.com"])
    assert result.status == "blocked"
    assert "admin.example.com is excluded" in result.reason
    assert runner.calls == []
    assert read_records(config.audit_log_path, 1)[0].decision == "blocked"


@pytest.mark.parametrize(
    ("extra_args", "reason"),
    [
        (["-fr"], "redirects can leave scope"),
        (["-follow-redirects"], "redirects can leave scope"),
        (["-l", "/etc/hosts"], "targets come only from the targets argument"),
        (["-list", "/etc/hosts"], "targets come only from the targets argument"),
        (["-u", "evil.com"], "targets come only from the targets argument"),
        (["-o", "/tmp/x"], "output paths are set by secmcp"),
        (["-r", "8.8.8.8"], "custom resolvers"),
        (["-proxy", "http://127.0.0.1:8080"], "proxies are not allowed"),
        (["-tls-probe"], "certificates can leave scope"),
        (["-path", "/etc/passwd"], "put the path in the target url"),
        (["-rl", "1000"], "use the rate_limit argument"),
        (["-x", "all"], "expected a comma-separated list of GET, HEAD, OPTIONS"),
        (["-x", "DELETE"], "expected a comma-separated list"),
        (["-mc", "200;id"], "shell metacharacters"),
        (["-mc", "999"], "expected values from 100 to 599"),
        (["-H", "Host: evil.com"], "unknown flag -H"),
        (["evil.com"], "extra targets are not allowed"),
    ],
)
async def test_flag_policy(config: Config, extra_args: list[str], reason: str) -> None:
    ctx, runner = make_ctx(config)
    result = await run_httpx(ctx, ["www.example.com"], extra_args=extra_args)
    assert result.status == "blocked"
    assert reason in result.reason
    assert runner.calls == []


async def test_allowed_flags_pass_through(config: Config) -> None:
    ctx, _ = make_ctx(config)
    result = await run_httpx(
        ctx,
        ["www.example.com"],
        extra_args=["-location", "-lc", "-p", "80,8080", "-mc", "200,301-302"],
        dry_run=True,
    )
    assert result.status == "dry_run"
    assert result.argv[-6:] == [
        "-location",
        "-lc",
        "-p",
        "80,8080",
        "-mc",
        "200,301-302",
    ]


async def test_rate_limit_above_cap_is_refused(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_httpx(ctx, ["www.example.com"], rate_limit=51)
    assert runner.calls == []
    assert result.status == "blocked"
    assert result.reason == "rate_limit must be from 1 to 50, the cap set in scope.yaml"


async def test_missing_binary_and_configured_path(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def which(name: str) -> None:
        seen.append(name)

    monkeypatch.setattr(common, "find_binary", which)
    ctx, _ = make_ctx(config, binaries={"httpx": Path("/opt/pd/httpx")})
    result = await run_httpx(ctx, ["www.example.com"])
    assert result.status == "missing_binary"
    assert "python httpx cli is a different tool" in result.reason
    assert seen == ["/opt/pd/httpx"]


async def test_failed_exit_keeps_output(config: Config) -> None:
    ctx, _ = make_ctx(config, runner=FakeRunner(output=b"", exit_code=2))
    result = await run_httpx(ctx, ["www.example.com"])
    assert result.status == "failed"
    assert result.reason == "httpx exited 2"
    assert result.output == "tool output\n"
