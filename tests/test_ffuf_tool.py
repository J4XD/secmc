from pathlib import Path

import pytest

from secmcp.audit import read_records
from secmcp.config import Config, RateLimits
from secmcp.parsers.ffuf_json import FfufParseError, parse_ffuf_json, summarize
from secmcp.tools import common
from secmcp.tools.ffuf import run_ffuf
from tests.helpers import FIXTURES, FakeRunner, make_ctx

pytestmark = pytest.mark.anyio

RESULTS = (FIXTURES / "ffuf_results.json").read_bytes()


@pytest.fixture(autouse=True)
def _ffuf_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(common, "find_binary", lambda name: "/usr/bin/ffuf")


@pytest.fixture
def lists(tmp_path: Path) -> Path:
    directory = tmp_path / "lists"
    directory.mkdir()
    (directory / "common.txt").write_text("admin\nrobots.txt\n")
    return directory


@pytest.fixture
def ffuf_config(config: Config, lists: Path) -> Config:
    return config.model_copy(update={"wordlist_dirs": [lists]})


def test_parse_results_fixture() -> None:
    matches = parse_ffuf_json(RESULTS)
    assert [match.word for match in matches] == ["admin", "robots.txt", "index.html"]
    admin = matches[0]
    assert (admin.status, admin.redirect_location) == (301, "/admin/")
    assert matches[1].content_type == "text/plain"
    assert summarize(matches) == "3 matches (200 x2, 301 x1)"
    assert summarize([]) == "no matches"


@pytest.mark.parametrize("data", [b"not json", b'{"results": [{"url": "x"}]}', b"[]"])
def test_parse_rejects_bad_output(data: bytes) -> None:
    with pytest.raises(FfufParseError):
        parse_ffuf_json(data)


async def test_dry_run_argv(ffuf_config: Config, lists: Path) -> None:
    ctx, runner = make_ctx(ffuf_config)
    result = await run_ffuf(
        ctx, "https://WWW.example.com/FUZZ", "common.txt", dry_run=True
    )
    assert result.status == "dry_run"
    assert runner.calls == []
    json_path = result.argv[6]
    assert result.argv == [
        "/usr/bin/ffuf",
        "-u",
        "https://www.example.com/FUZZ",
        "-w",
        str(lists.resolve() / "common.txt"),
        "-o",
        json_path,
        "-of",
        "json",
        "-noninteractive",
        "-s",
        "-rate",
        "50",
    ]


async def test_run_parses_matches(ffuf_config: Config, lists: Path) -> None:
    ctx, runner = make_ctx(ffuf_config, runner=FakeRunner(output=RESULTS))
    result = await run_ffuf(
        ctx,
        "https://www.example.com/app/FUZZ",
        str(lists / "common.txt"),
        rate_limit=10,
        extra_args=["-mc", "200,301", "-e", ".php,.bak", "-ac"],
    )
    assert result.status == "completed"
    assert runner.calls == [result.argv]
    assert result.argv[-6:] == ["10", "-mc", "200,301", "-e", ".php,.bak", "-ac"]
    assert len(result.matches) == 3
    assert result.summary == "3 matches (200 x2, 301 x1)"
    record = read_records(ffuf_config.audit_log_path, 1)[0]
    assert (record.tool, record.decision) == ("ffuf", "allowed")


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://evil.com/FUZZ", "evil.com is not in scope"),
        ("www.example.com/FUZZ", "expected a url starting with http"),
        ("https://FUZZ.example.com/", "FUZZ is only allowed in the path or query"),
        ("https://www.example.com/admin", "must contain FUZZ"),
        ("https://www.example.com:FUZZ/", "FUZZ is only allowed in the path"),
        ("https://www.example.com:99999/FUZZ", "invalid port"),
    ],
)
async def test_url_checks(ffuf_config: Config, url: str, reason: str) -> None:
    ctx, runner = make_ctx(ffuf_config)
    result = await run_ffuf(ctx, url, "common.txt")
    assert result.status == "blocked"
    assert reason in result.reason
    assert runner.calls == []


async def test_wordlist_must_be_inside_allowed_dirs(
    ffuf_config: Config, lists: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "secret.txt"
    outside.write_text("x\n")
    (lists / "link.txt").symlink_to(outside)
    ctx, runner = make_ctx(ffuf_config)
    url = "https://www.example.com/FUZZ"
    cases = {
        str(outside): "outside the allowed wordlist_dirs",
        "../secret.txt": "outside the allowed wordlist_dirs",
        "link.txt": "outside the allowed wordlist_dirs",
        "missing.txt": "not found in the allowed wordlist_dirs",
        "common.txt:HOST": "must not contain ':'",
        "common.txt;id": "shell metacharacters",
    }
    for wordlist, reason in cases.items():
        result = await run_ffuf(ctx, url, wordlist)
        assert result.status == "blocked", wordlist
        assert reason in result.reason, wordlist
    assert runner.calls == []


async def test_no_wordlist_dirs_configured(config: Config) -> None:
    ctx, _ = make_ctx(config)
    result = await run_ffuf(ctx, "https://www.example.com/FUZZ", "/etc/passwd")
    assert result.reason == "no wordlist_dirs are configured in scope.yaml"


@pytest.mark.parametrize(
    ("extra_args", "reason"),
    [
        (["-input-cmd", "id"], "running commands is not allowed"),
        (["-input-shell", "sh"], "running commands is not allowed"),
        (["-w", "/etc/passwd"], "use the wordlist argument"),
        (["-u", "https://evil.com/FUZZ"], "use the url argument"),
        (["-request", "req.txt"], "raw request files are not allowed"),
        (["-r"], "redirects can leave scope"),
        (["-x", "http://127.0.0.1:8080"], "proxies are not allowed"),
        (["-H", "Host:evil.com"], "custom headers"),
        (["-o", "/tmp/out"], "output paths are set by secmcp"),
        (["-rate", "9999"], "use the rate_limit argument"),
        (["-X", "DELETE"], "expected a comma-separated list of GET, HEAD, OPTIONS"),
        (["-mc", "all"], ""),
        (["-e", "php;id"], "shell metacharacters"),
        (["-recursion-depth", "50"], "expected an integer from 1 to 5"),
    ],
)
async def test_flag_policy(
    ffuf_config: Config, extra_args: list[str], reason: str
) -> None:
    ctx, runner = make_ctx(ffuf_config)
    result = await run_ffuf(
        ctx,
        "https://www.example.com/FUZZ",
        "common.txt",
        extra_args=extra_args,
        dry_run=not reason,
    )
    if not reason:
        assert result.status == "dry_run"
        return
    assert result.status == "blocked"
    assert reason in result.reason
    assert runner.calls == []


async def test_rate_limit_cap(ffuf_config: Config) -> None:
    ctx, runner = make_ctx(ffuf_config, rate_limits=RateLimits(ffuf=5))
    result = await run_ffuf(
        ctx, "https://www.example.com/FUZZ", "common.txt", rate_limit=6
    )
    assert result.reason == "rate_limit must be from 1 to 5, the cap set in scope.yaml"
    assert runner.calls == []
