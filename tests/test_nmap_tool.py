import shutil
from pathlib import Path

import pytest

from secmcp.audit import read_records
from secmcp.config import Config
from secmcp.runner import RunResult
from secmcp.tools import common, nmap
from secmcp.tools.nmap import load_script_db, run_nmap
from tests.helpers import FIXTURES, FakeRunner, make_ctx

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
def _nmap_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(common, "find_binary", lambda name: "/usr/bin/nmap")


async def test_dry_run_returns_exact_argv_without_running(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nmap(ctx, "203.0.113.10", dry_run=True)

    assert result.status == "dry_run"
    assert runner.calls == []
    xml_path = result.argv[-2]
    assert result.argv == [
        "/usr/bin/nmap",
        "-T4",
        "-F",
        "-oX",
        xml_path,
        "203.0.113.10",
    ]
    assert xml_path.startswith(str(config.runs_dir))
    record = read_records(config.audit_log_path, 1)[0]
    assert record.dry_run
    assert record.decision == "allowed"
    assert record.argv == result.argv


async def test_domain_is_pinned_to_checked_address(config: Config) -> None:
    ctx, _ = make_ctx(config)
    result = await run_nmap(
        ctx, "www.example.com", "service_version", ports="22,80", dry_run=True
    )
    assert result.argv[1:4] == ["-sV", "-p", "22,80"]
    assert result.argv[-1] == "203.0.113.10"


async def test_ipv6_target_adds_flag(config: Config) -> None:
    ctx, _ = make_ctx(config, allow=["2001:db8::/64", "*.example.com"])
    result = await run_nmap(ctx, "v6.example.com", "top_ports", dry_run=True)
    assert result.argv[1:3] == ["--top-ports", "1000"]
    assert result.argv[-4:-2] == ["-6", "-oX"]
    assert result.argv[-1] == "2001:db8::10"


async def test_completed_scan_returns_structured_hosts(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nmap(ctx, "203.0.113.10", "service_version", extra_args=["-Pn"])

    assert result.status == "completed"
    assert runner.calls == [result.argv]
    assert "-Pn" in result.argv
    assert result.hosts[0].ports[0].product == "OpenSSH"
    assert result.summary.startswith("1 of 2 hosts up")
    assert result.output is None
    assert result.raw_output_path
    assert Path(result.raw_output_path).exists()
    record = read_records(config.audit_log_path, 1)[0]
    assert (record.decision, record.exit_code, record.duration_s) == ("allowed", 0, 1.5)
    assert record.raw_output_path == result.raw_output_path


async def test_out_of_scope_is_blocked_and_logged(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nmap(ctx, "8.8.8.8")
    assert result.status == "blocked"
    assert result.reason == "8.8.8.8 is not in scope"
    assert runner.calls == []
    record = read_records(config.audit_log_path, 1)[0]
    assert (record.decision, record.target, record.reason) == (
        "blocked",
        "8.8.8.8",
        "8.8.8.8 is not in scope",
    )


async def test_metadata_ip_is_blocked(config: Config) -> None:
    ctx, runner = make_ctx(config, allow=["169.254.0.0/16"])
    result = await run_nmap(ctx, "169.254.169.254")
    assert result.status == "blocked"
    assert "cloud metadata" in result.reason
    assert runner.calls == []


async def test_unknown_flag_is_rejected(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nmap(ctx, "203.0.113.10", extra_args=["--badsum"])
    assert result.status == "blocked"
    assert result.reason == "unknown flag --badsum"
    assert runner.calls == []


@pytest.mark.parametrize(
    ("extra_args", "reason"),
    [
        (["-oN", "/tmp/out"], "-oN is not allowed: output paths are set by secmcp"),
        (["-oX/tmp/out.xml"], "output paths are set by secmcp"),
        (["--append-output"], "output paths are set by secmcp"),
        (["-iL", "hosts.txt"], "targets come only from the target argument"),
        (["-iR", "100"], "targets come only from the target argument"),
        (["203.0.113.99"], "extra targets are not allowed"),
        (["-Pn", "evil.com"], "extra targets are not allowed"),
        (["--max-retries", "-oN"], "--max-retries needs a value, got '-oN'"),
        (["--max-retries"], "--max-retries needs a value"),
        (["--host-timeout", "10s;id"], "shell metacharacters"),
        (["--script", "http-title|id"], "shell metacharacters"),
        (["--script=$(id)"], "shell metacharacters"),
        (["--open\nid"], "control characters"),
        (["--script", "../../tmp/evil"], "expected comma-separated script names"),
        (["--script-args", "newtargets"], "script arguments can add targets"),
        (["--datadir", "/tmp"], "loading nmap data from other paths"),
        (["-p", "1-65535"], "use the ports argument"),
        (["-p1-65535"], "use the ports argument"),
        (["--top-ports", "100"], "use scan_type"),
        (["-D", "RND:10"], "decoys are not allowed"),
        (["--open=yes"], "--open does not take a value"),
        (["--max-rate", "999999"], "expected an integer from 1 to 10000"),
        (["-sSV"], "unknown flag -sSV"),
    ],
)
async def test_injection_attempts_are_rejected(
    config: Config, extra_args: list[str], reason: str
) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nmap(ctx, "203.0.113.10", extra_args=extra_args)
    assert result.status == "blocked"
    assert reason in result.reason
    assert runner.calls == []
    assert read_records(config.audit_log_path, 1)[0].decision == "blocked"


@pytest.mark.parametrize("ports", ["80;id", "0", "70000", "80-20", "-1", "80, 443", ""])
async def test_invalid_ports_are_rejected(config: Config, ports: str) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nmap(ctx, "203.0.113.10", ports=ports)
    assert result.status == "blocked"
    assert runner.calls == []


async def test_safe_scripts_and_categories_run_without_approval(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nmap(
        ctx, "203.0.113.10", extra_args=["--script", "http-title,ssl-cert,safe", "-sC"]
    )
    assert result.status == "completed"
    assert result.approval_required == []
    assert len(runner.calls) == 1


@pytest.mark.parametrize(
    ("script", "risk"),
    [
        ("ssh-brute", "--script ssh-brute (brute, intrusive)"),
        ("http-slowloris", "--script http-slowloris (dos, intrusive)"),
        ("intrusive", "--script intrusive (intrusive)"),
        ("exploit", "--script exploit (exploit)"),
    ],
)
async def test_dangerous_scripts_need_config_and_confirm(
    config: Config, script: str, risk: str
) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nmap(
        ctx, "203.0.113.10", extra_args=["--script", script], confirm=True
    )
    assert result.status == "needs_approval"
    assert result.approval_required == [risk]
    assert (
        result.reason
        == "needs human approval: requires allow_dangerous: true in scope.yaml"
    )
    assert runner.calls == []

    ctx, runner = make_ctx(config, allow_dangerous=True)
    result = await run_nmap(ctx, "203.0.113.10", extra_args=["--script", script])
    assert result.status == "needs_approval"
    assert result.reason == "needs human approval: requires confirm=true on the call"
    assert runner.calls == []

    result = await run_nmap(
        ctx, "203.0.113.10", extra_args=["--script", script], confirm=True
    )
    assert result.status == "completed"
    assert result.approval_required == [risk]
    assert len(runner.calls) == 1


async def test_dangerous_without_either_lists_both(config: Config) -> None:
    ctx, _ = make_ctx(config)
    result = await run_nmap(ctx, "203.0.113.10", extra_args=["--script=ssh-brute"])
    assert result.reason == (
        "needs human approval: requires allow_dangerous: true in scope.yaml "
        "and confirm=true on the call"
    )
    record = read_records(config.audit_log_path, 1)[0]
    assert record.decision == "blocked"
    assert record.reason == result.reason


async def test_dry_run_reports_required_approval(config: Config) -> None:
    ctx, runner = make_ctx(config)
    result = await run_nmap(
        ctx, "203.0.113.10", extra_args=["--script", "brute"], dry_run=True
    )
    assert result.status == "dry_run"
    assert result.approval_required == ["--script brute (brute)"]
    assert result.reason.startswith("needs human approval")
    assert runner.calls == []


@pytest.mark.parametrize(
    ("script", "reason"),
    [
        ("broadcast-dhcp-discover", "sends traffic beyond the target"),
        ("broadcast", "sends traffic beyond the target"),
        ("all", "--script all is not allowed"),
        ("no-such-script", "unknown nmap script 'no-such-script'"),
    ],
)
async def test_blocked_scripts(config: Config, script: str, reason: str) -> None:
    ctx, _ = make_ctx(config, allow_dangerous=True)
    result = await run_nmap(
        ctx, "203.0.113.10", extra_args=["--script", script], confirm=True
    )
    assert result.status == "blocked"
    assert reason in result.reason


async def test_script_names_need_script_db(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(nmap, "SCRIPT_DB_LOCATIONS", ())
    ctx, _ = make_ctx(config, nmap_script_db=None)
    monkeypatch.setattr(common, "find_binary", lambda name: None)
    result = await run_nmap(ctx, "203.0.113.10", extra_args=["--script", "http-title"])
    assert "script.db not found" in result.reason
    result = await run_nmap(
        ctx, "203.0.113.10", extra_args=["--script", "safe"], dry_run=True
    )
    assert result.status == "dry_run"


async def test_missing_binary(config: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(common, "find_binary", lambda name: None)
    ctx, runner = make_ctx(config)
    result = await run_nmap(ctx, "203.0.113.10")
    assert result.status == "missing_binary"
    assert "nmap.org" in result.reason
    assert runner.calls == []

    result = await run_nmap(ctx, "203.0.113.10", dry_run=True)
    assert result.argv[0] == "nmap"
    assert "nmap not found" in result.reason


async def test_timeout_is_reported(config: Config) -> None:
    ctx, _ = make_ctx(
        config, runner=FakeRunner(output=b"<nmaprun><host>", timed_out=True)
    )
    result = await run_nmap(ctx, "203.0.113.10")
    assert result.status == "timed_out"
    assert result.output == "tool output\n"
    assert read_records(config.audit_log_path, 1)[0].timed_out


async def test_failed_run_includes_output(config: Config) -> None:
    ctx, _ = make_ctx(config, runner=FakeRunner(output=b"", exit_code=1))
    result = await run_nmap(ctx, "203.0.113.10")
    assert result.status == "failed"
    assert result.reason.startswith("nmap exited 1")
    assert result.output == "tool output\n"


async def test_exec_failure_is_reported_and_logged(config: Config) -> None:
    class BrokenRunner(FakeRunner):
        async def run(
            self, argv: list[str], timeout: float, raw_output_path: Path
        ) -> RunResult:
            raise PermissionError(13, "Permission denied")

    ctx, _ = make_ctx(config, runner=BrokenRunner())
    result = await run_nmap(ctx, "203.0.113.10")
    assert result.status == "failed"
    assert "could not start nmap" in result.reason
    assert read_records(config.audit_log_path, 1)[0].reason == result.reason


def test_load_script_db() -> None:
    db = load_script_db(FIXTURES / "script.db")
    assert db["ssh-brute"] == frozenset({"brute", "intrusive"})
    assert len(db) == 5


def test_real_script_db_parses_if_present() -> None:
    path = nmap.find_script_db(None, shutil.which("nmap"))
    if path is None:
        pytest.skip("nmap not installed")
    assert "http-title" in load_script_db(path)
