from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult

from secmcp import server
from secmcp.audit import read_records
from secmcp.config import Config
from secmcp.tools import common
from tests.helpers import make_ctx

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
def _nmap_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(common, "find_binary", lambda name: "/usr/bin/nmap")


async def call(config: Config, tool: str, arguments: dict[str, Any]) -> Any:
    ctx, _ = make_ctx(config)
    result = await server.build_server(ctx).call_tool(tool, arguments)
    assert isinstance(result, CallToolResult)
    assert not result.is_error
    return result.structured_content


async def test_tools_are_listed_with_schemas(config: Config) -> None:
    ctx, _ = make_ctx(config)
    tools = {tool.name: tool for tool in await server.build_server(ctx).list_tools()}
    assert set(tools) == {
        "run_nmap",
        "run_httpx",
        "run_ffuf",
        "run_nuclei",
        "check_scope",
        "get_audit_log",
        "generate_report",
    }
    schema = tools["run_nmap"].input_schema
    assert schema["required"] == ["target"]
    assert set(schema["properties"]) == {
        "target",
        "scan_type",
        "ports",
        "extra_args",
        "dry_run",
        "confirm",
    }
    assert "--script" in schema["properties"]["extra_args"]["description"]
    assert tools["run_nmap"].output_schema is not None
    assert tools["run_nuclei"].input_schema["required"] == ["targets"]
    assert "intrusive" in str(tools["run_nuclei"].input_schema["properties"]["tags"])
    assert tools["run_ffuf"].input_schema["required"] == ["url", "wordlist"]
    report = tools["generate_report"].input_schema
    assert set(report["properties"]) == {"target", "since", "until"}
    assert "required" not in report


async def test_run_nmap_dry_run_over_mcp(config: Config) -> None:
    content = await call(
        config,
        "run_nmap",
        {"target": "203.0.113.10", "scan_type": "top_ports", "dry_run": True},
    )
    assert content["status"] == "dry_run"
    assert content["argv"][-1] == "203.0.113.10"


async def test_invalid_scan_type_is_rejected(config: Config) -> None:
    ctx, runner = make_ctx(config)
    with pytest.raises(ToolError, match="scan_type"):
        await server.build_server(ctx).call_tool(
            "run_nmap", {"target": "203.0.113.10", "scan_type": "aggressive"}
        )
    assert runner.calls == []


async def test_run_httpx_dry_run_over_mcp(config: Config) -> None:
    content = await call(
        config,
        "run_httpx",
        {"targets": ["https://www.example.com"], "rate_limit": 5, "dry_run": True},
    )
    assert content["status"] == "dry_run"
    assert content["scope"][0]["url"] == "https://www.example.com"


@pytest.mark.parametrize(
    ("tool", "arguments", "message"),
    [
        ("run_httpx", {"targets": []}, "targets"),
        ("run_httpx", {"targets": ["www.example.com"], "rate_limit": 0}, "rate_limit"),
        (
            "run_nuclei",
            {"targets": ["www.example.com"], "severity": ["severe"]},
            "severity",
        ),
    ],
)
async def test_schema_violations_are_rejected(
    config: Config, tool: str, arguments: dict[str, Any], message: str
) -> None:
    ctx, runner = make_ctx(config)
    with pytest.raises(ToolError, match=message):
        await server.build_server(ctx).call_tool(tool, arguments)
    assert runner.calls == []


async def test_check_scope_accepts_urls(config: Config) -> None:
    content = await call(
        config, "check_scope", {"target": "https://www.example.com/login"}
    )
    assert content["allowed"] is True
    assert content["url"] == "https://www.example.com/login"
    content = await call(config, "check_scope", {"target": "203.0.113.0/28"})
    assert (content["allowed"], content["url"]) == (True, None)


async def test_check_scope_is_logged(config: Config) -> None:
    content = await call(config, "check_scope", {"target": "8.8.8.8"})
    assert content["allowed"] is False
    assert content["reason"] == "8.8.8.8 is not in scope"

    log = await call(config, "get_audit_log", {"limit": 5})
    assert [(r["tool"], r["decision"]) for r in log["records"]] == [
        ("check_scope", "blocked")
    ]


async def test_audit_log_limit(config: Config) -> None:
    for n in range(3):
        await call(config, "check_scope", {"target": f"203.0.113.{n + 1}"})
    log = await call(config, "get_audit_log", {"limit": 2})
    assert [r["target"] for r in log["records"]] == ["203.0.113.2", "203.0.113.3"]


def test_main_exits_on_bad_scope(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="cannot read"):
        server.main(["--scope", str(tmp_path / "missing.yaml")])


async def test_generate_report_over_mcp(config: Config) -> None:
    await call(config, "run_nmap", {"target": "203.0.113.10"})
    content = await call(
        config,
        "generate_report",
        {"target": "203.0.113.0/24", "since": "2000-01-01T00:00:00"},
    )
    assert content["runs"] == 1
    assert content["findings"] == 3
    assert "Open port 22/tcp" in content["markdown"]
    assert Path(content["report_path"]).is_file()


async def test_generate_report_rejects_bad_target(config: Config) -> None:
    ctx, _ = make_ctx(config)
    with pytest.raises(ToolError, match="invalid target"):
        await server.build_server(ctx).call_tool(
            "generate_report", {"target": "https://example.com"}
        )


def write_scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text("allow: [example.com]\ndata_dir: data\n")
    return path


def test_report_command_prints_draft(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    server.main(["report", "--scope", str(write_scope(tmp_path))])
    out = capsys.readouterr().out
    assert out.startswith("# Security testing report (draft)")
    assert "No tools were run in this period." in out
    assert read_records(tmp_path / "data" / "audit.jsonl", 10) == []


def test_report_command_writes_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "report.md"
    scope = str(write_scope(tmp_path))
    server.main(
        ["--scope", scope, "report", "--target", "example.com", "-o", str(output)]
    )
    assert output.read_text().startswith(
        "# Security testing report: example.com (draft)"
    )
    assert "wrote" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--since", "yesterday"], "invalid time"),
        (["--target", "a b"], "invalid target"),
        (["--since", "2026-11-25", "--until", "2026-11-24"], "earlier"),
    ],
)
def test_report_command_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    args: list[str],
    message: str,
) -> None:
    scope = str(write_scope(tmp_path))
    with pytest.raises(SystemExit) as exc:
        server.main(["report", "--scope", scope, *args])
    assert message in str(exc.value) + capsys.readouterr().err
