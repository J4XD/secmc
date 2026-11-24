from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult

from secmcp import server
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
    assert set(tools) == {"run_nmap", "check_scope", "get_audit_log"}
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
