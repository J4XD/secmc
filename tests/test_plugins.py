from pathlib import Path
from typing import get_args

import pytest
from mcp.server.mcpserver import MCPServer

from secmcp.config import Config, RateLimits, Timeouts, ToolName
from secmcp.tools import PLUGINS, common
from secmcp.tools.common import tool_status
from tests.helpers import make_ctx

pytestmark = pytest.mark.anyio


def test_every_tool_name_has_one_plugin() -> None:
    names = [plugin.name for plugin in PLUGINS]
    assert sorted(names) == sorted(get_args(ToolName))
    assert len(set(names)) == len(names)


def test_every_plugin_has_a_timeout() -> None:
    assert set(Timeouts.model_fields) == {plugin.name for plugin in PLUGINS}
    assert set(RateLimits.model_fields) < set(Timeouts.model_fields)


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda plugin: plugin.name)
def test_flags_are_either_allowed_or_blocked(plugin: common.Plugin) -> None:
    assert not set(plugin.allowed_flags) & set(plugin.blocked_flags)


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda plugin: plugin.name)
def test_plugin_metadata(plugin: common.Plugin) -> None:
    assert plugin.output_suffix.startswith(".")
    assert plugin.install_hint.startswith("install ")
    assert plugin.mcp_tool == f"run_{plugin.name}"


async def test_register_adds_the_plugin_tool(config: Config) -> None:
    ctx, _ = make_ctx(config)
    for plugin in PLUGINS:
        server = MCPServer("test")
        plugin.register(server, ctx)
        assert [tool.name for tool in await server.list_tools()] == [plugin.mcp_tool]


def test_dangerous_entries() -> None:
    by_name = {plugin.name: plugin for plugin in PLUGINS}
    assert set(by_name["nmap"].dangerous) == {
        "--script brute",
        "--script dos",
        "--script exploit",
        "--script intrusive",
    }
    assert "tag intrusive" in by_name["nuclei"].dangerous
    assert by_name["httpx"].dangerous == {}


def test_tool_status_uses_configured_binary(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = []
    monkeypatch.setattr(common, "find_binary", lambda name: seen.append(name))
    config = config.model_copy(update={"binaries": {"httpx": Path("/opt/pd/httpx")}})
    by_name = {plugin.name: plugin for plugin in PLUGINS}
    status = tool_status(config, by_name["httpx"])
    assert seen == ["/opt/pd/httpx"]
    assert not status.installed
    assert "projectdiscovery" in (status.install_hint or "")
    assert status.allowed_flags == sorted(by_name["httpx"].allowed_flags)
