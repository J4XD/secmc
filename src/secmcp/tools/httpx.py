"""httpx wrapper: probes web servers on checked targets."""

from pathlib import Path
from typing import Annotated

import anyio
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from secmcp.context import ToolContext
from secmcp.parsers.httpx_json import (
    HttpxParseError,
    Probe,
    parse_httpx_jsonl,
    summarize,
)
from secmcp.policy import (
    Flag,
    ParsedFlag,
    PolicyError,
    choice,
    int_between,
    int_list,
    parse_args,
    port_list,
)
from secmcp.runner import RunResult
from secmcp.scope import connect_denylist
from secmcp.targets import UrlDecision, check_urls
from secmcp.tools.common import (
    RUNS_TOOL,
    Confirm,
    DryRun,
    Plugin,
    RateLimit,
    ToolResult,
    WebTargets,
    audit,
    execute,
    extra_args_field,
    locate,
    parse_failed,
    pick_rate,
    ready_to_run,
    run_paths,
    set_exit_status,
    write_targets,
)

BASE_FLAGS = [
    "-silent",
    "-nc",
    "-duc",
    "-no-stdin",
    "-probe",
    "-sc",
    "-cl",
    "-ct",
    "-title",
    "-server",
    "-td",
    "-ip",
]

ALLOWED_FLAGS: dict[str, Flag] = {
    "-location": Flag(),
    "-favicon": Flag(),
    "-jarm": Flag(),
    "-rt": Flag(),
    "-lc": Flag(),
    "-wc": Flag(),
    "-method": Flag(),
    "-cname": Flag(),
    "-cdn": Flag(),
    "-tls-grab": Flag(),
    "-http2": Flag(),
    "-pipeline": Flag(),
    "-vhost": Flag(),
    "-pa": Flag(),
    "-nf": Flag(),
    "-nfs": Flag(),
    "-fd": Flag(),
    "-fhr": Flag(),
    "-hash": Flag(choice("md5", "mmh3", "simhash", "sha1", "sha256", "sha512")),
    "-x": Flag(choice("GET", "HEAD", "OPTIONS")),
    "-p": Flag(port_list),
    "-mc": Flag(int_list(100, 599)),
    "-fc": Flag(int_list(100, 599)),
    "-ml": Flag(int_list(0, 1_000_000_000)),
    "-fl": Flag(int_list(0, 1_000_000_000)),
    "-maxr": Flag(int_between(0, 10)),
    "-t": Flag(int_between(1, 100)),
    "-timeout": Flag(int_between(1, 120)),
    "-retries": Flag(int_between(0, 5)),
}

BLOCKED_FLAGS: dict[str, str] = {
    "-l": "targets come only from the targets argument",
    "-u": "targets come only from the targets argument",
    "-target": "targets come only from the targets argument",
    "-o": "output paths are set by secmcp",
    "-j": "output paths are set by secmcp",
    "-json": "output paths are set by secmcp",
    "-csv": "output paths are set by secmcp",
    "-sr": "output paths are set by secmcp",
    "-srd": "output paths are set by secmcp",
    "-fr": "redirects can leave scope, use -fhr for same-host redirects",
    "-follow-redirects": "redirects can leave scope, use -fhr for same-host redirects",
    "-tls-probe": "probing names found in certificates can leave scope",
    "-csp-probe": "probing names found in csp headers can leave scope",
    "-r": "custom resolvers would bypass the scope dns check",
    "-resolvers": "custom resolvers would bypass the scope dns check",
    "-allow": "connection filters are set by secmcp",
    "-deny": "connection filters are set by secmcp",
    "-proxy": "proxies are not allowed",
    "-http-proxy": "proxies are not allowed",
    "-config": "loading config files is not allowed",
    "-path": "put the path in the target url instead",
    "-ss": "headless browser screenshots are not supported",
    "-screenshot": "headless browser screenshots are not supported",
    "-rl": "use the rate_limit argument",
}


class HttpxResult(ToolResult):
    targets: list[str]
    scope: list[UrlDecision] = Field(default_factory=list)
    probes: list[Probe] = Field(default_factory=list)
    json_path: str | None = None


def build_argv(
    binary: str,
    list_path: Path,
    json_path: Path,
    rate: int,
    deny: list[str],
    flags: list[ParsedFlag],
) -> list[str]:
    """Assemble the httpx command line."""
    argv = [binary, "-l", str(list_path), "-j", "-o", str(json_path), *BASE_FLAGS]
    argv += ["-rl", str(rate)]
    if deny:
        argv += ["-deny", ",".join(deny)]
    for flag in flags:
        argv += flag.argv()
    return argv


def _finish(result: HttpxResult, run: RunResult, json_path: Path) -> None:
    result.json_path = str(json_path)
    try:
        probes = parse_httpx_jsonl(json_path.read_bytes())
    except FileNotFoundError:
        probes = []
    except (OSError, HttpxParseError) as exc:
        parse_failed(result, "httpx", run, str(exc))
        return
    result.probes, result.summary = probes, summarize(probes)
    set_exit_status(result, "httpx", run, "probe completed")


async def run_httpx(
    ctx: ToolContext,
    targets: list[str],
    rate_limit: int | None = None,
    extra_args: list[str] | None = None,
    dry_run: bool = False,
    confirm: bool = False,
) -> HttpxResult:
    """Check every target, then probe them with httpx and parse its JSON output."""
    target_text = " ".join(targets)
    decisions, refused = await anyio.to_thread.run_sync(
        check_urls, targets, ctx.scope, ctx.resolve
    )
    result = HttpxResult(
        status="blocked", reason=refused or "", targets=targets, scope=decisions
    )
    if refused:
        return audit(ctx, "httpx", target_text, result, dry_run)
    try:
        rate = pick_rate(rate_limit, ctx.config.rate_limits.httpx)
        flags = parse_args(extra_args or [], ALLOWED_FLAGS, BLOCKED_FLAGS)
    except PolicyError as exc:
        result.reason = str(exc)
        return audit(ctx, "httpx", target_text, result, dry_run)

    binary = locate(ctx.config, "httpx")
    json_path, log_path = run_paths(ctx.config.runs_dir, "httpx", ".jsonl")
    list_path = log_path.with_suffix(".targets")
    deny = connect_denylist(ctx.scope)
    result.argv = build_argv(binary or "httpx", list_path, json_path, rate, deny, flags)
    if not ready_to_run(ctx.config, PLUGIN, binary, result, dry_run, confirm):
        return audit(ctx, "httpx", target_text, result, dry_run)
    write_targets(list_path, [d.url for d in decisions if d.url])
    run = await execute(ctx, "httpx", result, ctx.config.timeouts.httpx, log_path)
    if run is not None:
        _finish(result, run, json_path)
    return audit(ctx, "httpx", target_text, result, dry_run)


def register(server: MCPServer, ctx: ToolContext) -> None:
    """Add the run_httpx tool to the server."""

    @server.tool(name="run_httpx", annotations=RUNS_TOOL)
    async def tool(
        targets: WebTargets,
        rate_limit: RateLimit = None,
        extra_args: Annotated[
            list[str] | None, extra_args_field(ALLOWED_FLAGS, "httpx")
        ] = None,
        dry_run: DryRun = False,
        confirm: Confirm = False,
    ) -> HttpxResult:
        """Probe web servers with httpx: status, title, server, tech and ip."""
        return await run_httpx(ctx, targets, rate_limit, extra_args, dry_run, confirm)


PLUGIN = Plugin(
    name="httpx",
    summary="web server probing: status, title, server, tech and ip",
    install_hint="install projectdiscovery httpx "
    "(go install github.com/projectdiscovery/httpx/cmd/httpx@latest); "
    "the python httpx cli is a different tool, set binaries.httpx if both exist",
    allowed_flags=ALLOWED_FLAGS,
    blocked_flags=BLOCKED_FLAGS,
    dangerous={},
    output_suffix=".jsonl",
    parse_error=HttpxParseError,
    register=register,
)
