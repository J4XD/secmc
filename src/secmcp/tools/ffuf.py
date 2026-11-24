"""ffuf wrapper: content discovery with allowlisted wordlists."""

import re
from pathlib import Path
from typing import Annotated

import anyio
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from secmcp.context import ToolContext
from secmcp.parsers.ffuf_json import (
    FfufMatch,
    FfufParseError,
    parse_ffuf_json,
    summarize,
)
from secmcp.policy import (
    Flag,
    ParsedFlag,
    PolicyError,
    check_text,
    choice,
    int_between,
    int_list,
    parse_args,
)
from secmcp.runner import RunResult
from secmcp.targets import UrlDecision, check_url
from secmcp.tools.common import (
    RUNS_TOOL,
    Confirm,
    DryRun,
    Plugin,
    RateLimit,
    ToolResult,
    audit,
    execute,
    extra_args_field,
    locate,
    parse_failed,
    pick_rate,
    ready_to_run,
    run_paths,
    set_exit_status,
)

KEYWORD = "FUZZ"
_EXTENSIONS = re.compile(r"\.?[A-Za-z0-9_-]{1,10}(,\.?[A-Za-z0-9_-]{1,10})*")
_DELAY = re.compile(r"\d{1,3}(\.\d{1,3})?(-\d{1,3}(\.\d{1,3})?)?")


def _status_codes(value: str) -> str | None:
    return None if value == "all" else int_list(100, 599)(value)


def _extensions(value: str) -> str | None:
    return (
        None if _EXTENSIONS.fullmatch(value) else "expected extensions like .php,.bak"
    )


def _delay(value: str) -> str | None:
    return None if _DELAY.fullmatch(value) else "expected seconds like 0.1 or 0.1-2.0"


ALLOWED_FLAGS: dict[str, Flag] = {
    "-mc": Flag(_status_codes),
    "-fc": Flag(int_list(100, 599)),
    "-ms": Flag(int_list(0, 1_000_000_000)),
    "-fs": Flag(int_list(0, 1_000_000_000)),
    "-mw": Flag(int_list(0, 1_000_000_000)),
    "-fw": Flag(int_list(0, 1_000_000_000)),
    "-ml": Flag(int_list(0, 1_000_000_000)),
    "-fl": Flag(int_list(0, 1_000_000_000)),
    "-mmode": Flag(choice("and", "or")),
    "-fmode": Flag(choice("and", "or")),
    "-ac": Flag(),
    "-ach": Flag(),
    "-ic": Flag(),
    "-D": Flag(),
    "-e": Flag(_extensions),
    "-X": Flag(choice("GET", "HEAD", "OPTIONS")),
    "-t": Flag(int_between(1, 100)),
    "-p": Flag(_delay),
    "-timeout": Flag(int_between(1, 120)),
    "-maxtime": Flag(int_between(1, 86_400)),
    "-maxtime-job": Flag(int_between(1, 86_400)),
    "-recursion": Flag(),
    "-recursion-depth": Flag(int_between(1, 5)),
    "-se": Flag(),
    "-sf": Flag(),
    "-sa": Flag(),
    "-v": Flag(),
    "-http2": Flag(),
    "-ignore-body": Flag(),
}

BLOCKED_FLAGS: dict[str, str] = {
    "-input-cmd": "running commands is not allowed",
    "-input-shell": "running commands is not allowed",
    "-input-num": "running commands is not allowed",
    "-u": "use the url argument",
    "-w": "use the wordlist argument",
    "-mode": "only a single wordlist is supported",
    "-request": "raw request files are not allowed",
    "-request-proto": "raw request files are not allowed",
    "-preflight": "raw request files are not allowed",
    "-postflight": "raw request files are not allowed",
    "-o": "output paths are set by secmcp",
    "-of": "output paths are set by secmcp",
    "-od": "output paths are set by secmcp",
    "-audit-log": "output paths are set by secmcp",
    "-debug-log": "output paths are set by secmcp",
    "-r": "redirects can leave scope",
    "-x": "proxies are not allowed",
    "-replay-proxy": "proxies are not allowed",
    "-config": "loading config files is not allowed",
    "-scraperfile": "loading scraper files is not allowed",
    "-H": "custom headers, cookies and bodies are not supported",
    "-b": "custom headers, cookies and bodies are not supported",
    "-d": "custom headers, cookies and bodies are not supported",
    "-rate": "use the rate_limit argument",
}


class FfufResult(ToolResult):
    url: str
    wordlist: str
    scope: UrlDecision | None = None
    matches: list[FfufMatch] = Field(default_factory=list)
    json_path: str | None = None


def check_fuzz_host(raw: str) -> None:
    """Refuse FUZZ in the host part, which would send requests to other hosts."""
    netloc = raw.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
    if KEYWORD in netloc:
        raise PolicyError("FUZZ is only allowed in the path or query")


def resolve_wordlist(value: str, allowed_dirs: list[Path]) -> Path:
    """Resolve a wordlist name or path that must be a file inside allowed_dirs."""
    if not allowed_dirs:
        raise PolicyError("no wordlist_dirs are configured in scope.yaml")
    check_text(value)
    # ffuf reads "path:KEYWORD", so a colon would change the keyword.
    if ":" in value:
        raise PolicyError("wordlist paths must not contain ':'")
    path = Path(value)
    candidates = [path] if path.is_absolute() else [d / path for d in allowed_dirs]
    roots = [directory.resolve() for directory in allowed_dirs]
    for candidate in candidates:
        # resolve() follows symlinks, so a link pointing outside is caught here.
        resolved = candidate.resolve()
        if not any(resolved.is_relative_to(root) for root in roots):
            raise PolicyError(f"wordlist {value} is outside the allowed wordlist_dirs")
        if resolved.is_file():
            return resolved
    raise PolicyError(f"wordlist {value} not found in the allowed wordlist_dirs")


def build_argv(
    binary: str,
    url: str,
    wordlist: Path,
    json_path: Path,
    rate: int,
    flags: list[ParsedFlag],
) -> list[str]:
    """Assemble the ffuf command line."""
    argv = [binary, "-u", url, "-w", str(wordlist)]
    argv += ["-o", str(json_path), "-of", "json", "-noninteractive", "-s"]
    argv += ["-rate", str(rate)]
    for flag in flags:
        argv += flag.argv()
    return argv


def _finish(result: FfufResult, run: RunResult, json_path: Path) -> None:
    result.json_path = str(json_path)
    try:
        matches = parse_ffuf_json(json_path.read_bytes())
    except FileNotFoundError:
        matches = []
    except (OSError, FfufParseError) as exc:
        parse_failed(result, "ffuf", run, str(exc))
        return
    result.matches, result.summary = matches, summarize(matches)
    set_exit_status(result, "ffuf", run, "fuzzing completed")


async def run_ffuf(
    ctx: ToolContext,
    url: str,
    wordlist: str,
    rate_limit: int | None = None,
    extra_args: list[str] | None = None,
    dry_run: bool = False,
    confirm: bool = False,
) -> FfufResult:
    """Check the url and wordlist, then fuzz with ffuf and parse its JSON output."""
    result = FfufResult(status="blocked", reason="", url=url, wordlist=wordlist)
    try:
        check_fuzz_host(url)
    except PolicyError as exc:
        result.reason = str(exc)
        return audit(ctx, "ffuf", url, result, dry_run)
    decision = await anyio.to_thread.run_sync(
        lambda: check_url(url, ctx.scope, ctx.resolve, require_scheme=True)
    )
    result.reason, result.scope = decision.reason, decision
    if not decision.allowed or decision.url is None:
        return audit(ctx, "ffuf", url, result, dry_run)
    try:
        if KEYWORD not in decision.url:
            raise PolicyError("the url must contain FUZZ in its path or query")
        wordlist_path = resolve_wordlist(wordlist, ctx.config.wordlist_dirs)
        rate = pick_rate(rate_limit, ctx.config.rate_limits.ffuf)
        flags = parse_args(extra_args or [], ALLOWED_FLAGS, BLOCKED_FLAGS)
    except PolicyError as exc:
        result.reason = str(exc)
        return audit(ctx, "ffuf", url, result, dry_run)

    binary = locate(ctx.config, "ffuf")
    json_path, log_path = run_paths(ctx.config.runs_dir, "ffuf", ".json")
    result.argv = build_argv(
        binary or "ffuf", decision.url, wordlist_path, json_path, rate, flags
    )
    if not ready_to_run(ctx.config, PLUGIN, binary, result, dry_run, confirm):
        return audit(ctx, "ffuf", url, result, dry_run)
    run = await execute(ctx, "ffuf", result, ctx.config.timeouts.ffuf, log_path)
    if run is not None:
        _finish(result, run, json_path)
    return audit(ctx, "ffuf", url, result, dry_run)


def register(server: MCPServer, ctx: ToolContext) -> None:
    """Add the run_ffuf tool to the server."""

    @server.tool(name="run_ffuf", annotations=RUNS_TOOL)
    async def tool(
        url: Annotated[
            str,
            Field(
                description="http(s) url in scope with FUZZ in the path or query, "
                "e.g. https://app.example.com/FUZZ"
            ),
        ],
        wordlist: Annotated[
            str,
            Field(
                description="wordlist file name or path inside a wordlist_dirs "
                "directory from scope.yaml"
            ),
        ],
        rate_limit: RateLimit = None,
        extra_args: Annotated[
            list[str] | None, extra_args_field(ALLOWED_FLAGS, "ffuf")
        ] = None,
        dry_run: DryRun = False,
        confirm: Confirm = False,
    ) -> FfufResult:
        """Discover content with ffuf using an allowlisted wordlist."""
        return await run_ffuf(
            ctx, url, wordlist, rate_limit, extra_args, dry_run, confirm
        )


PLUGIN = Plugin(
    name="ffuf",
    summary="content discovery with allowlisted wordlists",
    install_hint="install ffuf (apt install ffuf, brew install ffuf, "
    "or go install github.com/ffuf/ffuf/v2@latest)",
    allowed_flags=ALLOWED_FLAGS,
    blocked_flags=BLOCKED_FLAGS,
    dangerous={},
    output_suffix=".json",
    parse_error=FfufParseError,
    register=register,
)
