"""nuclei wrapper: template scans with severity and tag filters."""

import re
from pathlib import Path
from typing import Annotated

import anyio
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from secmcp.context import ToolContext
from secmcp.parsers.nuclei_jsonl import (
    Finding,
    NucleiParseError,
    Severity,
    parse_nuclei_jsonl,
    summarize,
)
from secmcp.policy import (
    Flag,
    ParsedFlag,
    PolicyError,
    choice,
    int_between,
    parse_args,
)
from secmcp.runner import RunResult
from secmcp.scope import Scope, allows_restricted
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

# Tags whose templates attack, overload or log in to the target.
DANGEROUS_TAGS: dict[str, str] = {
    "intrusive": "may change state on the target",
    "dos": "may crash or overload the target",
    "fuzz": "sends fuzzing payloads",
    "fuzzing": "sends fuzzing payloads",
    "bruteforce": "brute forces credentials",
    "default-login": "logs in with default credentials",
    "token-spray": "sprays tokens against the target",
    "file-upload": "uploads files to the target",
    "fileupload": "uploads files to the target",
    "file-write": "writes files on the target",
}

BASE_FLAGS = [
    "-silent",
    "-nc",
    "-duc",
    "-no-stdin",
    "-ni",
    "-dr",
    "-or",
    "-ot",
]

PROTOCOL_TYPES = ("dns", "http", "ssl", "tcp", "websocket", "whois", "javascript")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")


def _names(value: str) -> str | None:
    if all(_NAME.fullmatch(name) for name in value.split(",")):
        return None
    return "expected comma-separated template ids or tags"


ALLOWED_FLAGS: dict[str, Flag] = {
    "-es": Flag(choice("info", "low", "medium", "high", "critical", "unknown")),
    "-eid": Flag(_names),
    "-pt": Flag(choice(*PROTOCOL_TYPES)),
    "-ept": Flag(choice(*PROTOCOL_TYPES)),
    "-nt": Flag(),
    "-timeout": Flag(int_between(1, 120)),
    "-retries": Flag(int_between(0, 5)),
    "-c": Flag(int_between(1, 50)),
    "-bs": Flag(int_between(1, 50)),
    "-mhe": Flag(int_between(1, 100)),
    "-nmhe": Flag(),
    "-spm": Flag(),
    "-ss": Flag(choice("auto", "host-spray", "template-spray")),
    "-sa": Flag(),
    "-iv": Flag(choice("4", "6")),
    "-nh": Flag(),
    "-ldp": Flag(),
    "-fhr": Flag(),
    "-mr": Flag(int_between(0, 10)),
    "-ms": Flag(),
    "-v": Flag(),
}

BLOCKED_FLAGS: dict[str, str] = {
    "-l": "targets come only from the targets argument",
    "-u": "targets come only from the targets argument",
    "-targets-inline": "targets come only from the targets argument",
    "-uc": "uncover adds targets from search engines",
    "-uq": "uncover adds targets from search engines",
    "-t": "templates come only from the installed template set",
    "-w": "templates come only from the installed template set",
    "-turl": "templates come only from the installed template set",
    "-wurl": "templates come only from the installed template set",
    "-it": "templates come only from the installed template set",
    "-ai": "templates come only from the installed template set",
    "-tp": "templates come only from the installed template set",
    "-s": "use the severity argument",
    "-tags": "use the tags argument",
    "-etags": "use the exclude_tags argument",
    "-itags": "use the tags argument; dangerous tags need approval",
    "-id": "use the template_ids argument",
    "-code": "code, file, headless and dast templates are not supported",
    "-file": "code, file, headless and dast templates are not supported",
    "-headless": "code, file, headless and dast templates are not supported",
    "-dast": "code, file, headless and dast templates are not supported",
    "-fuzz": "code, file, headless and dast templates are not supported",
    "-esc": "self-contained templates send requests to hosts outside scope",
    "-lfa": "local file access is not allowed",
    "-o": "output paths are set by secmcp",
    "-j": "output paths are set by secmcp",
    "-je": "output paths are set by secmcp",
    "-jle": "output paths are set by secmcp",
    "-se": "output paths are set by secmcp",
    "-me": "output paths are set by secmcp",
    "-pe": "output paths are set by secmcp",
    "-sresp": "output paths are set by secmcp",
    "-fr": "redirects can leave scope, use -fhr for same-host redirects",
    "-r": "custom resolvers would bypass the scope dns check",
    "-p": "proxies are not allowed",
    "-config": "loading config files is not allowed",
    "-sf": "loading secret files is not allowed",
    "-V": "template variables are not supported",
    "-ev": "environment variables can leak secrets to templates",
    "-H": "custom headers are not supported",
    "-iserver": "interactsh is disabled",
    "-pd": "uploading results is not allowed",
    "-pdu": "uploading results is not allowed",
    "-rl": "use the rate_limit argument",
    "-up": "updates are not run from secmcp",
    "-ut": "updates are not run from secmcp",
    "-i": "interface and source address selection is not allowed",
    "-sip": "interface and source address selection is not allowed",
}


class NucleiResult(ToolResult):
    targets: list[str]
    scope: list[UrlDecision] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    jsonl_path: str | None = None


def check_names(kind: str, names: list[str]) -> None:
    for name in names:
        if not _NAME.fullmatch(name):
            raise PolicyError(f"invalid {kind} {name!r}")


def tag_risks(tags: list[str]) -> list[str]:
    """List requested tags that need approval."""
    return [
        f"tag {tag} ({DANGEROUS_TAGS[tag]})" for tag in tags if tag in DANGEROUS_TAGS
    ]


def excluded_tags(requested: list[str], extra: list[str], approved: bool) -> list[str]:
    """Dangerous tags stay excluded unless they were requested and approved."""
    excluded = [tag for tag in DANGEROUS_TAGS if not (approved and tag in requested)]
    return excluded + [tag for tag in extra if tag not in excluded]


def build_argv(
    binary: str,
    list_path: Path,
    jsonl_path: Path,
    rate: int,
    scope: Scope,
    severity: list[Severity],
    tags: list[str],
    exclude_tags: list[str],
    template_ids: list[str],
    flags: list[ParsedFlag],
) -> list[str]:
    """Assemble the nuclei command line."""
    argv = [binary, "-l", str(list_path), "-j", "-o", str(jsonl_path), *BASE_FLAGS]
    argv += ["-rl", str(rate)]
    # nuclei can block private and local addresses at connect time, which also
    # catches names that re-resolve there after the scope check.
    if not allows_restricted(scope):
        argv.append("-lna")
    argv += ["-etags", ",".join(exclude_tags)]
    if severity:
        argv += ["-s", ",".join(severity)]
    if tags:
        argv += ["-tags", ",".join(tags)]
    if template_ids:
        argv += ["-id", ",".join(template_ids)]
    for flag in flags:
        argv += flag.argv()
    return argv


def _finish(result: NucleiResult, run: RunResult, jsonl_path: Path) -> None:
    result.jsonl_path = str(jsonl_path)
    try:
        findings = parse_nuclei_jsonl(jsonl_path.read_bytes())
    except FileNotFoundError:
        findings = []
    except (OSError, NucleiParseError) as exc:
        parse_failed(result, "nuclei", run, str(exc))
        return
    result.findings, result.summary = findings, summarize(findings)
    set_exit_status(result, "nuclei", run)


async def run_nuclei(
    ctx: ToolContext,
    targets: list[str],
    severity: list[Severity] | None = None,
    tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
    template_ids: list[str] | None = None,
    rate_limit: int | None = None,
    extra_args: list[str] | None = None,
    dry_run: bool = False,
    confirm: bool = False,
) -> NucleiResult:
    """Check every target, then run nuclei templates and parse the findings."""
    target_text = " ".join(targets)
    tags, exclude_tags, template_ids = (
        tags or [],
        exclude_tags or [],
        template_ids or [],
    )
    decisions, refused = await anyio.to_thread.run_sync(
        check_urls, targets, ctx.scope, ctx.resolve
    )
    result = NucleiResult(
        status="blocked", reason=refused or "", targets=targets, scope=decisions
    )
    if refused:
        return audit(ctx, "nuclei", target_text, result, dry_run)
    try:
        check_names("tag", tags + exclude_tags)
        check_names("template id", template_ids)
        rate = pick_rate(rate_limit, ctx.config.rate_limits.nuclei)
        flags = parse_args(extra_args or [], ALLOWED_FLAGS, BLOCKED_FLAGS)
    except PolicyError as exc:
        result.reason = str(exc)
        return audit(ctx, "nuclei", target_text, result, dry_run)

    result.approval_required = tag_risks(tags)
    approved = ctx.config.allow_dangerous and confirm
    binary = locate(ctx.config, "nuclei")
    jsonl_path, log_path = run_paths(ctx.config.runs_dir, "nuclei", ".jsonl")
    list_path = log_path.with_suffix(".targets")
    result.argv = build_argv(
        binary or "nuclei",
        list_path,
        jsonl_path,
        rate,
        ctx.scope,
        list(dict.fromkeys(severity or [])),
        tags,
        excluded_tags(tags, exclude_tags, approved),
        template_ids,
        flags,
    )
    if not ready_to_run(ctx.config, PLUGIN, binary, result, dry_run, confirm):
        return audit(ctx, "nuclei", target_text, result, dry_run)
    write_targets(list_path, [d.url for d in decisions if d.url])
    run = await execute(ctx, "nuclei", result, ctx.config.timeouts.nuclei, log_path)
    if run is not None:
        _finish(result, run, jsonl_path)
    return audit(ctx, "nuclei", target_text, result, dry_run)


def register(server: MCPServer, ctx: ToolContext) -> None:
    """Add the run_nuclei tool to the server."""

    @server.tool(name="run_nuclei", annotations=RUNS_TOOL)
    async def tool(
        targets: WebTargets,
        severity: Annotated[
            list[Severity] | None,
            Field(description="only run templates with these severities"),
        ] = None,
        tags: Annotated[
            list[str] | None,
            Field(
                description="only run templates with these tags. Tags that need "
                "approval: " + " ".join(DANGEROUS_TAGS)
            ),
        ] = None,
        exclude_tags: Annotated[
            list[str] | None, Field(description="skip templates with these tags")
        ] = None,
        template_ids: Annotated[
            list[str] | None,
            Field(description="only run these template ids, e.g. CVE-2021-44228"),
        ] = None,
        rate_limit: RateLimit = None,
        extra_args: Annotated[
            list[str] | None, extra_args_field(ALLOWED_FLAGS, "nuclei")
        ] = None,
        dry_run: DryRun = False,
        confirm: Confirm = False,
    ) -> NucleiResult:
        """Run nuclei templates; intrusive tags are excluded unless approved."""
        return await run_nuclei(
            ctx,
            targets,
            severity,
            tags,
            exclude_tags,
            template_ids,
            rate_limit,
            extra_args,
            dry_run,
            confirm,
        )


PLUGIN = Plugin(
    name="nuclei",
    summary="template scans with severity and tag filters",
    install_hint="install nuclei "
    "(go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest) "
    "and run nuclei -update-templates once",
    allowed_flags=ALLOWED_FLAGS,
    blocked_flags=BLOCKED_FLAGS,
    dangerous={f"tag {tag}": reason for tag, reason in DANGEROUS_TAGS.items()},
    output_suffix=".jsonl",
    parse_error=NucleiParseError,
    register=register,
)
