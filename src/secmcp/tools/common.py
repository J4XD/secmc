"""Plugin model, schema pieces, result model and run steps shared by the tools."""

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from secmcp.audit import AuditRecord, append_record
from secmcp.config import Config, ToolName
from secmcp.context import ToolContext
from secmcp.policy import Flag, PolicyError
from secmcp.runner import RunResult, find_binary
from secmcp.targets import MAX_TARGETS

Status = Literal[
    "completed",
    "failed",
    "timed_out",
    "blocked",
    "needs_approval",
    "dry_run",
    "missing_binary",
]


class ToolResult(BaseModel):
    status: Status
    reason: str
    argv: list[str] = []
    approval_required: list[str] = []
    summary: str = ""
    exit_code: int | None = None
    duration_s: float | None = None
    raw_output_path: str | None = None
    output: str | None = None


R = TypeVar("R", bound=ToolResult)


@dataclass(frozen=True)
class Plugin:
    """Everything secmcp needs to know about one wrapped tool."""

    name: ToolName
    summary: str
    install_hint: str
    allowed_flags: Mapping[str, Flag]
    blocked_flags: Mapping[str, str]
    dangerous: Mapping[str, str]
    output_suffix: str
    parse_error: type[Exception]
    register: Callable[[MCPServer, ToolContext], None]

    @property
    def mcp_tool(self) -> str:
        return f"run_{self.name}"


class ToolStatus(BaseModel):
    name: str
    mcp_tool: str
    summary: str
    installed: bool
    binary: str | None = None
    install_hint: str | None = None
    allowed_flags: list[str]
    needs_approval: dict[str, str]


RUNS_TOOL = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, open_world_hint=True
)
DryRun = Annotated[
    bool, Field(description="return the exact command without running it")
]
Confirm = Annotated[
    bool,
    Field(description="set only after a human approved a needs_approval result"),
]
RateLimit = Annotated[
    int | None,
    Field(
        ge=1,
        description="requests per second, at most the cap in scope.yaml "
        "(default: the cap)",
    ),
]
WebTargets = Annotated[
    list[str],
    Field(
        min_length=1,
        max_length=MAX_TARGETS,
        description="urls (http or https) or host[:port] values, all in scope",
    ),
]


def extra_args_field(allowed: Mapping[str, Flag], tool: str) -> Any:
    """Describe an extra_args parameter, listing the allowed flags."""
    return Field(
        description=f"extra {tool} flags, one list item per token. Allowed: "
        + " ".join(sorted(allowed))
    )


def locate(config: Config, tool: ToolName) -> str | None:
    """Return the configured binary path if it is executable, else search PATH."""
    configured = config.binaries.get(tool)
    if configured is None:
        return find_binary(tool)
    return find_binary(str(configured))


def tool_status(config: Config, plugin: Plugin) -> ToolStatus:
    """Report whether a plugin's binary is installed and what its policy allows."""
    binary = locate(config, plugin.name)
    return ToolStatus(
        name=plugin.name,
        mcp_tool=plugin.mcp_tool,
        summary=plugin.summary,
        installed=binary is not None,
        binary=binary,
        install_hint=None if binary else plugin.install_hint,
        allowed_flags=sorted(plugin.allowed_flags),
        needs_approval=dict(plugin.dangerous),
    )


def pick_rate(requested: int | None, maximum: int) -> int:
    """Return the request rate to use, refusing anything above the configured cap."""
    if requested is None:
        return maximum
    if not 1 <= requested <= maximum:
        raise PolicyError(
            f"rate_limit must be from 1 to {maximum}, the cap set in scope.yaml"
        )
    return requested


def run_paths(runs_dir: Path, tool: str, suffix: str) -> tuple[Path, Path]:
    """Return unique paths for a run's parsed output file and its raw log."""
    run_id = f"{tool}-{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    return runs_dir / f"{run_id}{suffix}", runs_dir / f"{run_id}.log"


def audit(ctx: ToolContext, tool: str, target: str, result: R, dry_run: bool) -> R:
    """Append an audit record for a finished call and return the result."""
    allowed = result.status not in ("blocked", "needs_approval", "missing_binary")
    append_record(
        ctx.config.audit_log_path,
        AuditRecord(
            tool=tool,
            target=target,
            argv=result.argv,
            dry_run=dry_run,
            decision="allowed" if allowed else "blocked",
            reason=result.reason,
            exit_code=result.exit_code,
            timed_out=result.status == "timed_out",
            duration_s=result.duration_s,
            raw_output_path=result.raw_output_path,
        ),
    )
    return result


def approval_reason(config: Config, confirm: bool) -> str | None:
    """Explain what is missing before a dangerous call may run, or None."""
    missing = []
    if not config.allow_dangerous:
        missing.append("allow_dangerous: true in scope.yaml")
    if not confirm:
        missing.append("confirm=true on the call")
    if not missing:
        return None
    return "needs human approval: requires " + " and ".join(missing)


def ready_to_run(
    config: Config,
    plugin: Plugin,
    binary: str | None,
    result: ToolResult,
    dry_run: bool,
    confirm: bool,
) -> bool:
    """Settle dry runs, missing approval and missing binaries; True means run it."""
    approval = approval_reason(config, confirm) if result.approval_required else None
    if dry_run:
        result.status = "dry_run"
        result.reason = approval or "dry run, nothing executed"
        if binary is None:
            result.reason += f"; {plugin.name} not found: {plugin.install_hint}"
        return False
    if approval:
        result.status, result.reason = "needs_approval", approval
        return False
    if binary is None:
        result.status = "missing_binary"
        result.reason = f"{plugin.name} not found: {plugin.install_hint}"
        return False
    return True


async def execute(
    ctx: ToolContext, tool: str, result: ToolResult, timeout: float, log_path: Path
) -> RunResult | None:
    """Run result.argv and record the outcome; None means there is nothing to parse."""
    try:
        run = await ctx.runner.run(result.argv, timeout, log_path)
    except OSError as exc:
        result.status, result.reason = "failed", f"could not start {tool}: {exc}"
        return None
    result.exit_code = run.exit_code
    result.duration_s = run.duration_s
    result.raw_output_path = str(run.raw_output_path)
    if run.timed_out:
        result.status, result.reason = "timed_out", f"timed out after {run.duration_s}s"
        result.output = run.output
        return None
    return run


def parse_failed(result: ToolResult, tool: str, run: RunResult, error: str) -> None:
    result.status = "failed"
    result.reason = f"{tool} exited {run.exit_code}: {error}"
    result.output = run.output


def set_exit_status(
    result: ToolResult, tool: str, run: RunResult, done: str = "scan completed"
) -> None:
    if run.exit_code == 0:
        result.status, result.reason = "completed", done
    else:
        result.status, result.reason = "failed", f"{tool} exited {run.exit_code}"
        result.output = run.output


def write_targets(path: Path, urls: list[str]) -> None:
    """Write checked targets one per line for a tool's list input."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text("".join(f"{url}\n" for url in urls), encoding="utf-8")
