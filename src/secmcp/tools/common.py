"""Result model and run steps shared by the tool wrappers."""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import BaseModel

from secmcp.audit import AuditRecord, append_record
from secmcp.config import Config, ToolName
from secmcp.context import ToolContext
from secmcp.policy import PolicyError
from secmcp.runner import RunResult, find_binary, install_hint

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


def locate(config: Config, tool: ToolName) -> str | None:
    """Return the configured binary path if it is executable, else search PATH."""
    configured = config.binaries.get(tool)
    if configured is None:
        return find_binary(tool)
    return find_binary(str(configured))


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
    tool: str,
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
            result.reason += f"; {tool} not found: {install_hint(tool)}"
        return False
    if approval:
        result.status, result.reason = "needs_approval", approval
        return False
    if binary is None:
        result.status = "missing_binary"
        result.reason = f"{tool} not found: {install_hint(tool)}"
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
