"""MCP server exposing policy-checked security tools over stdio."""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from secmcp import __version__
from secmcp.audit import AuditRecord, append_record, read_records
from secmcp.config import Config, ConfigError, load_config
from secmcp.context import ToolContext
from secmcp.report import ReportError, ReportResult, build_report, write_report
from secmcp.scope import check_target
from secmcp.targets import UrlDecision, check_url
from secmcp.tools import PLUGINS
from secmcp.tools.common import ToolStatus, tool_status

INSTRUCTIONS = """\
secmcp runs security tools against targets that are in the operator's scope file.
Call check_scope before scanning a new target. Use dry_run=true to preview a command.
Show any needs_approval result to the human; only they can approve it.
"""


def scope_check(target: str, ctx: ToolContext) -> UrlDecision:
    """Check a host, ip, cidr or url target against the scope."""
    if "://" in target:
        return check_url(target, ctx.scope, ctx.resolve)
    decision = check_target(target, ctx.scope, ctx.resolve)
    return UrlDecision(**decision.model_dump())


class AuditLogResult(BaseModel):
    records: list[AuditRecord]


class ToolsResult(BaseModel):
    tools: list[ToolStatus]


def build_server(ctx: ToolContext) -> MCPServer:
    """Create the MCP server with all tools bound to ctx."""
    server = MCPServer("secmcp", instructions=INSTRUCTIONS, version=__version__)

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False)
    )
    async def check_scope(
        target: Annotated[
            str, Field(description="IP address, CIDR, hostname or http(s) url")
        ],
    ) -> UrlDecision:
        """Check whether a target is in scope without sending it any traffic."""
        decision = await anyio.to_thread.run_sync(scope_check, target, ctx)
        append_record(
            ctx.config.audit_log_path,
            AuditRecord(
                tool="check_scope",
                target=target,
                decision="allowed" if decision.allowed else "blocked",
                reason=decision.reason,
            ),
        )
        return decision

    for plugin in PLUGINS:
        plugin.register(server, ctx)

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False)
    )
    def check_tools() -> ToolsResult:
        """List the wrapped tools, whether each is installed, and its flag policy."""
        return ToolsResult(
            tools=[tool_status(ctx.config, plugin) for plugin in PLUGINS]
        )

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False)
    )
    def get_audit_log(
        limit: Annotated[
            int, Field(ge=1, le=500, description="number of records")
        ] = 20,
    ) -> AuditLogResult:
        """Return the most recent audit log records, oldest first."""
        return AuditLogResult(records=read_records(ctx.config.audit_log_path, limit))

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=False, open_world_hint=False
        )
    )
    async def generate_report(
        target: Annotated[
            str | None,
            Field(
                description="domain (includes subdomains), ip or cidr to report on "
                "(default: every target)"
            ),
        ] = None,
        since: Annotated[
            datetime | None,
            Field(description="include runs at or after this time (UTC if no zone)"),
        ] = None,
        until: Annotated[
            datetime | None,
            Field(description="include runs before this time (UTC if no zone)"),
        ] = None,
    ) -> ReportResult:
        """Draft a Markdown bug bounty report from the audit log and saved results."""
        try:
            return await anyio.to_thread.run_sync(
                write_report, ctx.config, target, since, until
            )
        except ReportError as exc:
            raise ToolError(str(exc)) from None

    return server


def _timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid time {value!r}, expected ISO 8601 such as 2026-11-24T18:00"
        ) from None


def _parser() -> argparse.ArgumentParser:
    scope_default = Path(os.environ.get("SECMCP_SCOPE", "scope.yaml"))
    scope_help = "path to scope.yaml (default: $SECMCP_SCOPE or ./scope.yaml)"
    parser = argparse.ArgumentParser(prog="secmcp", description=__doc__)
    parser.add_argument("--scope", type=Path, default=scope_default, help=scope_help)
    parser.add_argument("--version", action="version", version=f"secmcp {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="command")
    report = commands.add_parser(
        "report", help="print a Markdown report draft built from the audit log"
    )
    # SUPPRESS keeps the subcommand from overwriting a --scope given before it.
    report.add_argument(
        "--scope", type=Path, default=argparse.SUPPRESS, help=scope_help
    )
    report.add_argument(
        "--target", help="domain (includes subdomains), ip or cidr to report on"
    )
    report.add_argument(
        "--since", type=_timestamp, help="include runs at or after this time"
    )
    report.add_argument(
        "--until", type=_timestamp, help="include runs before this time"
    )
    report.add_argument(
        "-o", "--output", type=Path, help="write the draft here instead of stdout"
    )
    check = commands.add_parser(
        "check", help="show which tool binaries are installed; exit 1 if any is missing"
    )
    check.add_argument("--scope", type=Path, default=argparse.SUPPRESS, help=scope_help)
    return parser


def check_binaries(config: Config) -> bool:
    """Print one line per tool; True if every binary was found."""
    statuses = [tool_status(config, plugin) for plugin in PLUGINS]
    width = max(len(status.name) for status in statuses)
    for status in statuses:
        detail = (
            status.binary if status.installed else f"missing: {status.install_hint}"
        )
        print(f"{status.name:<{width}}  {detail}")
    return all(status.installed for status in statuses)


def main(argv: list[str] | None = None) -> None:
    """Serve over stdio, or run the report or check command."""
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.scope)
    except ConfigError as exc:
        sys.exit(f"secmcp: {exc}")
    if args.command == "check":
        sys.exit(0 if check_binaries(config) else 1)
    if args.command != "report":
        build_server(ToolContext.from_config(config)).run("stdio")
        return
    try:
        draft = build_report(config, args.target, args.since, args.until)
    except ReportError as exc:
        sys.exit(f"secmcp: {exc}")
    if args.output is None:
        sys.stdout.write(draft.markdown)
        return
    try:
        args.output.write_text(draft.markdown, encoding="utf-8")
    except OSError as exc:
        sys.exit(f"secmcp: cannot write {args.output}: {exc.strerror}")
    print(
        f"wrote {args.output}: {draft.runs} runs, {draft.findings} findings",
        file=sys.stderr,
    )
