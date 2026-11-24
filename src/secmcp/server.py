"""MCP server exposing policy-checked security tools over stdio."""

import argparse
import os
import sys
from pathlib import Path
from typing import Annotated

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from secmcp import __version__
from secmcp.audit import AuditRecord, append_record, read_records
from secmcp.config import ConfigError, load_config
from secmcp.context import ToolContext
from secmcp.scope import ScopeDecision, check_target
from secmcp.tools import nmap

INSTRUCTIONS = """\
secmcp runs security tools against targets that are in the operator's scope file.
Call check_scope before scanning a new target. Use dry_run=true to preview a command.
Show any needs_approval result to the human; only they can approve it.
"""


class AuditLogResult(BaseModel):
    records: list[AuditRecord]


def build_server(ctx: ToolContext) -> MCPServer:
    """Create the MCP server with all tools bound to ctx."""
    server = MCPServer("secmcp", instructions=INSTRUCTIONS, version=__version__)

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False)
    )
    async def check_scope(
        target: Annotated[str, Field(description="IP address, CIDR or hostname")],
    ) -> ScopeDecision:
        """Check whether a target is in scope without sending it any traffic."""
        decision = await anyio.to_thread.run_sync(
            check_target, target, ctx.scope, ctx.resolve
        )
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

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=False, open_world_hint=True
        )
    )
    async def run_nmap(
        target: Annotated[
            str, Field(description="IP address, CIDR or hostname in scope")
        ],
        scan_type: Annotated[
            nmap.ScanType,
            Field(
                description="quick: top 100 ports, top_ports: top 1000 ports, "
                "service_version: top 1000 ports with version detection"
            ),
        ] = "quick",
        ports: Annotated[
            str | None,
            Field(
                description="ports to scan instead of the scan type's set, "
                "e.g. 22,80,8000-8100"
            ),
        ] = None,
        extra_args: Annotated[
            list[str] | None,
            Field(
                description="extra nmap flags, one list item per token. Allowed: "
                + " ".join(sorted(nmap.ALLOWED_FLAGS))
            ),
        ] = None,
        dry_run: Annotated[
            bool, Field(description="return the exact command without running it")
        ] = False,
        confirm: Annotated[
            bool,
            Field(
                description="set only after a human approved a needs_approval result"
            ),
        ] = False,
    ) -> nmap.NmapResult:
        """Run an nmap scan after scope and flag checks and return parsed results."""
        return await nmap.run_nmap(
            ctx, target, scan_type, ports, extra_args, dry_run, confirm
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

    return server


def main(argv: list[str] | None = None) -> None:
    """Load the scope file and serve over stdio."""
    parser = argparse.ArgumentParser(prog="secmcp", description=__doc__)
    parser.add_argument(
        "--scope",
        type=Path,
        default=Path(os.environ.get("SECMCP_SCOPE", "scope.yaml")),
        help="path to scope.yaml (default: $SECMCP_SCOPE or ./scope.yaml)",
    )
    parser.add_argument("--version", action="version", version=f"secmcp {__version__}")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.scope)
    except ConfigError as exc:
        sys.exit(f"secmcp: {exc}")
    build_server(ToolContext.from_config(config)).run("stdio")
