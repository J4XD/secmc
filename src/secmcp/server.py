"""MCP server exposing policy-checked security tools over stdio."""

import argparse
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from secmcp import __version__
from secmcp.audit import AuditRecord, append_record, read_records
from secmcp.config import ConfigError, load_config
from secmcp.context import ToolContext
from secmcp.parsers.nuclei_jsonl import Severity
from secmcp.scope import check_target
from secmcp.targets import MAX_TARGETS, UrlDecision, check_url
from secmcp.tools import ffuf, httpx, nmap, nuclei

INSTRUCTIONS = """\
secmcp runs security tools against targets that are in the operator's scope file.
Call check_scope before scanning a new target. Use dry_run=true to preview a command.
Show any needs_approval result to the human; only they can approve it.
"""

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


def _extra_args(allowed: Mapping[str, object], tool: str) -> Any:
    return Field(
        description=f"extra {tool} flags, one list item per token. Allowed: "
        + " ".join(sorted(allowed))
    )


def scope_check(target: str, ctx: ToolContext) -> UrlDecision:
    """Check a host, ip, cidr or url target against the scope."""
    if "://" in target:
        return check_url(target, ctx.scope, ctx.resolve)
    decision = check_target(target, ctx.scope, ctx.resolve)
    return UrlDecision(**decision.model_dump())


class AuditLogResult(BaseModel):
    records: list[AuditRecord]


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
            list[str] | None, _extra_args(nmap.ALLOWED_FLAGS, "nmap")
        ] = None,
        dry_run: DryRun = False,
        confirm: Confirm = False,
    ) -> nmap.NmapResult:
        """Run an nmap scan after scope and flag checks and return parsed results."""
        return await nmap.run_nmap(
            ctx, target, scan_type, ports, extra_args, dry_run, confirm
        )

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=False, open_world_hint=True
        )
    )
    async def run_httpx(
        targets: WebTargets,
        rate_limit: RateLimit = None,
        extra_args: Annotated[
            list[str] | None, _extra_args(httpx.ALLOWED_FLAGS, "httpx")
        ] = None,
        dry_run: DryRun = False,
        confirm: Confirm = False,
    ) -> httpx.HttpxResult:
        """Probe web servers with httpx: status, title, server, tech and ip."""
        return await httpx.run_httpx(
            ctx, targets, rate_limit, extra_args, dry_run, confirm
        )

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=False, open_world_hint=True
        )
    )
    async def run_ffuf(
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
            list[str] | None, _extra_args(ffuf.ALLOWED_FLAGS, "ffuf")
        ] = None,
        dry_run: DryRun = False,
        confirm: Confirm = False,
    ) -> ffuf.FfufResult:
        """Discover content with ffuf using an allowlisted wordlist."""
        return await ffuf.run_ffuf(
            ctx, url, wordlist, rate_limit, extra_args, dry_run, confirm
        )

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=False, open_world_hint=True
        )
    )
    async def run_nuclei(
        targets: WebTargets,
        severity: Annotated[
            list[Severity] | None,
            Field(description="only run templates with these severities"),
        ] = None,
        tags: Annotated[
            list[str] | None,
            Field(
                description="only run templates with these tags. Tags that need "
                "approval: " + " ".join(nuclei.DANGEROUS_TAGS)
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
            list[str] | None, _extra_args(nuclei.ALLOWED_FLAGS, "nuclei")
        ] = None,
        dry_run: DryRun = False,
        confirm: Confirm = False,
    ) -> nuclei.NucleiResult:
        """Run nuclei templates; intrusive tags are excluded unless approved."""
        return await nuclei.run_nuclei(
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
