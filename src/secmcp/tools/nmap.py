"""nmap wrapper: argument policy, script gating and execution."""

import ipaddress
import re
from functools import cache
from pathlib import Path
from typing import Annotated, Literal

import anyio
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from secmcp.context import ToolContext
from secmcp.parsers.nmap_xml import Host, NmapParseError, parse_nmap_xml
from secmcp.policy import (
    Flag,
    ParsedFlag,
    PolicyError,
    duration,
    int_between,
    parse_args,
    port_list,
)
from secmcp.runner import RunResult
from secmcp.scope import ScopeDecision, check_target
from secmcp.tools.common import (
    RUNS_TOOL,
    Confirm,
    DryRun,
    Plugin,
    ToolResult,
    audit,
    execute,
    extra_args_field,
    locate,
    parse_failed,
    ready_to_run,
    run_paths,
    set_exit_status,
)

ScanType = Literal["quick", "top_ports", "service_version"]

SCAN_TYPES: dict[str, tuple[list[str], list[str]]] = {
    "quick": (["-T4"], ["-F"]),
    "top_ports": ([], ["--top-ports", "1000"]),
    "service_version": (["-sV"], ["--top-ports", "1000"]),
}

SCRIPT_CATEGORIES = frozenset(
    {
        "auth",
        "broadcast",
        "brute",
        "default",
        "discovery",
        "dos",
        "exploit",
        "external",
        "fuzzer",
        "intrusive",
        "malware",
        "safe",
        "version",
        "vuln",
    }
)
DANGEROUS_CATEGORIES = frozenset({"intrusive", "exploit", "dos", "brute"})
SCRIPT_DB_LOCATIONS = (
    Path("/usr/share/nmap/scripts/script.db"),
    Path("/usr/local/share/nmap/scripts/script.db"),
    Path("/opt/homebrew/share/nmap/scripts/script.db"),
)
_SCRIPT_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]*")
_SCRIPT_DB_ENTRY = re.compile(
    r'Entry\s*\{\s*filename\s*=\s*"([^"]+)\.nse"\s*,\s*categories\s*=\s*\{([^}]*)\}'
)


def _script_names(value: str) -> str | None:
    for name in value.split(","):
        if not _SCRIPT_NAME.fullmatch(name):
            return "expected comma-separated script names or categories"
    return None


ALLOWED_FLAGS: dict[str, Flag] = {
    "-Pn": Flag(),
    "-n": Flag(),
    "-sS": Flag(),
    "-sT": Flag(),
    "-sU": Flag(),
    "-sV": Flag(),
    "-sC": Flag(),
    "-O": Flag(),
    "-v": Flag(),
    "--open": Flag(),
    "--reason": Flag(),
    "--traceroute": Flag(),
    "--version-light": Flag(),
    "--version-all": Flag(),
    **{f"-T{level}": Flag() for level in range(6)},
    "--version-intensity": Flag(int_between(0, 9)),
    "--max-retries": Flag(int_between(0, 10)),
    "--min-rate": Flag(int_between(1, 10_000)),
    "--max-rate": Flag(int_between(1, 10_000)),
    "--host-timeout": Flag(duration),
    "--scan-delay": Flag(duration),
    "--max-scan-delay": Flag(duration),
    "--exclude-ports": Flag(port_list),
    "--script": Flag(_script_names),
}

BLOCKED_FLAGS: dict[str, str] = {
    "-o": "output paths are set by secmcp",
    "--append-output": "output paths are set by secmcp",
    "--stylesheet": "output paths are set by secmcp",
    "-i": "targets come only from the target argument",
    "--script-args": "script arguments can add targets or read files",
    "--script-args-file": "script arguments can add targets or read files",
    "--datadir": "loading nmap data from other paths is not allowed",
    "--servicedb": "loading nmap data from other paths is not allowed",
    "--versiondb": "loading nmap data from other paths is not allowed",
    "--resume": "resuming scans from files is not allowed",
    "-p": "use the ports argument",
    "-F": "use scan_type or the ports argument",
    "--top-ports": "use scan_type or the ports argument",
    "-6": "the address family follows the target",
    "-S": "source spoofing is not allowed",
    "-D": "decoys are not allowed",
    "-e": "interface selection is not allowed",
    "--spoof-mac": "source spoofing is not allowed",
    "--proxies": "proxies are not allowed",
}


class NmapResult(ToolResult):
    target: str
    scope: ScopeDecision | None = None
    hosts: list[Host] = Field(default_factory=list)
    xml_path: str | None = None


def load_script_db(path: Path) -> dict[str, frozenset[str]]:
    """Map script names to their categories from nmap's script.db."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return {
        name: frozenset(re.findall(r'"([^"]+)"', categories))
        for name, categories in _SCRIPT_DB_ENTRY.findall(text)
    }


def find_script_db(configured: Path | None, binary: str | None) -> Path | None:
    """Find script.db: the configured path, then next to the binary, then defaults."""
    if configured:
        return configured if configured.is_file() else None
    candidates = list(SCRIPT_DB_LOCATIONS)
    if binary:
        prefix = Path(binary).resolve().parent.parent
        candidates.insert(0, prefix / "share" / "nmap" / "scripts" / "script.db")
    return next((path for path in candidates if path.is_file()), None)


@cache
def _cached_script_db(path: Path) -> dict[str, frozenset[str]]:
    return load_script_db(path)


def script_risks(value: str, script_db: dict[str, frozenset[str]] | None) -> list[str]:
    """List scripts in a --script value that need approval; raise if any is blocked."""
    risks = []
    for name in value.split(","):
        if name == "all":
            raise PolicyError("--script all is not allowed")
        if name in SCRIPT_CATEGORIES:
            categories = frozenset({name})
        elif script_db is None:
            raise PolicyError(
                "cannot verify nmap script categories: script.db not found, "
                "set nmap_script_db in scope.yaml"
            )
        elif name not in script_db:
            raise PolicyError(f"unknown nmap script {name!r}")
        else:
            categories = script_db[name]
        if "broadcast" in categories:
            raise PolicyError(
                f"script {name} is not allowed: it sends traffic beyond the target"
            )
        dangerous = sorted(categories & DANGEROUS_CATEGORIES)
        if dangerous:
            risks.append(f"--script {name} ({', '.join(dangerous)})")
    return risks


def check_flags(
    ports: str | None,
    extra_args: list[str],
    script_db: dict[str, frozenset[str]] | None,
) -> tuple[list[ParsedFlag], list[str]]:
    """Validate ports and extra arguments; return parsed flags and approval reasons."""
    if ports is not None:
        error = port_list(ports)
        if error:
            raise PolicyError(error)
    flags = parse_args(extra_args, ALLOWED_FLAGS, BLOCKED_FLAGS)
    risks = []
    for flag in flags:
        if flag.dangerous:
            risks.append(f"{flag.name} ({flag.dangerous})")
        if flag.name == "--script" and flag.value:
            risks.extend(script_risks(flag.value, script_db))
    return flags, risks


def build_argv(
    binary: str,
    scan_type: ScanType,
    ports: str | None,
    flags: list[ParsedFlag],
    scan_target: str,
    xml_path: Path,
) -> list[str]:
    """Assemble the nmap command line; the target always comes last."""
    base, port_flags = SCAN_TYPES[scan_type]
    argv = [binary, *base]
    argv += ["-p", ports] if ports else port_flags
    for flag in flags:
        argv += flag.argv()
    if _is_ipv6(scan_target):
        argv.append("-6")
    argv += ["-oX", str(xml_path), scan_target]
    return argv


def _is_ipv6(target: str) -> bool:
    return ipaddress.ip_network(target, strict=False).version == 6


def _finish(result: NmapResult, run: RunResult, xml_path: Path) -> NmapResult:
    result.xml_path = str(xml_path)
    try:
        scan = parse_nmap_xml(xml_path.read_bytes())
    except (OSError, NmapParseError) as exc:
        parse_failed(result, "nmap", run, str(exc))
        return result
    result.hosts, result.summary = scan.hosts, scan.summary
    set_exit_status(result, "nmap", run)
    return result


async def run_nmap(
    ctx: ToolContext,
    target: str,
    scan_type: ScanType = "quick",
    ports: str | None = None,
    extra_args: list[str] | None = None,
    dry_run: bool = False,
    confirm: bool = False,
) -> NmapResult:
    """Check scope and flag policy, then run nmap and parse its XML output."""
    decision = await anyio.to_thread.run_sync(
        check_target, target, ctx.scope, ctx.resolve
    )
    result = NmapResult(
        status="blocked", reason=decision.reason, target=target, scope=decision
    )
    if not decision.allowed or decision.scan_target is None:
        return audit(ctx, "nmap", target, result, dry_run)

    binary = locate(ctx.config, "nmap")
    script_db_path = find_script_db(ctx.config.nmap_script_db, binary)
    script_db = _cached_script_db(script_db_path) if script_db_path else None
    try:
        flags, risks = check_flags(ports, extra_args or [], script_db)
    except PolicyError as exc:
        result.reason = str(exc)
        return audit(ctx, "nmap", target, result, dry_run)

    xml_path, log_path = run_paths(ctx.config.runs_dir, "nmap", ".xml")
    result.argv = build_argv(
        binary or "nmap", scan_type, ports, flags, decision.scan_target, xml_path
    )
    result.approval_required = risks
    if not ready_to_run(ctx.config, PLUGIN, binary, result, dry_run, confirm):
        return audit(ctx, "nmap", target, result, dry_run)
    run = await execute(ctx, "nmap", result, ctx.config.timeouts.nmap, log_path)
    if run is not None:
        _finish(result, run, xml_path)
    return audit(ctx, "nmap", target, result, dry_run)


def register(server: MCPServer, ctx: ToolContext) -> None:
    """Add the run_nmap tool to the server."""

    @server.tool(name="run_nmap", annotations=RUNS_TOOL)
    async def tool(
        target: Annotated[
            str, Field(description="IP address, CIDR or hostname in scope")
        ],
        scan_type: Annotated[
            ScanType,
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
            list[str] | None, extra_args_field(ALLOWED_FLAGS, "nmap")
        ] = None,
        dry_run: DryRun = False,
        confirm: Confirm = False,
    ) -> NmapResult:
        """Run an nmap scan after scope and flag checks and return parsed results."""
        return await run_nmap(
            ctx, target, scan_type, ports, extra_args, dry_run, confirm
        )


PLUGIN = Plugin(
    name="nmap",
    summary="port scans and service detection",
    install_hint="install nmap (apt install nmap, brew install nmap) "
    "or get it from https://nmap.org/download",
    allowed_flags=ALLOWED_FLAGS,
    blocked_flags=BLOCKED_FLAGS,
    dangerous={
        f"--script {category}": f"scripts in the {category} category"
        for category in sorted(DANGEROUS_CATEGORIES)
    },
    output_suffix=".xml",
    parse_error=NmapParseError,
    register=register,
)
