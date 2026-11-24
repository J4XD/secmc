# secmcp

secmcp is an MCP server that lets AI assistants run security tools for authorized
penetration testing and bug bounty work. Every tool call is checked against a scope
file and a per-tool flag policy before anything runs, and every call is audited.

Phase 1 ships nmap. httpx, ffuf, nuclei and sqlmap are planned.

## Why

Existing MCP wrappers for these tools pass the model's arguments straight through.
The model can scan any host, add flags that write files or open shells, hang a tool
on an interactive prompt, and get raw terminal output dumped into its context.
secmcp is safe by default instead:

- targets must be in your scope file, and exclusions always win
- only allowlisted flags are accepted; dangerous ones need your explicit approval
- tools run without a shell, with timeouts, closed stdin and capped output
- results come back as structured data, with the raw output saved to disk
- there is no generic shell command tool, and there will not be one

## Install

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/), Linux or macOS, and nmap.

```sh
# nmap
sudo apt install nmap        # or: brew install nmap

# secmcp, from a checkout of this repository
uv tool install .
secmcp --version
```

## Configure scope

```sh
cp scope.example.yaml scope.yaml
```

```yaml
allow:
  - 203.0.113.0/24        # CIDR
  - 198.51.100.7          # single IP
  - example.com           # exact domain
  - "*.example.com"       # any subdomain, not the apex
exclude:
  - 203.0.113.1
  - admin.example.com
  - "*.internal.example.com"
allow_dangerous: false
timeouts:
  nmap: 900
data_dir: ~/.local/share/secmcp
```

All keys are listed in `scope.example.yaml`. Unknown keys are rejected so typos do
not silently weaken the policy. The audit log is written to `data_dir/audit.jsonl`
and raw tool output to `data_dir/runs/`.

## Connect to an MCP client

secmcp speaks MCP over stdio. Use absolute paths.

Claude Code:

```sh
claude mcp add secmcp -- secmcp --scope /path/to/scope.yaml
```

Claude Desktop and other clients that use an `mcpServers` config:

```json
{
  "mcpServers": {
    "secmcp": {
      "command": "secmcp",
      "args": ["--scope", "/path/to/scope.yaml"]
    }
  }
}
```

The scope path can also be set with `SECMCP_SCOPE`.

## Example usage

Tools:

| Tool | Purpose |
| --- | --- |
| `check_scope(target)` | Explain whether a target is in scope, without sending it traffic |
| `run_nmap(target, scan_type, ports?, extra_args?, dry_run?, confirm?)` | Run a scan and return parsed results |
| `get_audit_log(limit)` | Return the most recent audit records |

`scan_type` is one of `quick` (top 100 ports), `top_ports` (top 1000) or
`service_version` (top 1000 with `-sV`). `extra_args` is a list with one token per
item, for example `["-Pn", "--script", "http-title"]`.

A prompt such as "check whether scanme.nmap.org is in scope, then run a
service_version scan on ports 22 and 80" leads to calls like:

```json
{"target": "scanme.nmap.org", "scan_type": "service_version", "ports": "22,80"}
```

which return (abbreviated):

```json
{
  "status": "completed",
  "summary": "1 of 1 hosts up\n45.33.32.156 (scanme.nmap.org): 2 open: 22/tcp ssh OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13, 80/tcp http Apache httpd 2.4.7",
  "hosts": [{"address": "45.33.32.156", "state": "up", "ports": [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "6.6.1p1 Ubuntu 2ubuntu2.13", "scripts": []}]}],
  "argv": ["/usr/bin/nmap", "-sV", "-p", "22,80", "-oX", "/home/me/.local/share/secmcp/runs/nmap-20261124T120000Z-1a2b3c4d.xml", "45.33.32.156"],
  "raw_output_path": "/home/me/.local/share/secmcp/runs/nmap-20261124T120000Z-1a2b3c4d.log"
}
```

Other statuses are `blocked`, `needs_approval`, `dry_run`, `missing_binary`,
`timed_out` and `failed`, each with a `reason`.

## Security model

Scope guard

- Targets may be an IP, a CIDR (at most 65536 addresses) or a hostname. URLs,
  values starting with `-`, and numeric shorthand such as `127.1` are rejected.
- Exclusions are checked first and always win.
- Hostnames must match an allowed domain or wildcard, then are resolved. Every
  resolved address is checked against exclusions and restricted ranges. If any
  address fails, the target is refused.
- The scan runs against the address that was checked, not the name, so a DNS
  change between check and scan cannot redirect it.
- Private, loopback, link-local, multicast and reserved addresses are refused
  unless an IP or CIDR allow entry covers them. Cloud metadata addresses
  (169.254.169.254, 169.254.170.2, 100.100.100.200, 168.63.129.16, fd00:ec2::254)
  additionally need their own single-address allow entry.

Flag policy

- Each tool has an allowlist of flags and validates each flag's value. Unknown flags
  are rejected.
- Flags that set output paths, read targets from files, load data from other paths,
  spoof sources or pass script arguments are rejected with a specific reason.
- Bare values (extra targets), values starting with `-` where a value is expected,
  control characters and shell metacharacters are rejected.
- nmap scripts are checked against nmap's `script.db`. Scripts in the `intrusive`,
  `exploit`, `dos` or `brute` categories need approval. `broadcast` scripts and
  `--script all` are always refused because they send traffic beyond the target.
- Approval means `allow_dangerous: true` in scope.yaml and `confirm=true` on the
  call. Without both, the tool returns `needs_approval` and lists what is missing.

Runner

- Commands are argument lists passed to `exec`; no shell is involved.
- Each run gets its own process group, which is killed on timeout or cancellation.
- stdin is closed, so tools cannot wait for input.
- Output is written to disk in full, and the copy returned to the model is capped.
- At most `max_concurrency` tools run at once.
- `dry_run=true` returns the exact argv after all checks, without running anything.

Audit log

- Every call, including blocked ones and `check_scope`, is appended to
  `audit.jsonl` with timestamp, tool, target, argv, dry_run, decision, reason, exit
  code, duration and raw output path.

## Limitations

- Linux and macOS only, since the runner relies on POSIX process groups.
- Only the first resolved address of a hostname is scanned (IPv4 preferred), the same
  as nmap's default.
- `-sS`, `-sU` and `-O` need root. secmcp does not escalate privileges.
- Scripts can be named only when nmap's `script.db` is found. Categories work
  without it. Set `nmap_script_db` if it lives somewhere unusual.
- nmap still does reverse DNS lookups unless you pass `-n`.
- Domain exclusions match names only. To keep a host's address out of scope as well,
  exclude its IP or CIDR.
- The audit log is append-only by convention, not tamper-proof. Ship it elsewhere if
  you need that.
- Scope is enforced on the target you pass. It cannot stop a service on an in-scope
  host from redirecting or proxying your traffic.

## Development

```sh
uv sync
uv run ruff check && uv run ruff format --check
uv run mypy
uv run pytest
```

Tests mock subprocess and DNS and never touch the network. The runner tests start
local Python processes to check timeouts and process group cleanup.

## License

MIT, see [LICENSE](LICENSE).

## Legal note

Only test systems you own or are explicitly authorized to test, and stay within the
rules of the program you are working on. For a live demo, add `scanme.nmap.org` to
your scope file; the nmap project allows light scanning of that host.
