# secmcp

[![M8ven Score](https://m8ven.ai/badge/mcp/j4xd-secmcp-d4w6sp?v=2fcc80132c5d66fab8409b85c0a15884)](https://m8ven.ai/mcp/j4xd-secmcp-d4w6sp?s=readme)

secmcp is an MCP server that lets AI assistants run security tools for authorized
penetration testing and bug bounty work. Every tool call is checked against a scope
file and a per-tool flag policy before anything runs, and every call is audited.

It ships nmap, httpx, ffuf and nuclei, plus a report helper that turns the audit
log and saved results into a Markdown bug bounty report draft.

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

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/), Linux or macOS, and the
tools you want to use. Missing tools are reported with an install hint when called.

```sh
sudo apt install nmap        # or: brew install nmap
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# secmcp, from a checkout of this repository
uv tool install .
secmcp --version
```

The Python `httpx` package also installs an `httpx` command on some systems. If
that one comes first on PATH, point secmcp at ProjectDiscovery's binary with
`binaries: {httpx: /path/to/httpx}`.

`secmcp check` lists each tool's binary, or an install hint for the missing ones,
and exits 1 if any is missing.

### Docker

The image has nmap, httpx, ffuf, nuclei and the nuclei templates preinstalled. It
runs as an unprivileged user and expects the scope file at `/config/scope.yaml`.

```sh
docker build -t secmcp .
docker run --rm -v "$PWD/scope.yaml:/config/scope.yaml:ro" secmcp check
```

Tool versions are pinned with build arguments (`HTTPX_VERSION`, `NUCLEI_VERSION`,
`FFUF_VERSION`). Rebuild to update the nuclei templates.

The audit log, raw output and reports go to `/home/secmcp/.local/share/secmcp`, the
default `data_dir`. Mount a volume there to keep them. Wordlists are not included;
mount yours read-only at a path listed in `wordlist_dirs`.

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
  httpx: 600
  ffuf: 1800
  nuclei: 3600
rate_limits:              # requests per second, the most a call may ask for
  httpx: 50
  ffuf: 50
  nuclei: 50
wordlist_dirs:            # ffuf only reads wordlists inside these directories
  - /usr/share/seclists
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

With Docker, run the image with `-i` so stdio stays open:

```json
{
  "mcpServers": {
    "secmcp": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/path/to/scope.yaml:/config/scope.yaml:ro",
        "-v", "secmcp-data:/home/secmcp/.local/share/secmcp",
        "-v", "/usr/share/seclists:/usr/share/seclists:ro",
        "secmcp"
      ]
    }
  }
}
```

## Example usage

Tools:

| Tool | Purpose |
| --- | --- |
| `check_scope(target)` | Explain whether a target is in scope, without sending it traffic |
| `check_tools()` | List each tool, whether its binary is installed, its allowed flags and what needs approval |
| `run_nmap(target, scan_type, ports?, extra_args?, dry_run?, confirm?)` | Run a scan and return parsed results |
| `run_httpx(targets, rate_limit?, extra_args?, dry_run?, confirm?)` | Probe web servers: status, title, server, tech, ip |
| `run_ffuf(url, wordlist, rate_limit?, extra_args?, dry_run?, confirm?)` | Content discovery with `FUZZ` in the url path or query |
| `run_nuclei(targets, severity?, tags?, exclude_tags?, template_ids?, rate_limit?, extra_args?, dry_run?, confirm?)` | Run nuclei templates and return findings |
| `get_audit_log(limit)` | Return the most recent audit records |
| `generate_report(target?, since?, until?)` | Draft a Markdown report from the audit log and saved results |

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

The web tools take urls (`https://app.example.com/login`) or `host[:port]` values.
For example, `run_ffuf` with
`{"url": "https://app.example.com/FUZZ", "wordlist": "Discovery/Web-Content/common.txt", "extra_args": ["-mc", "200,301", "-ac"]}`
returns `matches` with the word, url, status, length, words, lines and redirect
location of each hit, and `run_nuclei` with
`{"targets": ["https://app.example.com"], "severity": ["high", "critical"], "tags": ["cve"]}`
returns `findings` with template id, name, severity, tags, matched url and extracted
values.

Other statuses are `blocked`, `needs_approval`, `dry_run`, `missing_binary`,
`timed_out` and `failed`, each with a `reason`.

## Report drafts

The report helper reads the audit log and the output files saved under
`data_dir/runs/` and writes a Markdown draft with these sections: summary, scope,
methodology (every command run, in order), findings grouped by host and severity,
evidence file references, and empty impact and remediation sections for you to
write.

From the command line:

```sh
secmcp report --scope scope.yaml --target example.com \
  --since 2026-11-24 --until 2026-11-25 -o report.md
```

Without `-o` the draft goes to stdout. From an MCP client, `generate_report` takes
the same filters, saves the draft to `data_dir/reports/` and returns it.

- `target` is a domain (subdomains included), an IP or a CIDR. It matches calls
  whose target is that host or inside that range, and findings from multi-target
  httpx, ffuf and nuclei runs are filtered by host too. Without it, every call is
  included.
- `since` is inclusive and `until` is exclusive, so `--until 2026-11-25` covers all
  of November 24. Times without a zone are UTC.
- Only calls that ran are listed. Blocked calls and dry runs are counted in the
  summary.
- Findings are nuclei results at their template severity, plus open nmap ports,
  responding httpx hosts and ffuf matches as info. The same finding from several
  runs is listed once with every evidence file.
- Tool output such as page titles is put in code spans or escaped, so a hostile
  target cannot inject Markdown or HTML into the draft.

## Security model

Scope guard

- nmap targets may be an IP, a CIDR (at most 65536 addresses) or a hostname. URLs,
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

Web targets

- httpx, ffuf and nuclei accept only `http` and `https` urls or `host[:port]`. URLs
  with credentials, backslashes, whitespace or control characters are refused, and
  the url is rebuilt from the parsed host so the tool sees exactly the host that was
  checked.
- If any target in a call is out of scope, the whole call is refused.
- Targets are written to a list file instead of the command line, because httpx and
  nuclei split command line targets on commas.
- These tools connect by name, so a name could re-resolve after the check. As a
  backstop, httpx gets a `-deny` list of excluded networks, metadata addresses and
  private ranges that no allow entry covers, and nuclei gets `-lna` (no local or
  private network access) unless the scope allows a private range.
- Following redirects to other hosts is off: httpx and nuclei may only use their
  same-host redirect options, nuclei runs with `-dr`, and ffuf's `-r` is refused.
- Request rates default to the cap in `rate_limits` and a call can only go lower.

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
- ffuf wordlists must resolve, after following symlinks, to a file inside one of
  `wordlist_dirs`. `FUZZ` must be in the url path or query, never in the host.
  `-input-cmd`, raw request files, proxies, custom headers and output options are
  refused.
- nuclei runs only the installed template set: custom template paths, template
  urls, workflows, code, file, headless and dast templates are refused. Templates
  tagged `intrusive`, `dos`, `fuzz`, `fuzzing`, `bruteforce`, `default-login`,
  `token-spray`, `file-upload`, `fileupload` or `file-write` are always excluded
  unless you request the tag and approve it. Interactsh is off (`-ni`), so no data
  goes to the public OAST servers.
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
- The report helper only reads output files inside `data_dir/runs/`, so an edited
  audit log cannot make it read other files. The MCP tool cannot choose where the
  draft is written.

## Limitations

- sqlmap is not supported.
- Linux and macOS only, since the runner relies on POSIX process groups.
- Only the first resolved address of a hostname is scanned (IPv4 preferred), the same
  as nmap's default.
- `-sS`, `-sU` and `-O` need root. secmcp does not escalate privileges, and the
  Docker image runs as an unprivileged user, so nmap uses connect scans there.
- Scripts can be named only when nmap's `script.db` is found. Categories work
  without it. Set `nmap_script_db` if it lives somewhere unusual.
- nmap still does reverse DNS lookups unless you pass `-n`.
- Domain exclusions match names only. To keep a host's address out of scope as well,
  exclude its IP or CIDR.
- The audit log is append-only by convention, not tamper-proof. Ship it elsewhere if
  you need that.
- httpx, ffuf and nuclei resolve hostnames again when they connect. The deny list
  and `-lna` cover excluded and private networks, but ffuf has no equivalent option,
  and a name that moves to another public address is not caught. Prefer IP targets
  when that matters.
- nuclei templates that need interactsh (blind SSRF, OOB checks) do not run.
- Custom headers and cookies are not supported yet for the web tools.
- Tool config files in your home directory (such as `~/.config/ffuf/ffufrc` or
  nuclei's config) are still read by the tools.
- Scope is enforced on the target you pass. It cannot stop a service on an in-scope
  host from redirecting or proxying your traffic.
- Report drafts are a starting point. Findings are tool output, not verified
  vulnerabilities; confirm each one before you submit it. A hostname filter does not
  match nmap scans that were run against the IP address.

## Development

```sh
uv sync
uv run ruff check && uv run ruff format --check
uv run mypy
uv run pytest
```

Tests mock subprocess and DNS and never touch the network. The runner tests start
local Python processes to check timeouts and process group cleanup.

### Adding a tool

Each tool is one module in `src/secmcp/tools/` that ends with a `PLUGIN`
declaration: its allowed, blocked and dangerous flags, install hint, output suffix,
parse error and a `register` function that adds its MCP tool. The parser goes in
`src/secmcp/parsers/`. To add a tool:

1. Write the parser and the tool module, following `tools/httpx.py`. Build argv as a
   list, check targets with `scope.py` or `targets.py`, parse extra flags with
   `policy.parse_args`, and finish every path through `common.audit`.
2. Add the plugin to `PLUGINS` in `tools/__init__.py`.
3. Add the name to `ToolName` and a default to `Timeouts` in `config.py` (and to
   `RateLimits` if it sends requests at a rate).
4. Add a report section for its findings in `report.py` if it has any.

Tools must not accept a raw command or arbitrary file paths.

## License

MIT, see [LICENSE](LICENSE).

## Legal note

Only test systems you own or are explicitly authorized to test, and stay within the
rules of the program you are working on. For a live demo, add `scanme.nmap.org` to
your scope file; the nmap project allows light scanning of that host.
