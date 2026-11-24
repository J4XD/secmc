"""Target scope checks against the allow and exclude lists in scope.yaml."""

import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], list[str]]

MAX_NETWORK_ADDRESSES = 65536

METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(address)
    for address in (
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "168.63.129.16",
        "fd00:ec2::254",
    )
)

RESTRICTED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_NUMERIC_LABEL = re.compile(r"(0x[0-9a-f]+|[0-9]+)")


@dataclass(frozen=True)
class ScopeEntry:
    raw: str
    network: IPNetwork | None = None
    domain: str | None = None
    wildcard: bool = False

    def matches_domain(self, host: str) -> bool:
        if self.domain is None:
            return False
        if self.wildcard:
            return host.endswith("." + self.domain)
        return host == self.domain

    def contains(self, address: IPAddress) -> bool:
        return self.network is not None and address in self.network


@dataclass(frozen=True)
class Scope:
    allow: list[ScopeEntry] = field(default_factory=list)
    exclude: list[ScopeEntry] = field(default_factory=list)


class ScopeDecision(BaseModel):
    target: str
    allowed: bool
    reason: str
    kind: Literal["ip", "network", "domain"] | None = None
    addresses: list[str] = []
    scan_target: str | None = None


def normalize_hostname(value: str) -> str:
    """Lowercase and validate a DNS hostname, raising ValueError if it is not one."""
    host = value.strip().rstrip(".").lower()
    if not host or len(host) > 253:
        raise ValueError(f"invalid hostname: {value!r}")
    labels = host.split(".")
    if not all(_LABEL.fullmatch(label) for label in labels):
        raise ValueError(f"invalid hostname: {value!r}")
    # getaddrinfo accepts forms like "127.1" or "0x7f.1" as IPv4 addresses.
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        raise ValueError(f"ambiguous numeric hostname: {value!r}")
    return host


def parse_entry(value: str) -> ScopeEntry:
    """Parse one allow or exclude entry from scope.yaml."""
    raw = value.strip()
    try:
        return ScopeEntry(raw=raw, network=ipaddress.ip_network(raw, strict=True))
    except ValueError:
        pass
    try:
        if raw.startswith("*."):
            return ScopeEntry(
                raw=raw, domain=normalize_hostname(raw[2:]), wildcard=True
            )
        return ScopeEntry(raw=raw, domain=normalize_hostname(raw))
    except ValueError:
        raise ValueError(f"invalid scope entry: {value!r}") from None


def parse_target(value: str) -> IPAddress | IPNetwork | str:
    """Parse a scan target into an address, a network or a normalized hostname."""
    raw = value.strip()
    if not raw:
        raise ValueError("empty target")
    if "://" in raw:
        raise ValueError("expected a host, ip or cidr, not a url")
    if raw.startswith("-"):
        raise ValueError("target must not start with '-'")
    if "/" in raw:
        try:
            return ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            raise ValueError(f"invalid network: {exc}") from None
    try:
        return unmap(ipaddress.ip_address(raw))
    except ValueError:
        pass
    return normalize_hostname(raw)


def unmap(address: IPAddress) -> IPAddress:
    """Return the IPv4 address behind an IPv4-mapped IPv6 address."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def resolve_host(host: str) -> list[str]:
    """Resolve a hostname to its unique IP addresses."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    addresses = {str(info[4][0]).split("%", 1)[0] for info in infos}
    return sorted(addresses)


def restricted_kind(address: IPAddress) -> str | None:
    """Name the non-public range an address belongs to, or None if it is public."""
    if address in METADATA_ADDRESSES:
        return "cloud metadata"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_unspecified:
        return "unspecified"
    if address.is_multicast:
        return "multicast"
    if address.is_private:
        return "private"
    if not address.is_global:
        return "reserved"
    return None


def _explicitly_allowed(address: IPAddress, scope: Scope) -> bool:
    # A metadata address needs its own single-address entry, a broad CIDR is not enough.
    if address in METADATA_ADDRESSES:
        return any(
            entry.network is not None
            and entry.network.num_addresses == 1
            and entry.network.network_address == address
            for entry in scope.allow
        )
    return any(entry.contains(address) for entry in scope.allow)


def _address_problem(address: IPAddress, scope: Scope) -> str | None:
    for entry in scope.exclude:
        if entry.contains(address):
            return f"{address} is excluded by {entry.raw}"
    kind = restricted_kind(address)
    if kind and not _explicitly_allowed(address, scope):
        return f"{address} is a {kind} address and not explicitly allowed"
    return None


def _check_address(raw: str, address: IPAddress, scope: Scope) -> ScopeDecision:
    problem = _address_problem(address, scope)
    if problem is None and not any(entry.contains(address) for entry in scope.allow):
        problem = f"{address} is not in scope"
    if problem:
        return ScopeDecision(target=raw, allowed=False, reason=problem, kind="ip")
    return ScopeDecision(
        target=raw,
        allowed=True,
        reason="in scope",
        kind="ip",
        addresses=[str(address)],
        scan_target=str(address),
    )


def _within(network: IPNetwork, entry: ScopeEntry) -> bool:
    other = entry.network
    if other is None or other.version != network.version:
        return False
    return network.subnet_of(other)  # type: ignore[arg-type]


def _overlaps(network: IPNetwork, entry: ScopeEntry) -> bool:
    other = entry.network
    if other is None or other.version != network.version:
        return False
    return network.overlaps(other)


def _check_network(raw: str, network: IPNetwork, scope: Scope) -> ScopeDecision:
    def blocked(reason: str) -> ScopeDecision:
        return ScopeDecision(target=raw, allowed=False, reason=reason, kind="network")

    if network.num_addresses > MAX_NETWORK_ADDRESSES:
        return blocked(f"{network} is larger than {MAX_NETWORK_ADDRESSES} addresses")
    if not any(_within(network, entry) for entry in scope.allow):
        return blocked(f"{network} is not fully inside an allowed range")
    for entry in scope.exclude:
        if _overlaps(network, entry):
            return blocked(f"{network} overlaps excluded {entry.raw}")
    for address in METADATA_ADDRESSES:
        if address in network and not _explicitly_allowed(address, scope):
            return blocked(f"{network} contains cloud metadata address {address}")
    return ScopeDecision(
        target=raw,
        allowed=True,
        reason="in scope",
        kind="network",
        addresses=[str(network)],
        scan_target=str(network),
    )


def _check_domain(
    raw: str, host: str, scope: Scope, resolve: Resolver
) -> ScopeDecision:
    def blocked(reason: str, addresses: list[str] | None = None) -> ScopeDecision:
        return ScopeDecision(
            target=raw,
            allowed=False,
            reason=reason,
            kind="domain",
            addresses=addresses or [],
        )

    for entry in scope.exclude:
        if entry.matches_domain(host):
            return blocked(f"{host} is excluded by {entry.raw}")
    if not any(entry.matches_domain(host) for entry in scope.allow):
        return blocked(f"{host} is not in scope")
    try:
        resolved = resolve(host)
    except (OSError, UnicodeError):
        return blocked(f"could not resolve {host}")
    addresses = sorted(
        {unmap(ipaddress.ip_address(a)) for a in resolved}, key=_address_order
    )
    if not addresses:
        return blocked(f"{host} did not resolve to any address")
    shown = [str(a) for a in addresses]
    for address in addresses:
        problem = _address_problem(address, scope)
        if problem:
            return blocked(f"{host} resolves to {problem}", shown)
    return ScopeDecision(
        target=raw,
        allowed=True,
        reason="in scope",
        kind="domain",
        addresses=shown,
        scan_target=shown[0],
    )


def _address_order(address: IPAddress) -> tuple[int, int]:
    return (address.version, int(address))


def check_target(
    raw: str, scope: Scope, resolve: Resolver = resolve_host
) -> ScopeDecision:
    """Decide whether a target may be scanned.

    Domains are resolved and every resulting address must pass the exclude and
    restricted-range checks. scan_target is the exact address or network that
    was checked, so tools scan that instead of resolving the name again.
    """
    try:
        target = parse_target(raw)
    except ValueError as exc:
        return ScopeDecision(target=raw, allowed=False, reason=str(exc))
    if isinstance(target, ipaddress.IPv4Network | ipaddress.IPv6Network):
        return _check_network(raw, target, scope)
    if isinstance(target, ipaddress.IPv4Address | ipaddress.IPv6Address):
        return _check_address(raw, target, scope)
    return _check_domain(raw, target, scope, resolve)


def connect_denylist(scope: Scope) -> list[str]:
    """Networks an HTTP tool must never connect to, even if a name re-resolves there.

    Covers exclusions, metadata addresses and the common private ranges that no
    allow entry overlaps.
    """
    denied = [str(entry.network) for entry in scope.exclude if entry.network]
    denied += [
        str(address)
        for address in sorted(METADATA_ADDRESSES, key=_address_order)
        if not _explicitly_allowed(address, scope)
    ]
    denied += [
        str(network)
        for network in RESTRICTED_NETWORKS
        if not any(_overlaps(network, entry) for entry in scope.allow)
    ]
    return denied


def allows_restricted(scope: Scope) -> bool:
    """True if any allow entry overlaps a private or other restricted range."""
    return any(
        _overlaps(network, entry)
        for network in RESTRICTED_NETWORKS
        for entry in scope.allow
    )
