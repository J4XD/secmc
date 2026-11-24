import socket

import pytest

from secmcp.scope import Scope, check_target, parse_entry, resolve_host
from tests.conftest import fake_resolver

NO_DNS = fake_resolver({})


@pytest.mark.parametrize("target", ["203.0.113.10", "198.51.100.7", "203.0.113.0/28"])
def test_allowed_ips_and_networks(scope: Scope, target: str) -> None:
    decision = check_target(target, scope, NO_DNS)
    assert decision.allowed, decision.reason
    assert decision.scan_target == target


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("8.8.4.4", "not in scope"),
        ("198.51.100.8", "not explicitly allowed"),
        ("203.0.113.66", "excluded by 203.0.113.66"),
        ("203.0.112.0/23", "not fully inside an allowed range"),
        ("203.0.113.64/28", "overlaps excluded 203.0.113.66"),
        ("10.0.0.0/8", "larger than"),
    ],
)
def test_blocked_ips_and_networks(scope: Scope, target: str, reason: str) -> None:
    decision = check_target(target, scope, NO_DNS)
    assert not decision.allowed
    assert reason in decision.reason


def test_cidr_with_host_bits_is_rejected(scope: Scope) -> None:
    decision = check_target("203.0.113.5/24", scope, NO_DNS)
    assert not decision.allowed
    assert "invalid network" in decision.reason


def test_exact_domain_and_wildcard(scope: Scope) -> None:
    resolve = fake_resolver(
        {"example.com": ["203.0.113.10"], "a.b.example.com": ["8.8.8.8"]}
    )
    assert check_target("example.com", scope, resolve).allowed
    decision = check_target("A.B.Example.COM.", scope, resolve)
    assert decision.allowed
    assert decision.scan_target == "8.8.8.8"


def test_wildcard_does_not_match_apex_or_lookalikes() -> None:
    scope = Scope(allow=[parse_entry("*.example.com")])
    resolve = fake_resolver({"example.com": ["8.8.8.8"], "badexample.com": ["8.8.8.8"]})
    assert "not in scope" in check_target("example.com", scope, resolve).reason
    assert "not in scope" in check_target("badexample.com", scope, resolve).reason


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("admin.example.com", "excluded by admin.example.com"),
        ("vpn.corp.example.com", "excluded by *.corp.example.com"),
        ("other.org", "not in scope"),
    ],
)
def test_domain_exclusions_win(scope: Scope, target: str, reason: str) -> None:
    resolve = fake_resolver({target: ["8.8.8.8"]})
    decision = check_target(target, scope, resolve)
    assert not decision.allowed
    assert reason in decision.reason


def test_domain_resolving_into_excluded_range(scope: Scope) -> None:
    resolve = fake_resolver({"shop.example.com": ["8.8.8.8", "192.0.2.10"]})
    decision = check_target("shop.example.com", scope, resolve)
    assert not decision.allowed
    assert "192.0.2.10 is excluded by 192.0.2.0/24" in decision.reason
    assert decision.addresses == ["8.8.8.8", "192.0.2.10"]


@pytest.mark.parametrize(
    ("address", "kind"),
    [
        ("169.254.169.254", "cloud metadata"),
        ("127.0.0.1", "loopback"),
        ("10.1.2.3", "private"),
        ("fe80::1", "link-local"),
        ("::ffff:169.254.169.254", "cloud metadata"),
    ],
)
def test_domain_resolving_to_restricted_address(
    scope: Scope, address: str, kind: str
) -> None:
    resolve = fake_resolver({"internal.example.com": [address]})
    decision = check_target("internal.example.com", scope, resolve)
    assert not decision.allowed
    assert f"a {kind} address" in decision.reason


def test_metadata_ip_blocked_even_inside_allowed_cidr() -> None:
    scope = Scope(allow=[parse_entry("169.254.0.0/16")])
    assert check_target("169.254.10.1", scope, NO_DNS).allowed
    decision = check_target("169.254.169.254", scope, NO_DNS)
    assert not decision.allowed
    assert "cloud metadata" in decision.reason
    assert (
        "contains cloud metadata"
        in check_target("169.254.169.0/24", scope, NO_DNS).reason
    )


def test_metadata_ip_allowed_only_by_exact_entry() -> None:
    scope = Scope(allow=[parse_entry("169.254.169.254")])
    assert check_target("169.254.169.254", scope, NO_DNS).allowed


def test_private_range_allowed_when_listed(scope: Scope) -> None:
    assert check_target("10.0.5.20", scope, NO_DNS).allowed
    resolve = fake_resolver({"lab.example.com": ["10.0.5.20"]})
    assert check_target("lab.example.com", scope, resolve).allowed


def test_unresolvable_domain(scope: Scope) -> None:
    decision = check_target("missing.example.com", scope, NO_DNS)
    assert not decision.allowed
    assert "could not resolve" in decision.reason


@pytest.mark.parametrize(
    "target",
    [
        "",
        "-iL /etc/passwd",
        "example.com;id",
        "example.com 203.0.113.1",
        "http://example.com",
        "$(id).example.com",
        "127.1",
        "0x7f.1",
        "exa_mple.com",
    ],
)
def test_malformed_targets(scope: Scope, target: str) -> None:
    resolve = fake_resolver({"example.com": ["203.0.113.10"]})
    assert not check_target(target, scope, resolve).allowed


@pytest.mark.parametrize(
    "entry", ["*.", "10.0.0.1/8", "exa mple.com", "*.*.example.com"]
)
def test_invalid_scope_entries(entry: str) -> None:
    with pytest.raises(ValueError, match="invalid scope entry"):
        parse_entry(entry)


def test_resolve_host_dedupes_and_strips_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    def getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%eth0", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    assert resolve_host("example.com") == ["203.0.113.1", "fe80::1"]
