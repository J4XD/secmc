import pytest

from secmcp.scope import Scope, allows_restricted, connect_denylist, parse_entry
from secmcp.targets import MAX_TARGETS, check_url, check_urls, normalize_url
from tests.helpers import fake_resolver

RESOLVE = fake_resolver(
    {
        "www.example.com": ["203.0.113.10"],
        "rebind.example.com": ["192.0.2.5"],
        "meta.example.com": ["169.254.169.254"],
    }
)


@pytest.mark.parametrize(
    ("raw", "url", "host"),
    [
        (
            "https://WWW.Example.com/a?b=1",
            "https://www.example.com/a?b=1",
            "www.example.com",
        ),
        ("http://203.0.113.10:8080", "http://203.0.113.10:8080", "203.0.113.10"),
        ("www.example.com:8443", "www.example.com:8443", "www.example.com"),
        ("http://[2001:db8::1]/x", "http://[2001:db8::1]/x", "2001:db8::1"),
        (
            "https://www.example.com/a#frag",
            "https://www.example.com/a",
            "www.example.com",
        ),
    ],
)
def test_normalize_url(raw: str, url: str, host: str) -> None:
    assert normalize_url(raw) == (url, host)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "empty target"),
        ("-l", "must not start with '-'"),
        ("ftp://www.example.com", "unsupported scheme 'ftp'"),
        ("file:///etc/passwd", "unsupported scheme 'file'"),
        ("http://user:pw@www.example.com", "credentials"),
        ("http://evil.com@www.example.com", "credentials"),
        ("http://www.example.com\\@evil.com", "backslashes"),
        ("http://www.example.com /x", "whitespace"),
        ("http://www.example.com\n-u evil", "whitespace or control"),
        ("http://www.example.com:99999", "invalid port"),
        ("http:///path", "missing host"),
    ],
)
def test_normalize_url_rejects(raw: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_url(raw)


def test_scheme_can_be_required() -> None:
    with pytest.raises(ValueError, match="expected a url"):
        normalize_url("www.example.com/FUZZ", require_scheme=True)


def test_check_url_uses_scope_and_dns(scope: Scope) -> None:
    decision = check_url("https://www.example.com/login", scope, RESOLVE)
    assert decision.allowed
    assert decision.url == "https://www.example.com/login"
    assert decision.addresses == ["203.0.113.10"]


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("https://evil.com/", "evil.com is not in scope"),
        ("https://admin.example.com/", "excluded by admin.example.com"),
        ("https://rebind.example.com/", "resolves to 192.0.2.5 is excluded"),
        ("http://meta.example.com/latest", "cloud metadata"),
        ("http://169.254.169.254/latest/meta-data", "cloud metadata"),
        ("http://203.0.113.66/", "excluded by 203.0.113.66"),
        ("http://0x7f.1/", "ambiguous numeric hostname"),
        ("http://%65vil.com/", "invalid hostname"),
    ],
)
def test_check_url_refuses(scope: Scope, raw: str, reason: str) -> None:
    decision = check_url(raw, scope, RESOLVE)
    assert not decision.allowed
    assert decision.url is None
    assert reason in decision.reason


def test_check_urls_refuses_whole_call_if_any_target_is_out(scope: Scope) -> None:
    _, reason = check_urls(["www.example.com", "evil.com"], scope, RESOLVE)
    assert reason == "1 target(s) refused: evil.com: evil.com is not in scope"
    decisions, reason = check_urls(["www.example.com"], scope, RESOLVE)
    assert reason is None
    assert decisions[0].url == "www.example.com"


def test_check_urls_limits(scope: Scope) -> None:
    assert check_urls([], scope, RESOLVE)[1] == "no targets given"
    too_many = ["www.example.com"] * (MAX_TARGETS + 1)
    reason = check_urls(too_many, scope, RESOLVE)[1]
    assert reason is not None
    assert reason.startswith("too many targets")


def test_connect_denylist(scope: Scope) -> None:
    denied = connect_denylist(scope)
    assert denied[:2] == ["203.0.113.66/32", "192.0.2.0/24"]
    assert "169.254.169.254" in denied
    assert "192.168.0.0/16" in denied
    # 10.0.5.0/24 is allowed in the test scope, so 10.0.0.0/8 must stay reachable.
    assert "10.0.0.0/8" not in denied
    assert allows_restricted(scope)


def test_public_only_scope_denies_all_private_ranges() -> None:
    scope = Scope(allow=[parse_entry("203.0.113.0/24")])
    assert "10.0.0.0/8" in connect_denylist(scope)
    assert not allows_restricted(scope)
