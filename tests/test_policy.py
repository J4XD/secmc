import pytest

from secmcp.policy import (
    Flag,
    ParsedFlag,
    PolicyError,
    check_text,
    choice,
    duration,
    int_between,
    int_list,
    parse_args,
    port_list,
)

ALLOWED = {
    "-v": Flag(),
    "--rate": Flag(int_between(1, 100)),
    "--os-shell": Flag(dangerous="spawns a shell on the target"),
}
BLOCKED = {"-o": "output paths are set by secmcp"}


def test_parse_inline_and_separate_values() -> None:
    parsed = parse_args(["-v", "--rate=10", "--rate", "20"], ALLOWED, BLOCKED)
    assert parsed == [
        ParsedFlag("-v"),
        ParsedFlag("--rate", "10"),
        ParsedFlag("--rate", "20"),
    ]
    assert [arg for flag in parsed for arg in flag.argv()] == [
        "-v",
        "--rate",
        "10",
        "--rate",
        "20",
    ]


def test_dangerous_flag_is_marked() -> None:
    (flag,) = parse_args(["--os-shell"], ALLOWED, BLOCKED)
    assert flag.dangerous == "spawns a shell on the target"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["-oA", "x"], "-oA is not allowed"),
        (["--nope"], "unknown flag --nope"),
        (["--rate"], "needs a value"),
        (["--rate="], "needs a value"),
        (["--rate", "--rate"], "needs a value, got '--rate'"),
        (["--rate", "1000"], "expected an integer from 1 to 100"),
        (["-v=1"], "invalid flag"),
        (["--v@x"], "invalid flag"),
        (["target.example.com"], "extra targets are not allowed"),
    ],
)
def test_parse_rejects(args: list[str], message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        parse_args(args, ALLOWED, BLOCKED)


@pytest.mark.parametrize(
    "text", ["a;b", "a|b", "a&b", "$x", "`id`", "a>b", "a b", "~/x", "a\x00"]
)
def test_check_text_rejects(text: str) -> None:
    with pytest.raises(PolicyError):
        check_text(text)


def test_validators() -> None:
    assert port_list("22,80,8000-8100") is None
    assert port_list("65536") is not None
    assert port_list("22,,80") is not None
    assert duration("500ms") is None
    assert duration("5 m") is not None
    assert int_between(0, 9)("10") is not None
    assert int_between(0, 9)("-1") is not None
    assert int_list(100, 599)("200,301-302") is None
    assert int_list(100, 599)("302-301") is not None
    assert int_list(0, 10)("1,,2") is not None
    assert choice("GET", "HEAD")("GET,HEAD") is None
    assert choice("GET", "HEAD")("GET,POST") is not None


def test_exact_allowed_flag_wins_over_short_blocked_prefix() -> None:
    allowed = {"-lc": Flag()}
    blocked = {"-l": "targets come only from the target argument"}
    assert parse_args(["-lc"], allowed, blocked) == [ParsedFlag("-lc")]
    with pytest.raises(PolicyError, match="targets come only"):
        parse_args(["-list"], allowed, blocked)
