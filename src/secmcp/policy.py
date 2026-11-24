"""Flag allowlist checks shared by the tool wrappers."""

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

Validator = Callable[[str], str | None]

SHELL_METACHARACTERS = frozenset(";|&$`<>\\'\"(){}[]*?!~# \t")
_FLAG_NAME = re.compile(r"--?[A-Za-z0-9][A-Za-z0-9-]*")
_PORT_RANGE = re.compile(r"(\d{1,5})(?:-(\d{1,5}))?")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Flag:
    """An allowed flag. value validates its argument; None means it takes none."""

    value: Validator | None = None
    dangerous: str | None = None


@dataclass(frozen=True)
class ParsedFlag:
    name: str
    value: str | None = None
    dangerous: str | None = None

    def argv(self) -> list[str]:
        return [self.name] if self.value is None else [self.name, self.value]


def check_text(text: str) -> None:
    """Reject control characters and shell metacharacters."""
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise PolicyError(f"control characters are not allowed: {text!r}")
    bad = sorted(set(text) & SHELL_METACHARACTERS)
    if bad:
        raise PolicyError(
            f"shell metacharacters are not allowed: {''.join(bad)!r} in {text!r}"
        )


def _blocked_reason(name: str, blocked: Mapping[str, str]) -> str | None:
    if name in blocked:
        return blocked[name]
    # Short flags can carry their value inline, as in -oXfile or -iLtargets.
    for prefix, reason in blocked.items():
        if len(prefix) == 2 and name.startswith(prefix):
            return reason
    return None


def parse_args(
    args: Sequence[str], allowed: Mapping[str, Flag], blocked: Mapping[str, str]
) -> list[ParsedFlag]:
    """Validate extra arguments against an allowlist and return them parsed."""
    parsed: list[ParsedFlag] = []
    items = iter(args)
    for arg in items:
        check_text(arg)
        if not arg.startswith("-"):
            raise PolicyError(
                f"unexpected argument {arg!r}: extra targets are not allowed"
            )
        name, has_inline, inline = (
            arg.partition("=") if arg.startswith("--") else (arg, "", "")
        )
        reason = _blocked_reason(name, blocked)
        if reason:
            raise PolicyError(f"{name} is not allowed: {reason}")
        if not _FLAG_NAME.fullmatch(name):
            raise PolicyError(f"invalid flag {arg!r}")
        spec = allowed.get(name)
        if spec is None:
            raise PolicyError(f"unknown flag {name}")
        if spec.value is None:
            if has_inline:
                raise PolicyError(f"{name} does not take a value")
            parsed.append(ParsedFlag(name, dangerous=spec.dangerous))
            continue
        value = inline if has_inline else next(items, "")
        if not value:
            raise PolicyError(f"{name} needs a value")
        if value.startswith("-"):
            raise PolicyError(f"{name} needs a value, got {value!r}")
        check_text(value)
        error = spec.value(value)
        if error:
            raise PolicyError(f"invalid value for {name}: {error}")
        parsed.append(ParsedFlag(name, value, spec.dangerous))
    return parsed


def int_between(low: int, high: int) -> Validator:
    def validate(value: str) -> str | None:
        if not value.isdigit() or not low <= int(value) <= high:
            return f"expected an integer from {low} to {high}"
        return None

    return validate


def duration(value: str) -> str | None:
    if not re.fullmatch(r"\d{1,6}(ms|s|m|h)?", value):
        return "expected a duration like 500ms, 30s, 5m or 1h"
    return None


def port_list(value: str) -> str | None:
    """Validate a port spec like 22,80,8000-8100."""
    for part in value.split(","):
        match = _PORT_RANGE.fullmatch(part)
        if not match:
            return f"invalid port spec {value!r}"
        low = int(match.group(1))
        high = int(match.group(2) or low)
        if not 1 <= low <= high <= 65535:
            return f"invalid port range {part!r}"
    return None
