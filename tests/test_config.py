from pathlib import Path

import pytest

from secmcp.config import ConfigError, load_config


def test_load_config_resolves_relative_paths(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text("allow: [example.com]\ndata_dir: data\ntimeouts: {nmap: 60}\n")
    config = load_config(path)
    assert config.data_dir == tmp_path / "data"
    assert config.timeouts.nmap == 60
    assert config.audit_log_path == tmp_path / "data" / "audit.jsonl"
    assert not config.allow_dangerous


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("allow: []\n", "allow"),
        ("allow: ['not a host']\n", "invalid scope entry"),
        ("allow: [example.com]\nallow_dangerus: true\n", "allow_dangerus"),
        ("- example.com\n", "mapping"),
        ("allow: [example.com\n", "invalid yaml"),
    ],
)
def test_invalid_config(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text(content)
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_missing_config(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "nope.yaml")
