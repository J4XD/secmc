"""Configuration loaded from scope.yaml."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from secmcp.scope import Scope, parse_entry


class ConfigError(Exception):
    pass


class Timeouts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nmap: int = Field(default=900, ge=1, le=86_400)


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(min_length=1)
    exclude: list[str] = []
    allow_dangerous: bool = False
    max_concurrency: int = Field(default=2, ge=1, le=16)
    max_output_bytes: int = Field(default=20_000, ge=1_000, le=10_000_000)
    timeouts: Timeouts = Timeouts()
    data_dir: Path = Path("~/.local/share/secmcp")
    nmap_script_db: Path | None = None

    @field_validator("allow", "exclude")
    @classmethod
    def _entries_parse(cls, entries: list[str]) -> list[str]:
        for entry in entries:
            parse_entry(entry)
        return entries

    @field_validator("data_dir", "nmap_script_db")
    @classmethod
    def _expand_user(cls, path: Path | None) -> Path | None:
        return path.expanduser() if path else None

    def scope(self) -> Scope:
        return Scope(
            allow=[parse_entry(entry) for entry in self.allow],
            exclude=[parse_entry(entry) for entry in self.exclude],
        )

    @property
    def audit_log_path(self) -> Path:
        return self.data_dir / "audit.jsonl"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"


def load_config(path: Path) -> Config:
    """Load and validate a scope file; relative paths resolve against its directory."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid yaml in {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    try:
        config = Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    base = path.parent.resolve()
    updates: dict[str, Path] = {"data_dir": base / config.data_dir}
    if config.nmap_script_db:
        updates["nmap_script_db"] = base / config.nmap_script_db
    return config.model_copy(update=updates)
