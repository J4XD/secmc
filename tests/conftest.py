import socket
from pathlib import Path
from typing import Any

import pytest

from secmcp.config import Config
from secmcp.scope import Scope


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("tests must not touch the network")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "gethostbyname", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        allow=[
            "203.0.113.0/24",
            "198.51.100.7",
            "example.com",
            "*.example.com",
            "10.0.5.0/24",
        ],
        exclude=[
            "203.0.113.66",
            "admin.example.com",
            "*.corp.example.com",
            "192.0.2.0/24",
        ],
        data_dir=tmp_path / "data",
    )


@pytest.fixture
def scope(config: Config) -> Scope:
    return config.scope()


def fake_resolver(table: dict[str, list[str]]) -> Any:
    def resolve(host: str) -> list[str]:
        if host not in table:
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        return table[host]

    return resolve
