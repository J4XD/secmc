"""Shared state handed to every tool."""

from dataclasses import dataclass

from secmcp.config import Config
from secmcp.runner import Runner
from secmcp.scope import Resolver, Scope, resolve_host


@dataclass(frozen=True)
class ToolContext:
    config: Config
    scope: Scope
    runner: Runner
    resolve: Resolver = resolve_host

    @classmethod
    def from_config(cls, config: Config) -> "ToolContext":
        return cls(
            config=config,
            scope=config.scope(),
            runner=Runner(config.max_concurrency, config.max_output_bytes),
        )
