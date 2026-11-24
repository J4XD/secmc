import socket
from pathlib import Path
from typing import Any

from secmcp.config import Config
from secmcp.context import ToolContext
from secmcp.runner import Runner, RunResult


def fake_resolver(table: dict[str, list[str]]) -> Any:
    def resolve(host: str) -> list[str]:
        if host not in table:
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        return table[host]

    return resolve


FIXTURES = Path(__file__).parent / "fixtures"


class FakeRunner(Runner):
    def __init__(
        self, xml: bytes | None = None, exit_code: int = 0, timed_out: bool = False
    ) -> None:
        super().__init__(max_concurrency=1, max_output_bytes=1000)
        self.calls: list[list[str]] = []
        self.xml = (
            xml
            if xml is not None
            else (FIXTURES / "nmap_service_version.xml").read_bytes()
        )
        self.exit_code = exit_code
        self.timed_out = timed_out

    async def run(
        self, argv: list[str], timeout: float, raw_output_path: Path
    ) -> RunResult:
        self.calls.append(argv)
        xml_path = Path(argv[argv.index("-oX") + 1])
        xml_path.parent.mkdir(parents=True, exist_ok=True)
        xml_path.write_bytes(self.xml)
        raw_output_path.write_text("Starting Nmap\n")
        return RunResult(
            argv=argv,
            exit_code=None if self.timed_out else self.exit_code,
            timed_out=self.timed_out,
            duration_s=1.5,
            output="Starting Nmap\n",
            truncated=False,
            raw_output_path=raw_output_path,
        )


def make_ctx(
    config: Config, runner: FakeRunner | None = None, **overrides: object
) -> tuple[ToolContext, FakeRunner]:
    runner = runner or FakeRunner()
    config = config.model_copy(
        update={"nmap_script_db": FIXTURES / "script.db", **overrides}
    )
    resolve = fake_resolver(
        {"www.example.com": ["203.0.113.10"], "v6.example.com": ["2001:db8::10"]}
    )
    ctx = ToolContext(
        config=config, scope=config.scope(), runner=runner, resolve=resolve
    )
    return ctx, runner
