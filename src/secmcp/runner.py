"""Subprocess execution with timeouts, output caps and a concurrency limit."""

import asyncio
import contextlib
import os
import shutil
import signal
import time
from dataclasses import dataclass
from pathlib import Path

INSTALL_HINTS = {
    "nmap": "install nmap (apt install nmap, brew install nmap) "
    "or get it from https://nmap.org/download",
}


@dataclass(frozen=True)
class RunResult:
    argv: list[str]
    exit_code: int | None
    timed_out: bool
    duration_s: float
    output: str
    truncated: bool
    raw_output_path: Path


def find_binary(name: str) -> str | None:
    """Return the full path of an executable on PATH, or None."""
    return shutil.which(name)


def install_hint(name: str) -> str:
    return INSTALL_HINTS.get(name, f"install {name} and make sure it is on PATH")


def read_capped(path: Path, limit: int) -> tuple[str, bool]:
    """Read at most limit bytes of a file, appending a note if it was cut."""
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    truncated = len(data) > limit
    text = data[:limit].decode("utf-8", errors="replace")
    if truncated:
        size = path.stat().st_size
        text += (
            f"\n[output truncated at {limit} of {size} bytes, full output in {path}]"
        )
    return text, truncated


def _kill_group(pid: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGKILL)


class Runner:
    """Runs argv lists with a shared concurrency limit."""

    def __init__(self, max_concurrency: int, max_output_bytes: int) -> None:
        self._slots = asyncio.Semaphore(max_concurrency)
        self.max_output_bytes = max_output_bytes

    async def run(
        self, argv: list[str], timeout: float, raw_output_path: Path
    ) -> RunResult:
        """Run argv without a shell, killing its whole process group on timeout."""
        async with self._slots:
            return await self._run(argv, timeout, raw_output_path)

    async def _run(
        self, argv: list[str], timeout: float, raw_output_path: Path
    ) -> RunResult:
        raw_output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        timed_out = False
        started = time.monotonic()
        with raw_output_path.open("wb") as raw:
            # A new session makes the child a process group leader, so killpg also
            # reaches anything it spawned. stdin is closed so prompts fail fast.
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=raw,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                await asyncio.wait_for(process.wait(), timeout)
            except TimeoutError:
                timed_out = True
            finally:
                # Runs after a normal exit too, to stop children left in the background.
                # A group id is not reused while any member is still alive.
                _kill_group(process.pid)
                await process.wait()
        duration = round(time.monotonic() - started, 3)
        output, truncated = read_capped(raw_output_path, self.max_output_bytes)
        return RunResult(
            argv=argv,
            exit_code=None if timed_out else process.returncode,
            timed_out=timed_out,
            duration_s=duration,
            output=output,
            truncated=truncated,
            raw_output_path=raw_output_path,
        )
