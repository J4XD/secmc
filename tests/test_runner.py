import asyncio
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from secmcp.runner import Runner, find_binary, read_capped

pytestmark = pytest.mark.anyio


def _is_running(pid: int) -> bool:
    # The orphaned child can linger as a zombie until init reaps it.
    if Path("/proc").is_dir():
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
        except FileNotFoundError:
            return False
        return stat.rsplit(")", 1)[1].split()[0] != "Z"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class FakeProcess:
    def __init__(self, delay: float = 0.0, returncode: int = 0) -> None:
        self.pid = 999_999
        self.returncode: int | None = None
        self._delay = delay
        self._final = returncode

    async def wait(self) -> int:
        await asyncio.sleep(self._delay)
        self.returncode = self._final
        return self._final


async def test_run_uses_argv_without_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    async def fake_exec(*args: Any, **kwargs: Any) -> FakeProcess:
        calls.append((args, kwargs))
        kwargs["stdout"].write(b"Nmap done\n")
        return FakeProcess(returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(os, "killpg", lambda pid, sig: None)
    runner = Runner(max_concurrency=2, max_output_bytes=1000)
    result = await runner.run(["nmap", "-F", "203.0.113.1"], 5, tmp_path / "run.log")

    args, kwargs = calls[0]
    assert args == ("nmap", "-F", "203.0.113.1")
    assert "shell" not in kwargs
    assert kwargs["stdin"] == asyncio.subprocess.DEVNULL
    assert kwargs["start_new_session"] is True
    assert result.exit_code == 0
    assert not result.timed_out
    assert result.output == "Nmap done\n"


async def test_concurrency_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    running = 0
    peak = 0

    class TrackedProcess(FakeProcess):
        async def wait(self) -> int:
            nonlocal running, peak
            running += 1
            peak = max(peak, running)
            await asyncio.sleep(0.02)
            running -= 1
            self.returncode = 0
            return 0

    async def fake_exec(*args: Any, **kwargs: Any) -> FakeProcess:
        return TrackedProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(os, "killpg", lambda pid, sig: None)
    runner = Runner(max_concurrency=2, max_output_bytes=1000)
    await asyncio.gather(
        *(runner.run(["true"], 5, tmp_path / f"{i}.log") for i in range(6))
    )
    assert peak == 2


async def test_timeout_kills_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    sleeper = "import time; time.sleep(60)"
    script = (
        "import subprocess, sys, time\n"
        f"child = subprocess.Popen([sys.executable, '-c', {sleeper!r}])\n"
        f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
        "print('started', flush=True)\n"
        "time.sleep(60)\n"
    )
    runner = Runner(max_concurrency=1, max_output_bytes=1000)
    started = time.monotonic()
    result = await runner.run([sys.executable, "-c", script], 1.0, tmp_path / "run.log")

    assert result.timed_out
    assert result.exit_code is None
    assert time.monotonic() - started < 10
    assert "started" in result.output
    child_pid = int(pid_file.read_text())
    await asyncio.sleep(0.2)
    assert not _is_running(child_pid)


async def test_nonzero_exit_and_output_cap(tmp_path: Path) -> None:
    script = "import sys; sys.stdout.write('x' * 5000); sys.exit(3)"
    runner = Runner(max_concurrency=1, max_output_bytes=1000)
    result = await runner.run([sys.executable, "-c", script], 10, tmp_path / "run.log")
    assert result.exit_code == 3
    assert result.truncated
    assert result.output.startswith("x" * 1000)
    assert "output truncated at 1000 of 5000 bytes" in result.output
    assert result.raw_output_path.stat().st_size == 5000


def test_read_capped_short_file(tmp_path: Path) -> None:
    path = tmp_path / "out.log"
    path.write_bytes(b"short\xff")
    assert read_capped(path, 100) == ("short�", False)


def test_find_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert find_binary("nmap") is None
