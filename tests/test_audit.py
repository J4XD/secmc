import json
from pathlib import Path

from secmcp.audit import AuditRecord, append_record, read_records


def record(n: int) -> AuditRecord:
    return AuditRecord(
        tool="nmap", target=f"203.0.113.{n}", decision="allowed", reason="ok"
    )


def test_append_and_read_last_records(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "audit.jsonl"
    for n in range(5):
        append_record(path, record(n))

    lines = path.read_text().splitlines()
    assert len(lines) == 5
    first = json.loads(lines[0])
    assert first["target"] == "203.0.113.0"
    assert {
        "timestamp",
        "tool",
        "argv",
        "dry_run",
        "decision",
        "reason",
        "exit_code",
    } <= set(first)
    assert [r.target for r in read_records(path, 2)] == ["203.0.113.3", "203.0.113.4"]
    assert path.stat().st_mode & 0o777 == 0o600


def test_append_keeps_existing_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(record(1).model_dump_json() + "\n")
    append_record(path, record(2))
    assert len(read_records(path, 10)) == 2


def test_read_skips_corrupt_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    append_record(path, record(1))
    with path.open("a") as handle:
        handle.write("not json\n")
    append_record(path, record(2))
    assert [r.target for r in read_records(path, 10)] == ["203.0.113.1", "203.0.113.2"]


def test_read_missing_or_zero(tmp_path: Path) -> None:
    assert read_records(tmp_path / "missing.jsonl", 10) == []
    path = tmp_path / "audit.jsonl"
    append_record(path, record(1))
    assert read_records(path, 0) == []
