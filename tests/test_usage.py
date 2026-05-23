from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from aigov_redact.cli.main import app
from aigov_redact.usage import get_history, get_history_summary, record_usage

runner = CliRunner()


def test_record_and_get_history(tmp_path: Path, monkeypatch):
    history_file = tmp_path / "history.jsonl"
    monkeypatch.setattr("aigov_redact.usage._history_path", lambda: history_file)

    record_usage(command="check", source="stdin", entity_count=2, entity_types=["EMAIL", "SSN"])
    record_usage(command="redact", source="file", file_path="test.txt", entity_count=1, entity_types=["EMAIL"])

    records = get_history()
    assert len(records) == 2
    assert records[0].command == "check"
    assert records[0].entity_count == 2
    assert records[0].entity_types == ["EMAIL", "SSN"]
    assert records[1].command == "redact"
    assert records[1].file_path == "test.txt"


def test_get_history_empty(tmp_path: Path, monkeypatch):
    history_file = tmp_path / "history.jsonl"
    monkeypatch.setattr("aigov_redact.usage._history_path", lambda: history_file)
    assert get_history() == []


def test_get_history_limit(tmp_path: Path, monkeypatch):
    history_file = tmp_path / "history.jsonl"
    monkeypatch.setattr("aigov_redact.usage._history_path", lambda: history_file)

    for i in range(10):
        record_usage(command="check", source="stdin", entity_count=i, entity_types=[])

    records = get_history(limit=3)
    assert len(records) == 3
    assert records[0].entity_count == 7
    assert records[2].entity_count == 9


def test_get_history_summary(tmp_path: Path, monkeypatch):
    history_file = tmp_path / "history.jsonl"
    monkeypatch.setattr("aigov_redact.usage._history_path", lambda: history_file)

    record_usage(command="check", source="stdin", entity_count=2, entity_types=["EMAIL", "SSN"])
    record_usage(command="redact", source="file", file_path="x.txt", entity_count=1, entity_types=["EMAIL"])
    record_usage(command="check", source="file", file_path="y.txt", entity_count=0, entity_types=[])

    records = get_history()
    summary = get_history_summary(records)
    assert summary["total_runs"] == 3
    assert summary["commands"] == {"check": 2, "redact": 1}
    assert summary["entity_types_detected"] == {"EMAIL": 2, "SSN": 1}


def test_history_cli_command(tmp_path: Path, monkeypatch):
    history_file = tmp_path / "history.jsonl"
    monkeypatch.setattr("aigov_redact.usage._history_path", lambda: history_file)

    record_usage(command="check", source="stdin", entity_count=1, entity_types=["EMAIL"])
    record_usage(command="redact", source="file", file_path="log.txt", entity_count=2, entity_types=["SSN", "PHONE"])

    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0
    assert "Total runs: 2" in result.stdout
    assert "check: 1" in result.stdout
    assert "redact: 1" in result.stdout


def test_history_cli_empty(tmp_path: Path, monkeypatch):
    history_file = tmp_path / "history.jsonl"
    monkeypatch.setattr("aigov_redact.usage._history_path", lambda: history_file)

    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0
    assert "No usage history recorded yet" in result.stdout
