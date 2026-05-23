from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

import typer

from aigov_redact.auditor import Auditor
from aigov_redact.config import load_config, merge_config_with_cli, parse_custom_patterns
from aigov_redact.detector import Detector, create_detector
from aigov_redact.redactor import detect as detect_lib
from aigov_redact.redactor import redact as redact_lib
from aigov_redact.usage import get_history, get_history_summary

app = typer.Typer(
    name="aigov-redact",
    help="PII Redactor for LLM Data — detect, redact, and audit sensitive data.",
    no_args_is_help=True,
)


def _resolve_config(config_path: Optional[str], compliance_profile: Optional[str] = None) -> dict:
    cfg = load_config(config_path) if config_path else load_config(None)
    if compliance_profile:
        cfg = merge_config_with_cli(cfg, {"compliance_profile": compliance_profile})
    return cfg


def _build_detector(config: dict, cli_overrides: dict | None = None) -> Detector:
    if cli_overrides:
        config = merge_config_with_cli(config, cli_overrides)

    enabled = config.get("pii_types", {}).get("enabled")
    disabled = config.get("pii_types", {}).get("disabled")
    excluded = config.get("excluded_patterns")
    custom = parse_custom_patterns(config)

    return create_detector(
        enabled_types=enabled,
        disabled_types=disabled,
        custom_patterns=custom,
        excluded_patterns=excluded,
    )


def _detector_options(config: dict) -> dict:
    return {
        "custom_patterns": parse_custom_patterns(config),
        "excluded_patterns": config.get("excluded_patterns"),
        "enabled_types": config.get("pii_types", {}).get("enabled"),
        "disabled_types": config.get("pii_types", {}).get("disabled"),
    }


def _print_json(data) -> None:
    json.dump(data, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def _read_stdin() -> str:
    return sys.stdin.read()


@app.command()
def check(
    file: Optional[str] = typer.Argument(None, help="File to scan for PII"),
    stdin: bool = typer.Option(False, "--stdin", help="Read from stdin"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file"),
    ner: bool = typer.Option(False, "--ner", help="Enable NER-based detection (requires presidio)"),
    compliance_profile: Optional[str] = typer.Option(
        None, "--compliance-profile", help="Apply a compliance profile from config"
    ),
):
    """Detect PII in text or file without redacting."""
    cfg = _resolve_config(config, compliance_profile)

    if ner:
        cfg["ner_enabled"] = True

    opts = _detector_options(cfg)

    if stdin:
        text = _read_stdin()
        result = detect_lib(text, ner_enabled=ner, **opts)
    elif file:
        filepath = Path(file)
        if not filepath.exists():
            typer.echo(f"Error: file not found: {file}", err=True)
            raise typer.Exit(1)
        text = filepath.read_text("utf-8", errors="replace")
        result = detect_lib(text, ner_enabled=ner, **opts)
    else:
        typer.echo("Error: provide a file or use --stdin", err=True)
        raise typer.Exit(1)

    if json_output:
        _print_json(result.model_dump())
        if result.count > 0:
            raise typer.Exit(1)
        return

    if not result.entities:
        typer.echo("No PII detected.")
        return

    typer.echo(f"Found {len(result.entities)} PII entit{'y' if len(result.entities) == 1 else 'ies'}:")
    typer.echo("")
    typer.echo(f"  {'Type':<20} {'Confidence':<12} {'Severity':<10} {'Text'}")
    typer.echo(f"  {'----':<20} {'----------':<12} {'--------':<10} {'----'}")
    for e in result.entities:
        display = e.text[:40] + "..." if len(e.text) > 43 else e.text
        typer.echo(f"  {e.type:<20} {e.confidence:<12.2f} {e.severity:<10} {display}")

    raise typer.Exit(1)


@app.command()
def redact(
    file: Optional[str] = typer.Argument(None, help="File to redact in-place"),
    stdin: bool = typer.Option(False, "--stdin", help="Read from stdin"),
    stdout: bool = typer.Option(False, "--stdout", help="Print to stdout instead of writing file"),
    no_backup: bool = typer.Option(False, "--no-backup", help="Skip creating .bak backup"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file"),
    ner: bool = typer.Option(False, "--ner", help="Enable NER-based detection"),
    mode: Optional[str] = typer.Option(
        None, "--mode", "-m", help="Redaction mode: replace, mask, hash, remove, custom"
    ),
    placeholder_style: Optional[str] = typer.Option(
        None, "--placeholder-style", help="Placeholder style: type, hash, redact, custom"
    ),
    mask_char: Optional[str] = typer.Option(None, "--mask-char", help="Character for mask mode"),
    compliance_profile: Optional[str] = typer.Option(
        None, "--compliance-profile", help="Apply a compliance profile from config"
    ),
):
    """Redact PII from a file or stdin."""
    cfg = _resolve_config(config, compliance_profile)
    if ner:
        cfg["ner_enabled"] = True

    cli_keys = [("mode", mode), ("placeholder_style", placeholder_style), ("mask_char", mask_char)]
    cli_overrides = {k: v for k, v in cli_keys if v is not None}
    cfg = merge_config_with_cli(cfg, cli_overrides)

    opts = _detector_options(cfg)

    mode = cfg.get("mode", "replace")
    placeholder_style = cfg.get("placeholder_style", "type")
    mask_char = cfg.get("mask_char", "*")

    if stdin:
        text = _read_stdin()
        result = redact_lib(
            text=text,
            mode=mode,
            ner_enabled=ner,
            mask_char=mask_char,
            placeholder_style=placeholder_style,
            **opts,
        )
        if stdout:
            sys.stdout.write(result.text)
        else:
            typer.echo(result.text)
        return

    if not file:
        typer.echo("Error: provide a file or use --stdin", err=True)
        raise typer.Exit(1)

    filepath = Path(file)
    if not filepath.exists():
        typer.echo(f"Error: file not found: {file}", err=True)
        raise typer.Exit(1)

    original = filepath.read_text("utf-8", errors="replace")
    result = redact_lib(
        text=original,
        mode=mode,
        ner_enabled=ner,
        mask_char=mask_char,
        placeholder_style=placeholder_style,
        **opts,
    )

    if stdout:
        sys.stdout.write(result.text)
        return

    if not no_backup:
        backup_path = filepath.with_suffix(filepath.suffix + ".bak")
        shutil.copy2(filepath, backup_path)

    filepath.write_text(result.text, "utf-8")
    typer.echo(f"Redacted {len(result.entities)} entit{'y' if len(result.entities) == 1 else 'ies'} in {file}")


@app.command()
def audit(
    file: Optional[str] = typer.Argument(None, help="Log file to scan for PII"),
    stdin: bool = typer.Option(False, "--stdin", help="Read from stdin"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, summary"),
    fail_on_pii: bool = typer.Option(False, "--fail-on-pii", help="Exit with code 1 if PII is found"),
    audit_log: Optional[str] = typer.Option(None, "--audit-log", "-a", help="Path to persistent audit log file"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file"),
    ner: bool = typer.Option(False, "--ner", help="Enable NER-based detection"),
    compliance_profile: Optional[str] = typer.Option(
        None, "--compliance-profile", help="Apply a compliance profile from config"
    ),
):
    """Scan files for PII leaks (production log audit)."""
    cfg = _resolve_config(config, compliance_profile)
    if ner:
        cfg["ner_enabled"] = True

    detector = _build_detector(cfg)
    auditor = Auditor(detector, audit_log_path=audit_log)

    if stdin:
        text = _read_stdin()
        result = auditor.scan_text(text)
    elif file:
        if not os.path.exists(file):
            typer.echo(f"Error: file not found: {file}", err=True)
            raise typer.Exit(1)
        result = auditor.scan_file(file)
    else:
        typer.echo("Error: provide a file or use --stdin", err=True)
        raise typer.Exit(1)

    if format == "json":
        _print_json(result.model_dump())
    elif format == "summary":
        typer.echo(f"Files scanned: {result.total_files}")
        typer.echo(f"Total entities: {result.total_entities}")
        typer.echo("By type:")
        for pii_type, count in sorted(result.summary.items()):
            typer.echo(f"  {pii_type}: {count}")
    else:
        if not result.entries:
            typer.echo("No PII leaks detected.")
        else:
            typer.echo(f"Found {result.total_entities} PII entit{'y' if result.total_entities == 1 else 'ies'}:")
            typer.echo("")
            typer.echo(f"  {'Type':<20} {'File':<25} {'Line':<6} {'Col':<5} {'Severity':<10}")
            typer.echo(f"  {'----':<20} {'----':<25} {'----':<6} {'---':<5} {'--------':<10}")
            for e in result.entries:
                typer.echo(f"  {e.type:<20} {e.filename:<25} {e.line:<6} {e.column:<5} {e.severity:<10}")

    if fail_on_pii and result.total_entities > 0:
        raise typer.Exit(1)


@app.command()
def history(
    limit: int = typer.Option(50, "--limit", "-n", help="Number of recent records to show"),
):
    """Show usage history."""
    records = get_history(limit=limit)
    if not records:
        typer.echo("No usage history recorded yet.")
        raise typer.Exit(0)

    summary = get_history_summary(records)
    typer.echo(f"Total runs: {summary['total_runs']}")
    typer.echo("")
    typer.echo("Runs by command:")
    for cmd, count in sorted(summary["commands"].items()):
        typer.echo(f"  {cmd}: {count}")
    if summary["entity_types_detected"]:
        typer.echo("")
        typer.echo("Entity types detected (top):")
        for etype, count in list(summary["entity_types_detected"].items())[:10]:
            typer.echo(f"  {etype}: {count}")
    typer.echo("")
    typer.echo("Recent runs:")
    for r in reversed(records[-10:]):
        types = ", ".join(r.entity_types[:3])
        if len(r.entity_types) > 3:
            types += f" +{len(r.entity_types) - 3} more"
        typer.echo(f"  {r.timestamp[:19]}  {r.command:<8}  {r.source:<6}  count={r.entity_count}  [{types}]")


if __name__ == "__main__":
    app()
