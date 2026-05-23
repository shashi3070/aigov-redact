from __future__ import annotations

import os
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from aigov_redact.cli.main import app

runner = CliRunner()


class TestCLICheck:
    def test_check_file_with_pii(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("My email is john@example.com")
            f.flush()
            result = runner.invoke(app, ["check", f.name])
        os.unlink(f.name)
        assert result.exit_code == 1
        assert "EMAIL" in result.stdout

    def test_check_file_clean(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("Hello world, this is clean.")
            f.flush()
            result = runner.invoke(app, ["check", f.name])
        os.unlink(f.name)
        assert result.exit_code == 0
        assert "No PII detected" in result.stdout

    def test_check_file_not_found(self):
        result = runner.invoke(app, ["check", "/nonexistent/file.txt"])
        assert result.exit_code == 1

    def test_check_stdin(self):
        result = runner.invoke(app, ["check", "--stdin"], input="Email: a@b.com")
        assert result.exit_code == 1
        assert "EMAIL" in result.stdout

    def test_check_json_output(self):
        result = runner.invoke(app, ["check", "--stdin", "--json"], input="Email: a@b.com")
        assert result.exit_code == 1 or result.exit_code == 0
        assert result.stdout.strip() != ""


class TestCLIRedact:
    def test_redact_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("My email is john@example.com")
            f.flush()
            fname = f.name

        result = runner.invoke(app, ["redact", fname, "--no-backup"])
        assert result.exit_code == 0
        assert "{EMAIL}" in Path(fname).read_text("utf-8")
        os.unlink(fname)

    def test_redact_stdout(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("My SSN is 123-45-6789")
            f.flush()
            fname = f.name

        result = runner.invoke(app, ["redact", fname, "--stdout", "--no-backup"])
        assert result.exit_code == 0
        assert "{SSN}" in result.stdout
        os.unlink(fname)

    def test_redact_stdin(self):
        result = runner.invoke(app, ["redact", "--stdin"], input="Email: a@b.com")
        assert result.exit_code == 0
        assert "{EMAIL}" in result.stdout

    def test_redact_custom_mode(self):
        result = runner.invoke(app, ["redact", "--stdin", "--mode", "mask"], input="SSN: 123-45-6789")
        assert result.exit_code == 0
        assert "123-45-6789" not in result.stdout

    def test_redact_no_args(self):
        result = runner.invoke(app, ["redact"])
        assert result.exit_code == 1


class TestCLIAudit:
    def test_audit_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write("user: alice@example.com\nmy SSN is 123-45-6789\nclean line\n")
            f.flush()
            fname = f.name

        result = runner.invoke(app, ["audit", fname])
        assert result.exit_code == 0
        assert "EMAIL" in result.stdout
        assert "SSN" in result.stdout
        os.unlink(fname)

    def test_audit_stdin(self):
        result = runner.invoke(app, ["audit", "--stdin"], input="email: a@b.com\nSSN is 123-45-6789")
        assert result.exit_code == 0
        assert "EMAIL" in result.stdout
        assert "SSN" in result.stdout

    def test_audit_json(self):
        result = runner.invoke(app, ["audit", "--stdin", "--format", "json"], input="email: a@b.com")
        assert result.exit_code == 0
        assert "entries" in result.stdout

    def test_audit_summary(self):
        inp = "email: a@b.com\nmy SSN is 123-45-6789"
        result = runner.invoke(app, ["audit", "--stdin", "--format", "summary"], input=inp)
        assert result.exit_code == 0
        assert "Total entities: 2" in result.stdout

    def test_audit_fail_on_pii(self):
        result = runner.invoke(app, ["audit", "--stdin", "--fail-on-pii"], input="email: a@b.com")
        assert result.exit_code == 1
        assert "EMAIL" in result.stdout

    def test_audit_no_pii(self):
        result = runner.invoke(app, ["audit", "--stdin"], input="clean log line\nanother clean line")
        assert result.exit_code == 0
        assert "No PII leaks detected" in result.stdout

    def test_audit_file_not_found(self):
        result = runner.invoke(app, ["audit", "/nonexistent/file.log"])
        assert result.exit_code == 1


class TestCLIHelp:
    def test_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "prompt-sanitizer" in result.stdout

    def test_no_args(self):
        result = runner.invoke(app, [])
        assert result.exit_code == 0 or result.exit_code == 2


class TestCLIComplianceProfile:
    def test_check_compliance_profile_disables_pii_type(self):
        config_data = {
            "compliance_profiles": {
                "hipaa": {"disabled": ["EMAIL"]},
            },
        }
        import json
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as cfg:
            json.dump(config_data, cfg)
            cfg.flush()
            cfg_path = cfg.name

        result = runner.invoke(app, [
            "check", "--stdin", "--json",
            "--config", cfg_path,
            "--compliance-profile", "hipaa",
        ], input="email: a@b.com SSN: 123-45-6789")
        os.unlink(cfg_path)
        assert result.exit_code == 1
        assert "SSN" in result.stdout
        assert "EMAIL" not in result.stdout

    def test_redact_compliance_profile_changes_placeholder_style(self):
        config_data = {
            "compliance_profiles": {
                "pci": {"placeholder_style": "hash"},
            },
        }
        import json
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as cfg:
            json.dump(config_data, cfg)
            cfg.flush()
            cfg_path = cfg.name

        result = runner.invoke(app, [
            "redact", "--stdin",
            "--config", cfg_path,
            "--compliance-profile", "pci",
        ], input="Email: a@b.com")
        os.unlink(cfg_path)
        assert result.exit_code == 0
        assert "{EMAIL}" not in result.stdout
        # hash style produces <TYPE_hash> like <EMAIL_fb98d44a>
        import re
        assert re.search(r"<[A-Z]+_[0-9a-f]{8,}>", result.stdout)
