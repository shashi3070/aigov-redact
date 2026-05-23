from __future__ import annotations

import os
import tempfile

import pytest

from aigov_redact.auditor import Auditor
from aigov_redact.detector import Detector


@pytest.fixture
def sample_log():
    return "\n".join([
        "INFO user: alice@example.com logged in",
        "WARN SSN: 123-45-6789 found in request",
        "INFO everything is fine here",
        "ERROR Credit card: 4111-1111-1111-1111 declined",
    ])


class TestAuditor:
    def test_scan_text(self, sample_log):
        d = Detector()
        auditor = Auditor(d)
        result = auditor.scan_text(sample_log, filename="test.log")
        assert result.total_entities == 3
        assert result.total_files == 1
        assert len(result.entries) == 3

    def test_scan_text_line_numbers(self, sample_log):
        d = Detector()
        auditor = Auditor(d)
        result = auditor.scan_text(sample_log)
        lines = {e.line for e in result.entries}
        assert 1 in lines  # EMAIL
        assert 2 in lines  # SSN
        assert 4 in lines  # CREDIT_CARD

    def test_scan_text_no_pii(self):
        d = Detector()
        auditor = Auditor(d)
        result = auditor.scan_text("clean log line\nanother clean line")
        assert result.total_entities == 0
        assert len(result.entries) == 0

    def test_scan_file(self, sample_log):
        d = Detector()
        auditor = Auditor(d)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(sample_log)
            f.flush()
            result = auditor.scan_file(f.name)
        os.unlink(f.name)
        assert result.total_entities == 3

    def test_audit_log_written(self, sample_log):
        d = Detector()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as alog:
            audit_path = alog.name

        try:
            auditor = Auditor(d, audit_log_path=audit_path)
            auditor.scan_text(sample_log)
            with open(audit_path, "r") as f:
                content = f.read()
            assert "timestamp" in content
            assert "EMAIL" in content
            assert "SSN" in content
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)

    def test_summary(self, sample_log):
        d = Detector()
        auditor = Auditor(d)
        result = auditor.scan_text(sample_log)
        assert result.summary.get("EMAIL") == 1
        assert result.summary.get("SSN") == 1
        assert result.summary.get("CREDIT_CARD") == 1
