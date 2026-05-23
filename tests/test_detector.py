from __future__ import annotations

import re

from aigov_redact.detector import Detector, create_detector
from aigov_redact.patterns import PIIDefinition


class TestDetector:
    def test_detect_email(self):
        d = Detector()
        result = d.detect("My email is john@example.com")
        assert len(result) == 1
        assert result[0].type == "EMAIL"
        assert result[0].text == "john@example.com"
        assert result[0].start == 12
        assert result[0].end == 28

    def test_detect_ssn(self):
        d = Detector()
        result = d.detect("SSN: 123-45-6789")
        assert len(result) == 1
        assert result[0].type == "SSN"

    def test_detect_multiple(self):
        d = Detector()
        result = d.detect("Email: a@b.com, SSN: 123-45-6789")
        assert len(result) == 2
        types = {e.type for e in result}
        assert types == {"EMAIL", "SSN"}

    def test_detect_none(self):
        d = Detector()
        result = d.detect("Hello world, this is clean text.")
        assert len(result) == 0

    def test_detect_empty(self):
        d = Detector()
        assert d.detect("") == []

    def test_disabled_types(self):
        d = Detector(disabled_types=["EMAIL"])
        result = d.detect("Email: a@b.com")
        assert len(result) == 0

    def test_enabled_types(self):
        d = Detector(enabled_types=["SSN"])
        result = d.detect("Email: a@b.com, SSN: 123-45-6789")
        assert len(result) == 1
        assert result[0].type == "SSN"

    def test_custom_pattern(self):
        custom = PIIDefinition(
            name="CUSTOM_ID",
            description="Custom test",
            regex=re.compile(r"EMP-\d{4}"),
            confidence=0.9,
            severity="medium",
            placeholder="{CUSTOM_ID}",
        )
        d = Detector(custom_patterns=[custom])
        result = d.detect("Employee: EMP-1234")
        assert len(result) == 1
        assert result[0].type == "CUSTOM_ID"

    def test_excluded_patterns(self):
        d = Detector(excluded_patterns=[r"example\.com"])
        result = d.detect("email: john@example.com")
        assert len(result) == 0

    def test_hash_value(self):
        h = Detector.hash_value("test")
        assert len(h) == 16
        assert isinstance(h, str)

    def test_email_ssn_credit_card(self):
        d = Detector()
        result = d.detect("Email:user@test.com SSN:789-65-4320 CC:4111-1111-1111-1111")
        assert len(result) >= 3
        types = {e.type for e in result}
        assert "EMAIL" in types
        assert "SSN" in types
        assert "CREDIT_CARD" in types


class TestCreateDetector:
    def test_create_detector(self):
        d = create_detector()
        assert isinstance(d, Detector)
        assert len(d.definitions) == 50
