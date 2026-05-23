from __future__ import annotations

from aigov_redact.redactor import detect, mask, redact


class TestRedact:
    def test_redact_email(self):
        result = redact("My email is john@example.com")
        assert "{EMAIL}" in result.text
        assert "john@example.com" not in result.text
        assert len(result.entities) == 1

    def test_redact_ssn(self):
        result = redact("My SSN is 123-45-6789")
        assert "{SSN}" in result.text
        assert "123-45-6789" not in result.text

    def test_redact_multiple(self):
        result = redact("Email: a@b.com, SSN: 123-45-6789")
        assert "{EMAIL}" in result.text
        assert "{SSN}" in result.text

    def test_redact_none(self):
        result = redact("Hello world")
        assert result.text == "Hello world"
        assert len(result.entities) == 0

    def test_redact_mode_mask(self):
        result = redact("Email: a@b.com", mode="mask")
        assert "@" not in result.text
        assert "*" in result.text

    def test_redact_mode_hash(self):
        result = redact("SSN: 123-45-6789", mode="hash")
        assert "<SSN_" in result.text
        assert "123-45-6789" not in result.text

    def test_redact_mode_remove(self):
        result = redact("Email: a@b.com", mode="remove")
        assert result.text == "Email: "

    def test_redact_mode_custom(self):
        result = redact("SSN: 123-45-6789", mode="custom", custom_placeholder="[REDACTED]")
        assert "[REDACTED]" in result.text
        assert "123-45-6789" not in result.text

    def test_redact_placeholder_style_hash(self):
        result = redact("Email: a@b.com", placeholder_style="hash")
        assert "{EMAIL}" not in result.text
        assert "a@b.com" not in result.text

    def test_redact_unicode(self):
        result = redact("Email: user@domain.com with unicode")
        assert "{EMAIL}" in result.text
        assert "user@domain.com" not in result.text

    def test_redact_multiple_same_type(self):
        result = redact("Emails: a@b.com and c@d.com")
        assert result.text.count("{EMAIL}") == 2


class TestDetect:
    def test_detect_results(self):
        result = detect("Email: a@b.com, Phone: 555-123-4567")
        assert len(result.entities) >= 1
        assert result.count >= 1

    def test_detect_no_pii(self):
        result = detect("Hello world")
        assert result.count == 0
        assert len(result.entities) == 0


class TestMask:
    def test_mask_default_char(self):
        result = mask("Email: a@b.com")
        assert "@" not in result.text
        assert result.entities[0].type == "EMAIL"

    def test_mask_custom_char(self):
        result = mask("SSN: 123-45-6789", char="#")
        assert "123-45-6789" not in result.text
        assert result.text.count("#") == 11
