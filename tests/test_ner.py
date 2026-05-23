from __future__ import annotations

import pytest

from aigov_redact.ner.presidio import detect_ner


@pytest.mark.skipif(True, reason="Presidio not installed in test environment")
class TestNER:
    def test_detect_ner_email(self):
        result = detect_ner("Contact John at john@example.com")
        types = {e.type for e in result}
        assert "PERSON" in types or "EMAIL" in types

    def test_detect_empty(self):
        result = detect_ner("")
        assert result == []

    def test_score_threshold(self):
        result = detect_ner("Hello world", score_threshold=0.99)
        assert result == []
