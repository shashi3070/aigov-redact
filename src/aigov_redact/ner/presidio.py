from __future__ import annotations

from aigov_redact.models import PIIEntity

_PRESIDIO_AVAILABLE = False

try:
    from presidio_analyzer import AnalyzerEngine
    _PRESIDIO_AVAILABLE = True
except ImportError:
    AnalyzerEngine = None  # type: ignore


_ENGINE_INSTANCE = None


def _get_engine():
    global _ENGINE_INSTANCE
    if _ENGINE_INSTANCE is None and _PRESIDIO_AVAILABLE:
        _ENGINE_INSTANCE = AnalyzerEngine()
    return _ENGINE_INSTANCE


NER_MAP = {
    "PERSON": "PERSON",
    "LOCATION": "LOCATION",
    "ORGANIZATION": "ORGANIZATION",
    "DATE_TIME": "DOB",
    "NRP": "NRP",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "CREDIT_CARD": "CREDIT_CARD",
}


def detect_ner(text: str, score_threshold: float = 0.35) -> list[PIIEntity]:
    engine = _get_engine()
    if engine is None:
        return []

    try:
        results = engine.analyze(text=text, language="en")
    except Exception:
        return []

    entities: list[PIIEntity] = []
    for r in results:
        if r.score < score_threshold:
            continue
        mapped = NER_MAP.get(r.entity_type, r.entity_type)
        entities.append(PIIEntity(
            type=mapped,
            text=text[r.start:r.end],
            start=r.start,
            end=r.end,
            confidence=r.score,
            severity="medium" if mapped in ("PERSON", "LOCATION", "ORGANIZATION") else "high",
        ))
    return entities
