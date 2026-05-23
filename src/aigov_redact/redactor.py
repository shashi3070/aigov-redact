from __future__ import annotations

import hashlib

from aigov_redact.detector import Detector, create_detector
from aigov_redact.models import DetectionResult, PIIEntity, RedactResult
from aigov_redact.patterns import PIIDefinition
from aigov_redact.usage import record_usage

_in_detect: bool = False


def detect(
    text: str,
    enabled_types: list[str] | None = None,
    disabled_types: list[str] | None = None,
    custom_patterns: list[PIIDefinition] | None = None,
    excluded_patterns: list[str] | None = None,
    ner_enabled: bool = False,
    history_path: str | None = None,
    file_path: str | None = None,
    source: str | None = None,
) -> DetectionResult:
    global _in_detect
    detector = create_detector(
        enabled_types=enabled_types,
        disabled_types=disabled_types,
        custom_patterns=custom_patterns,
        excluded_patterns=excluded_patterns,
    )
    entities = detector.detect(text)

    if ner_enabled:
        try:
            from aigov_redact.ner.presidio import detect_ner
            ner_entities = detect_ner(text)
            entities.extend(ner_entities)
            entities = Detector._resolve_overlaps(entities)
        except ImportError:
            pass

    result = DetectionResult(text=text, entities=entities)

    if not _in_detect:
        record_usage(
            command="check",
            history_path=history_path,
            source=source or "library",
            file_path=file_path,
            entity_count=result.count,
            entity_types=[e.type for e in result.entities],
            ner_enabled=ner_enabled,
        )

    return result


def redact(
    text: str,
    mode: str = "replace",
    enabled_types: list[str] | None = None,
    disabled_types: list[str] | None = None,
    custom_patterns: list[PIIDefinition] | None = None,
    excluded_patterns: list[str] | None = None,
    ner_enabled: bool = False,
    placeholder_style: str = "type",
    mask_char: str = "*",
    custom_placeholder: str = "{PII}",
    history_path: str | None = None,
    file_path: str | None = None,
    source: str | None = None,
) -> RedactResult:
    global _in_detect
    _in_detect = True
    detection = detect(
        text=text,
        enabled_types=enabled_types,
        disabled_types=disabled_types,
        custom_patterns=custom_patterns,
        excluded_patterns=excluded_patterns,
        ner_enabled=ner_enabled,
    )
    _in_detect = False

    entities = detection.entities

    if mode == "remove":
        result = _apply_remove(text, entities)
    elif mode == "mask":
        result = _apply_mask(text, entities, mask_char)
    elif mode == "hash":
        result = _apply_hash(text, entities)
    elif mode == "custom":
        result = _apply_custom(text, entities, custom_placeholder)
    else:
        result = _apply_replace(text, entities, placeholder_style)

    record_usage(
        command="redact",
        history_path=history_path,
        source=source or "library",
        file_path=file_path,
        entity_count=len(entities),
        entity_types=[e.type for e in entities],
        mode=mode,
        ner_enabled=ner_enabled,
    )

    return RedactResult(text=result, entities=entities, mode=mode)


def mask(
    text: str,
    char: str = "*",
    enabled_types: list[str] | None = None,
    disabled_types: list[str] | None = None,
    custom_patterns: list[PIIDefinition] | None = None,
    excluded_patterns: list[str] | None = None,
    history_path: str | None = None,
    file_path: str | None = None,
) -> RedactResult:
    return redact(
        text=text,
        mode="mask",
        mask_char=char,
        enabled_types=enabled_types,
        disabled_types=disabled_types,
        custom_patterns=custom_patterns,
        excluded_patterns=excluded_patterns,
        history_path=history_path,
        file_path=file_path,
    )


def _apply_replace(text: str, entities: list[PIIEntity], style: str = "type") -> str:
    if style == "hash":
        return _apply_hash(text, entities)
    if style == "redact":
        return _apply_remove(text, entities)
    if style == "custom":
        return _apply_custom(text, entities, "{PII}")

    result = list(text)
    for ent in sorted(entities, key=lambda e: e.start, reverse=True):
        placeholder = ent.placeholder or f"{{{ent.type}}}"
        result[ent.start:ent.end] = placeholder
    return "".join(result)


def _apply_mask(text: str, entities: list[PIIEntity], char: str = "*") -> str:
    result = list(text)
    for ent in sorted(entities, key=lambda e: e.start, reverse=True):
        length = ent.end - ent.start
        result[ent.start:ent.end] = char * length
    return "".join(result)


def _apply_hash(text: str, entities: list[PIIEntity]) -> str:
    result = list(text)
    for ent in sorted(entities, key=lambda e: e.start, reverse=True):
        hash_val = hashlib.sha256(ent.text.encode("utf-8")).hexdigest()[:8]
        result[ent.start:ent.end] = f"<{ent.type}_{hash_val}>"
    return "".join(result)


def _apply_remove(text: str, entities: list[PIIEntity]) -> str:
    result = list(text)
    for ent in sorted(entities, key=lambda e: e.start, reverse=True):
        del result[ent.start:ent.end]
    return "".join(result)


def _apply_custom(text: str, entities: list[PIIEntity], placeholder: str) -> str:
    result = list(text)
    for ent in sorted(entities, key=lambda e: e.start, reverse=True):
        result[ent.start:ent.end] = placeholder
    return "".join(result)
