from __future__ import annotations

import hashlib
import re

from aigov_redact.models import PIIEntity
from aigov_redact.patterns import PATTERNS, PIIDefinition


class Detector:
    def __init__(
        self,
        enabled_types: list[str] | None = None,
        disabled_types: list[str] | None = None,
        custom_patterns: list[PIIDefinition] | None = None,
        excluded_patterns: list[str] | None = None,
    ):
        self._definitions: list[PIIDefinition] = list(PATTERNS)

        if disabled_types:
            self._definitions = [p for p in self._definitions if p.name not in disabled_types]

        if enabled_types:
            self._definitions = [p for p in self._definitions if p.name in enabled_types]

        if custom_patterns:
            self._definitions.extend(custom_patterns)

        self._excluded: list[re.Pattern] = []
        if excluded_patterns:
            self._excluded = [re.compile(p) for p in excluded_patterns]

        self._definitions.sort(key=lambda p: p.tier)

    @property
    def definitions(self) -> list[PIIDefinition]:
        return list(self._definitions)

    def detect(self, text: str) -> list[PIIEntity]:
        raw: list[PIIEntity] = []

        for definition in self._definitions:
            for match in definition.regex.finditer(text):
                value = match.group()
                if self._is_excluded(value):
                    continue
                if definition.validator and not definition.validator(value):
                    continue
                raw.append(PIIEntity(
                    type=definition.name,
                    text=value,
                    start=match.start(),
                    end=match.end(),
                    confidence=definition.confidence,
                    severity=definition.severity,
                    placeholder=definition.placeholder,
                ))

        return self._resolve_overlaps(raw)

    def detect_line(self, text: str, line_number: int = 1) -> list[PIIEntity]:
        entities = self.detect(text)
        for e in entities:
            e.start += 0
            e.end += 0
        return entities

    def _is_excluded(self, value: str) -> bool:
        for pattern in self._excluded:
            if pattern.search(value):
                return True
        return False

    @staticmethod
    def _resolve_overlaps(entities: list[PIIEntity]) -> list[PIIEntity]:
        if not entities:
            return []

        sorted_ents = sorted(entities, key=lambda e: (e.start, -e.end))
        merged: list[PIIEntity] = []
        for ent in sorted_ents:
            if merged and ent.start < merged[-1].end:
                prev = merged[-1]
                if ent.end > prev.end:
                    if ent.confidence > prev.confidence:
                        merged[-1] = ent
                    elif ent.confidence == prev.confidence and (ent.end - ent.start) > (prev.end - prev.start):
                        merged[-1] = ent
            else:
                merged.append(ent)

        final: list[PIIEntity] = []
        for ent in merged:
            if not final or ent.start >= final[-1].end:
                final.append(ent)
            elif ent.end > final[-1].end and ent.confidence > final[-1].confidence:
                final[-1] = ent

        return final

    @staticmethod
    def hash_value(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def create_detector(
    enabled_types: list[str] | None = None,
    disabled_types: list[str] | None = None,
    custom_patterns: list[PIIDefinition] | None = None,
    excluded_patterns: list[str] | None = None,
) -> Detector:
    return Detector(
        enabled_types=enabled_types,
        disabled_types=disabled_types,
        custom_patterns=custom_patterns,
        excluded_patterns=excluded_patterns,
    )
