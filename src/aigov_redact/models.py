from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field, computed_field


class PIIEntity(BaseModel):
    type: str
    text: str
    start: int
    end: int
    confidence: float = 0.0
    severity: str = "medium"
    placeholder: str = ""


class RedactResult(BaseModel):
    text: str
    entities: list[PIIEntity]
    mode: str = "replace"


class DetectionResult(BaseModel):
    text: str
    entities: list[PIIEntity]

    @computed_field
    @property
    def count(self) -> int:
        return len(self.entities)


class AuditEntry(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    filename: str
    line: int
    column: int
    type: str
    value_hash: str
    confidence: float
    severity: str

    def csv_row(self) -> str:
        return (
            f"{self.timestamp},"
            f"{self.filename},"
            f"{self.line},"
            f"{self.column},"
            f"{self.type},"
            f"{self.value_hash},"
            f"{self.confidence},"
            f"{self.severity}"
        )


class AuditResult(BaseModel):
    entries: list[AuditEntry]
    total_files: int = 0

    @computed_field
    @property
    def total_entities(self) -> int:
        return len(self.entries)

    @computed_field
    @property
    def summary(self) -> dict[str, int]:
        s: dict[str, int] = {}
        for entry in self.entries:
            s[entry.type] = s.get(entry.type, 0) + 1
        return s
