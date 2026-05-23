from __future__ import annotations

import os

from aigov_redact.detector import Detector
from aigov_redact.models import AuditEntry, AuditResult


class Auditor:
    def __init__(
        self,
        detector: Detector,
        audit_log_path: str | None = None,
    ):
        self._detector = detector
        self._audit_log_path = audit_log_path

    def scan_file(self, filepath: str) -> AuditResult:
        entries: list[AuditEntry] = []
        seen_types: set[str] = set()

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                entities = self._detector.detect(line.strip("\n"))
                for entity in entities:
                    entry = AuditEntry(
                        filename=os.path.basename(filepath),
                        line=line_no,
                        column=entity.start,
                        type=entity.type,
                        value_hash=self._detector.hash_value(entity.text),
                        confidence=entity.confidence,
                        severity=entity.severity,
                    )
                    entries.append(entry)
                    seen_types.add(entity.type)

                    if self._audit_log_path:
                        self._append_to_log(entry)

        return AuditResult(
            entries=entries,
            total_files=1,
            summary={t: sum(1 for e in entries if e.type == t) for t in seen_types},
        )

    def scan_text(self, text: str, filename: str = "<stdin>") -> AuditResult:
        entries: list[AuditEntry] = []
        seen_types: set[str] = set()

        for line_no, line in enumerate(text.splitlines(), 1):
            entities = self._detector.detect(line)
            for entity in entities:
                entry = AuditEntry(
                    filename=filename,
                    line=line_no,
                    column=entity.start,
                    type=entity.type,
                    value_hash=self._detector.hash_value(entity.text),
                    confidence=entity.confidence,
                    severity=entity.severity,
                )
                entries.append(entry)
                seen_types.add(entity.type)

                if self._audit_log_path:
                    self._append_to_log(entry)

        return AuditResult(
            entries=entries,
            total_files=1,
            summary={t: sum(1 for e in entries if e.type == t) for t in seen_types},
        )

    def _append_to_log(self, entry: AuditEntry) -> None:
        header = "timestamp,filename,line,column,type,value_hash,confidence,severity"
        write_header = not os.path.exists(self._audit_log_path) or os.path.getsize(self._audit_log_path) == 0
        with open(self._audit_log_path, "a", encoding="utf-8") as f:
            if write_header:
                f.write(header + "\n")
            f.write(entry.csv_row() + "\n")
