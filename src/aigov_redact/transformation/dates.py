from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aigov_redact.mapping.vault import MappingVault

_YMD_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}")
_DMY_PATTERN = re.compile(r"\d{2}/\d{2}/\d{4}")
_MDY_PATTERN = re.compile(r"\d{2}-\d{2}-\d{4}")


class DateTransformer:
    """Transforms date values for privacy protection.

    Supports:
    - Shift: offset all dates by a constant number of days
    - Preserve: no transformation
    """

    def __init__(self, vault: MappingVault | None = None):
        self._vault = vault

    def shift(self, text: str, days: int) -> str:
        def shift_ymd(match: re.Match) -> str:
            try:
                d = datetime.strptime(match.group(0), "%Y-%m-%d")
                shifted = d + timedelta(days=days)
                if self._vault:
                    self._vault.register_date_op(d, shifted)
                return shifted.strftime("%Y-%m-%d")
            except ValueError:
                return match.group(0)

        def shift_dmy(match: re.Match) -> str:
            try:
                d = datetime.strptime(match.group(0), "%d/%m/%Y")
                shifted = d + timedelta(days=days)
                if self._vault:
                    self._vault.register_date_op(d, shifted)
                return shifted.strftime("%d/%m/%Y")
            except ValueError:
                return match.group(0)

        def shift_mdy(match: re.Match) -> str:
            try:
                d = datetime.strptime(match.group(0), "%m-%d-%Y")
                shifted = d + timedelta(days=days)
                if self._vault:
                    self._vault.register_date_op(d, shifted)
                return shifted.strftime("%m-%d-%Y")
            except ValueError:
                return match.group(0)

        result = _YMD_PATTERN.sub(shift_ymd, text)
        result = _DMY_PATTERN.sub(shift_dmy, result)
        result = _MDY_PATTERN.sub(shift_mdy, result)
        return result

    def reverse(self, text: str) -> str:
        if not self._vault:
            return text

        def reverse_ymd(match: re.Match) -> str:
            try:
                d = datetime.strptime(match.group(0), "%Y-%m-%d")
                original = self._vault.reverse_date(d)
                if original is not None:
                    return original.strftime("%Y-%m-%d")
                return match.group(0)
            except ValueError:
                return match.group(0)

        result = _YMD_PATTERN.sub(reverse_ymd, text)
        return result
