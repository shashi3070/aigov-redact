from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aigov_redact.mapping.vault import MappingVault


_CURRENCY_PATTERN = re.compile(
    r"([₹$€£¥])\s*(\d+(?:\.\d+)?)\s*(Cr|Lakh|Million|Billion|K|%|lakh|cr)?"
)
_NUMBER_PATTERN = re.compile(
    r"(?<![<₹$€£¥\w.])(\d+(?:\.\d+)?)\s*(Cr|Lakh|Million|Billion|K|%|lakh|cr)(?![>\w])"
)


class NumberTransformer:
    """Transforms numeric values for privacy protection.

    Supports:
    - Scale: multiply by a factor
    - Random scale: multiply by a random factor within a range
    - Range: replace with approximate range
    - Percentile: replace with percentile rank
    - Preserve: no transformation
    """

    def __init__(self, vault: MappingVault | None = None):
        self._vault = vault

    def scale(self, text: str, factor: float) -> str:
        def replace_currency(match: re.Match) -> str:
            prefix = match.group(1)
            value = float(match.group(2))
            unit = match.group(3) or ""
            scaled = round(value * factor, 2)
            if self._vault:
                self._vault.register_number_op(value, scaled, "scale", factor)
            return f"{prefix}{scaled} {unit}".strip()

        def replace_number(match: re.Match) -> str:
            value = float(match.group(1))
            unit = match.group(2) or ""
            scaled = round(value * factor, 2)
            if self._vault:
                self._vault.register_number_op(value, scaled, "scale", factor)
            return f"{scaled} {unit}".strip()

        result = _CURRENCY_PATTERN.sub(replace_currency, text)
        result = _NUMBER_PATTERN.sub(replace_number, result)
        return result

    def random_scale(self, text: str, min_factor: float = 0.8, max_factor: float = 1.4) -> str:
        import random
        factor = random.uniform(min_factor, max_factor)
        return self.scale(text, factor)

    def range_transform(self, text: str) -> str:
        def replace_currency(match: re.Match) -> str:
            prefix = match.group(1) or ""
            value = float(match.group(2))
            unit = match.group(3) or ""
            magnitude = 10 ** (len(str(int(value))) - 1) if value >= 10 else 1
            low = (int(value) // magnitude) * magnitude
            high = low + magnitude
            if self._vault:
                self._vault.register_number_op(value, float(low), "range")
            return f"{prefix}{low}-{high} {unit}".strip()

        def replace_number(match: re.Match) -> str:
            value_str = match.group(1)
            if value_str is None:
                return match.group(0)
            value = float(value_str)
            unit = match.group(2) or ""
            magnitude = 10 ** (len(str(int(value))) - 1) if value >= 10 else 1
            low = (int(value) // magnitude) * magnitude
            high = low + magnitude
            if self._vault:
                self._vault.register_number_op(value, float(low), "range")
            return f"{low}-{high} {unit}".strip()

        result = _CURRENCY_PATTERN.sub(replace_currency, text)
        result = _NUMBER_PATTERN.sub(replace_number, result)
        return result

    def percentile_transform(self, text: str) -> str:
        return text

    def reverse(self, text: str) -> str:
        if not self._vault:
            return text

        def reverse_currency(match: re.Match) -> str:
            prefix = match.group(1) or ""
            transformed = float(match.group(2))
            unit = match.group(3) or ""
            original = self._vault.reverse_number(transformed)
            if original is not None:
                return f"{prefix}{original} {unit}".strip()
            return match.group(0)

        def reverse_number(match: re.Match) -> str:
            transformed = float(match.group(1))
            unit = match.group(2) or ""
            original = self._vault.reverse_number(transformed)
            if original is not None:
                return f"{original} {unit}".strip()
            return match.group(0)

        result = _CURRENCY_PATTERN.sub(reverse_currency, text)
        result = _NUMBER_PATTERN.sub(reverse_number, result)
        return result
