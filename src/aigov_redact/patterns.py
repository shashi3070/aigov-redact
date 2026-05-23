from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


@dataclass
class PIIDefinition:
    name: str
    description: str
    regex: re.Pattern
    confidence: float
    severity: str
    placeholder: str
    validator: Callable[[str], bool] | None = None
    tier: int = 3


def _always_valid(_: str) -> bool:
    return True


def _luhn_checksum(card: str) -> bool:
    digits = [int(c) for c in card if c.isdigit()]
    if len(digits) < 12:
        return False
    if len(set(digits)) == 1:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _validate_ssn(value: str) -> bool:
    digits = value.replace("-", "")
    if len(digits) != 9 or not digits.isdigit():
        return False
    area = int(digits[:3])
    if area in (0, 666) or area >= 900:
        return False
    group = int(digits[3:5])
    serial = int(digits[5:])
    if group == 0 or serial == 0:
        return False
    return True


def _validate_itin(value: str) -> bool:
    digits = value.replace("-", "")
    if len(digits) != 9 or not digits.isdigit():
        return False
    if digits[0] != "9":
        return False
    if digits[3] not in ("7", "8"):
        return False
    return True


def _validate_ein(value: str) -> bool:
    cleaned = value.replace("-", "")
    if len(cleaned) != 9 or not cleaned.isdigit():
        return False
    if cleaned[0] == "0":
        return False
    return True


def _validate_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _validate_phone_us(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11 and digits[0] == "1":
        digits = digits[1:]
    if len(digits) != 10:
        return False
    area = int(digits[:3])
    exchange = int(digits[3:6])
    if area < 200 or exchange < 200:
        return False
    return True


def _validate_routing(value: str) -> bool:
    digits = value.replace("-", "")
    if len(digits) != 9 or not digits.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(digits, [3, 7, 1, 3, 7, 1, 3, 7, 1]))
    return total % 10 == 0


def _validate_uk_nhs(value: str) -> bool:
    digits = value.replace(" ", "")
    if len(digits) != 10 or not digits.isdigit():
        return False
    total = sum(int(d) * (10 - i) for i, d in enumerate(digits[:9]))
    check = total % 11
    if check == 11:
        check = 0
    return check == int(digits[9])


def _validate_au_tfn(value: str) -> bool:
    digits = value.replace(" ", "")
    if len(digits) not in (8, 9) or not digits.isdigit():
        return False
    weights = [1, 4, 3, 7, 5, 8, 6, 9, 10][-len(digits):]
    total = sum(int(d) * w for d, w in zip(digits, weights))
    return total % 11 != 0


def _validate_ca_sin(value: str) -> bool:
    digits = value.replace(" ", "").replace("-", "")
    if len(digits) != 9 or not digits.isdigit():
        return False
    return _luhn_checksum(digits)


def _validate_uk_nino(value: str) -> bool:
    cleaned = value.replace(" ", "").upper()
    if not re.match(r"^[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]$", cleaned):
        return False
    invalid_prefixes = {"GB", "BG", "NK", "KN", "TN", "NT", "ZZ"}
    if cleaned[:2] in invalid_prefixes:
        return False
    return True


def _validate_br_cpf(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11:
        return False
    if all(c == digits[0] for c in digits):
        return False
    total = sum(int(digits[i]) * (10 - i) for i in range(9))
    d1 = (total * 10) % 11
    if d1 == 10:
        d1 = 0
    if d1 != int(digits[9]):
        return False
    total = sum(int(digits[i]) * (11 - i) for i in range(10))
    d2 = (total * 10) % 11
    if d2 == 10:
        d2 = 0
    return d2 == int(digits[10])


def _validate_br_cnpj(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 14:
        return False
    if all(c == digits[0] for c in digits):
        return False
    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(int(digits[i]) * w1[i] for i in range(12))
    d1 = total % 11
    d1 = 0 if d1 < 2 else 11 - d1
    if d1 != int(digits[12]):
        return False
    w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(int(digits[i]) * w2[i] for i in range(13))
    d2 = total % 11
    d2 = 0 if d2 < 2 else 11 - d2
    return d2 == int(digits[13])


def _validate_aadhaar(value: str) -> bool:
    digits = value.replace(" ", "")
    if len(digits) != 12 or not digits.isdigit():
        return False
    if digits[0] in ("0", "1"):
        return False
    return True


def _validate_pan_india(value: str) -> bool:
    cleaned = value.upper().strip()
    if not re.match(r"^[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]$", cleaned):
        return False
    return True


def _validate_cn_id(value: str) -> bool:
    digits = value.upper().replace("X", "X")
    if not re.match(r"^\d{17}[\dX]$", digits):
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    total = sum(int(digits[i]) * weights[i] for i in range(17))
    check = (12 - (total % 11)) % 11
    expected = str(check) if check < 10 else "X"
    return expected == digits[17]


def _validate_bitcoin(value: str) -> bool:
    return bool(re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", value))


def _validate_eth(value: str) -> bool:
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", value))


def _validate_crypto(value: str) -> bool:
    return _validate_bitcoin(value) or _validate_eth(value)


def _validate_jwt(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    for p in parts:
        try:
            base = p.replace("-", "+").replace("_", "/")
            rem = len(base) % 4
            if rem == 2:
                base += "=="
            elif rem == 3:
                base += "="
            import base64
            base64.b64decode(base, validate=True)
        except Exception:
            return False
    return True


def _validate_medicare_au(value: str) -> bool:
    digits = value.replace(" ", "")
    if len(digits) != 10 or not digits.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(digits[:8], [1, 3, 7, 9, 1, 3, 7, 9]))
    check = total % 10
    return check == int(digits[8])


def _validate_dea(value: str) -> bool:
    cleaned = value.upper().strip()
    if not re.match(r"^[ABFGMPSU][A-Z]\d{7}$", cleaned):
        return False
    digits = cleaned[2:]
    odd_sum = sum(int(d) for i, d in enumerate(digits[:6]) if i % 2 == 0)
    even_sum = sum(int(d) for i, d in enumerate(digits[:6]) if i % 2 == 1)
    check = (odd_sum + even_sum * 2) % 10
    return check == int(digits[-1])


def _validate_iban(value: str) -> bool:
    cleaned = value.replace(" ", "").upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", cleaned):
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    num_str = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    remainder = int(num_str) % 97
    return remainder == 1


# =============================================================================
# All 44 pattern definitions
# =============================================================================

PATTERNS: list[PIIDefinition] = [

    # ── TIER 1: High confidence, rigorous validation ──────────────────────
    PIIDefinition(
        name="EMAIL",
        description="Email address (RFC 5322 loose)",
        regex=re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        confidence=0.95,
        severity="high",
        placeholder="{EMAIL}",
        tier=1,
    ),
    PIIDefinition(
        name="SSN",
        description="US Social Security Number (with area validation)",
        regex=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        confidence=0.98,
        severity="critical",
        placeholder="{SSN}",
        validator=_validate_ssn,
        tier=1,
    ),
    PIIDefinition(
        name="CREDIT_CARD",
        description="Credit/debit card number (Luhn-validated)",
        regex=re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        confidence=0.98,
        severity="critical",
        placeholder="{CREDIT_CARD}",
        validator=_luhn_checksum,
        tier=1,
    ),
    PIIDefinition(
        name="IBAN",
        description="International Bank Account Number (MOD-97)",
        regex=re.compile(
            r"\b[A-Z]{2}\d{2}[ ]?[A-Z0-9]{4}[ ]?[A-Z0-9]{4}"
            r"[ ]?[A-Z0-9]{4}[ ]?[A-Z0-9]{4}[ ]?[A-Z0-9]{1,14}\b"
        ),
        confidence=0.98,
        severity="critical",
        placeholder="{IBAN}",
        validator=_validate_iban,
        tier=1,
    ),
    PIIDefinition(
        name="AADHAAR",
        description="India Aadhaar number (12-digit)",
        regex=re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b"),
        confidence=0.90,
        severity="high",
        placeholder="{AADHAAR}",
        validator=_validate_aadhaar,
        tier=1,
    ),
    PIIDefinition(
        name="PAN_INDIA",
        description="India Permanent Account Number",
        regex=re.compile(r"\b[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]\b", re.IGNORECASE),
        confidence=0.90,
        severity="high",
        placeholder="{PAN_INDIA}",
        validator=_validate_pan_india,
        tier=1,
    ),
    PIIDefinition(
        name="ITIN",
        description="US Individual Taxpayer Identification Number",
        regex=re.compile(r"\b9\d{2}-\d{2}-\d{4}\b"),
        confidence=0.95,
        severity="high",
        placeholder="{ITIN}",
        validator=_validate_itin,
        tier=1,
    ),
    PIIDefinition(
        name="EIN",
        description="US Employer Identification Number",
        regex=re.compile(r"\b\d{2}-\d{7}\b"),
        confidence=0.95,
        severity="high",
        placeholder="{EIN}",
        validator=_validate_ein,
        tier=1,
    ),
    PIIDefinition(
        name="UK_NHS",
        description="UK National Health Service Number (modulus-11)",
        regex=re.compile(r"\b\d{3}\s?\d{3}\s?\d{4}\b"),
        confidence=0.90,
        severity="high",
        placeholder="{UK_NHS}",
        validator=_validate_uk_nhs,
        tier=1,
    ),
    PIIDefinition(
        name="AU_TFN",
        description="Australian Tax File Number (modulus-11)",
        regex=re.compile(r"\b\d{2,3}\s?\d{3}\s?\d{3}\b"),
        confidence=0.85,
        severity="high",
        placeholder="{AU_TFN}",
        validator=_validate_au_tfn,
        tier=1,
    ),
    PIIDefinition(
        name="ROUTING_NUMBER",
        description="US ABA Routing Number (check digit)",
        regex=re.compile(r"\b\d{9}\b"),
        confidence=0.80,
        severity="high",
        placeholder="{ROUTING_NUMBER}",
        validator=_validate_routing,
        tier=1,
    ),
    PIIDefinition(
        name="PRIVATE_KEY",
        description="Private key in PEM format",
        regex=re.compile(r"-----BEGIN\s[A-Z ]+?KEY-----[a-zA-Z0-9+/=\s]+?-----END\s[A-Z ]+?KEY-----"),
        confidence=0.95,
        severity="critical",
        placeholder="{PRIVATE_KEY}",
        tier=1,
    ),

    # ── TIER 2: Medium-high confidence, format validation ────────────────
    PIIDefinition(
        name="PHONE_US",
        description="US phone number (10-digit NANP)",
        regex=re.compile(r"\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}"),
        confidence=0.95,
        severity="high",
        placeholder="{PHONE}",
        validator=_validate_phone_us,
        tier=2,
    ),
    PIIDefinition(
        name="PHONE_INTL",
        description="International phone number (with + prefix)",
        regex=re.compile(r"\+\d{1,3}[\s.-]?\d{3,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}"),
        confidence=0.85,
        severity="high",
        placeholder="{PHONE}",
        tier=2,
    ),
    PIIDefinition(
        name="US_PASSPORT",
        description="US Passport number (9-digit)",
        regex=re.compile(r"\b\d{9}\b"),
        confidence=0.70,
        severity="high",
        placeholder="{PASSPORT}",
        tier=2,
    ),
    PIIDefinition(
        name="DRIVERS_LICENSE",
        description="US Driver's License number (CA, NY, TX, FL, IL, OH, PA)",
        regex=re.compile(r"\b[A-Z]\d{7}\b"),
        confidence=0.70,
        severity="high",
        placeholder="{DRIVERS_LICENSE}",
        tier=2,
    ),
    PIIDefinition(
        name="UK_NINO",
        description="UK National Insurance Number",
        regex=re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?[A-D]\b", re.IGNORECASE),
        confidence=0.90,
        severity="high",
        placeholder="{UK_NINO}",
        validator=_validate_uk_nino,
        tier=2,
    ),
    PIIDefinition(
        name="CA_SIN",
        description="Canadian Social Insurance Number (Luhn)",
        regex=re.compile(r"\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b"),
        confidence=0.85,
        severity="high",
        placeholder="{CA_SIN}",
        validator=_validate_ca_sin,
        tier=2,
    ),
    PIIDefinition(
        name="AU_MEDICARE",
        description="Australian Medicare number (checksum)",
        regex=re.compile(r"\b\d{4}\s?\d{5}\s?\d{1}\b"),
        confidence=0.85,
        severity="high",
        placeholder="{AU_MEDICARE}",
        validator=_validate_medicare_au,
        tier=2,
    ),
    PIIDefinition(
        name="BR_CPF",
        description="Brazilian CPF (modulus-11)",
        regex=re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
        confidence=0.85,
        severity="high",
        placeholder="{BR_CPF}",
        validator=_validate_br_cpf,
        tier=2,
    ),
    PIIDefinition(
        name="BR_CNPJ",
        description="Brazilian CNPJ (modulus-11)",
        regex=re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
        confidence=0.85,
        severity="high",
        placeholder="{BR_CNPJ}",
        validator=_validate_br_cnpj,
        tier=2,
    ),
    PIIDefinition(
        name="CN_ID",
        description="China ID card number (18-digit weighted sum)",
        regex=re.compile(r"\b\d{17}[\dXx]\b"),
        confidence=0.85,
        severity="high",
        placeholder="{CN_ID}",
        validator=_validate_cn_id,
        tier=2,
    ),
    PIIDefinition(
        name="JP_MYNUMBER",
        description="Japan My Number (12-digit)",
        regex=re.compile(r"\b\d{12}\b"),
        confidence=0.75,
        severity="high",
        placeholder="{JP_MYNUMBER}",
        tier=2,
    ),
    PIIDefinition(
        name="CRYPTO_WALLET",
        description="Cryptocurrency wallet address (BTC/ETH)",
        regex=re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b"),
        confidence=0.90,
        severity="high",
        placeholder="{CRYPTO_WALLET}",
        validator=_validate_crypto,
        tier=2,
    ),

    # ── TIER 3: Medium confidence, shape-based detection ─────────────────
    PIIDefinition(
        name="IPV4",
        description="IPv4 address",
        regex=re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        confidence=0.70,
        severity="medium",
        placeholder="{IP}",
        validator=_validate_ipv4,
        tier=3,
    ),
    PIIDefinition(
        name="IPV6",
        description="IPv6 address (RFC 4291)",
        regex=re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
        confidence=0.70,
        severity="medium",
        placeholder="{IP}",
        tier=3,
    ),
    PIIDefinition(
        name="API_KEY",
        description="API key / secret token (prefix-based)",
        regex=re.compile(
            r"\b("
            r"sk-proj-[a-zA-Z0-9]{20,}"
            r"|sk-[a-zA-Z0-9]{20,}"
            r"|pk-[a-zA-Z0-9]{20,}"
            r"|github_pat_[a-zA-Z0-9]{30,}"
            r"|gh[opuv]_[a-zA-Z0-9]{30,}"
            r"|xox[abp]-[a-zA-Z0-9-]{10,}"
            r"|AKIA[0-9A-Z]{16}"
            r"|da2-[a-z0-9]{26}"
            r"|(?:rk|sk)_(?:live|test)_[a-zA-Z0-9]{20,}"
            r"|whsec_[a-zA-Z0-9]{16,}"
            r"|SB-\d{8,}"
            r"|AIza[0-9A-Za-z_-]{20,}"
            r"|glpat-[a-zA-Z0-9_-]{10,}"
            r"|hrku_[a-zA-Z0-9-]{30,}"
            r"|AC[a-zA-Z0-9]{32}"
            r"|PMAT-[A-Za-z0-9]{20,}"
            r"|npm_[a-zA-Z0-9]{30,}"
            r"|key-[a-zA-Z0-9]{30,}"
            r"|pypi-[A-Za-z0-9_-]{20,}"
            r"|dop_v1_[a-zA-Z0-9]{50,}"
            r"|robots[A-Za-z0-9]{32,}"
            r"|SG\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{30,}"
            r"|shp(?:at|ss|sa)_[a-zA-Z0-9]{32}"
            r"|NRAK-[A-Za-z0-9]{20,}"
            r"|EAAA[A-Za-z0-9]{30,}"
            r"|hvs\.[A-Za-z0-9]{24,}"
            r"|pscale_pw_[a-zA-Z0-9]{30,}"
            r"|lin_api_[a-zA-Z0-9]{30,}"
            r"|tfp_[A-Za-z0-9]{40,}"
            r"|GOCSPX-[A-Za-z0-9]{20,}"
            r"|ghr_[A-Za-z0-9]{30,}"
            r"|GR1348941[A-Za-z0-9]{16,}"
            r"|EAAC[A-Za-z0-9]{30,}"
            r"|dt0c01\.[A-Za-z0-9]{20,}\.[A-Za-z0-9]{50,}"
            r"|ATATT3xFfGF[A-Za-z0-9]{30,}"
            r"|y_[A-Za-z0-9]{20,}"
            r"|(?:pub|sub)-c-[a-zA-Z0-9-]{30,}"
            r"|hawkt\.[a-zA-Z0-9]{30,}\.[A-Za-z0-9]{4,}"
            r"|api-[a-zA-Z0-9-]{30,}"
            r"|oauth:[a-zA-Z0-9]{20,}"
            r"|00[a-zA-Z0-9]{30,}"
            r"|CLOJARS_[a-zA-Z0-9]{30,}"
            r"|AAAA[a-zA-Z0-9]+:APA91[a-zA-Z0-9]{30,}"
            r"|IQoJ[A-Za-z0-9+/]{20,}"
            r"|API-[A-Za-z0-9]{20,}"
            r"|pk\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9]{20,}"
            r"|1000\.[a-zA-Z0-9]{30,}\.[a-zA-Z0-9]{30,}"
            r"|ED[A-Za-z0-9]{50,}"
            r"|v1[A-Za-z0-9]{50,}"
            r")\b"
        ),
        confidence=0.95,
        severity="critical",
        placeholder="{API_KEY}",
        tier=3,
    ),
    PIIDefinition(
        name="AWS_SECRET_KEY",
        description="AWS Secret Access Key (40-char base64)",
        regex=re.compile(r"\b[A-Za-z0-9+/]{40}\b"),
        confidence=0.80,
        severity="critical",
        placeholder="{AWS_SECRET_KEY}",
        tier=3,
    ),
    PIIDefinition(
        name="URL_CREDENTIALS",
        description="URL containing embedded credentials",
        regex=re.compile(r"(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|redshift|mssql|amqp)://[^\s:@]+:[^\s:@]+@[^\s]+"),
        confidence=0.98,
        severity="critical",
        placeholder="{URL}",
        tier=3,
    ),
    PIIDefinition(
        name="AZURE_CONNECTION_STRING",
        description="Azure Storage connection string with account key",
        regex=re.compile(r"AccountKey=[a-zA-Z0-9+/=]{80,}"),
        confidence=0.80,
        severity="critical",
        placeholder="{AZURE_KEY}",
        tier=3,
    ),
    PIIDefinition(
        name="TELEGRAM_BOT_TOKEN",
        description="Telegram Bot Token (numeric:alphanumeric)",
        regex=re.compile(r"\b\d{8,10}:[\w-]{35,}\b"),
        confidence=0.95,
        severity="critical",
        placeholder="{TELEGRAM_BOT}",
        tier=3,
    ),
    PIIDefinition(
        name="HASHICORP_TF_TOKEN",
        description="HashiCorp Terraform Cloud token (atlasv1 format)",
        regex=re.compile(r"\b[a-zA-Z0-9_]{16,}\.atlasv1\.[a-zA-Z0-9]{50,}\b"),
        confidence=0.90,
        severity="critical",
        placeholder="{HASHICORP_TOKEN}",
        tier=3,
    ),
    PIIDefinition(
        name="BANK_ACCOUNT",
        description="US Bank Account number (8-17 digits)",
        regex=re.compile(r"\b\d{8,17}\b"),
        confidence=0.60,
        severity="high",
        placeholder="{BANK_ACCOUNT}",
        tier=3,
    ),
    PIIDefinition(
        name="MAC_ADDRESS",
        description="MAC address (6 hex pairs)",
        regex=re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b"),
        confidence=0.70,
        severity="low",
        placeholder="{MAC_ADDRESS}",
        tier=3,
    ),
    PIIDefinition(
        name="JWT_TOKEN",
        description="JSON Web Token (3 base64url segments)",
        regex=re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
        confidence=0.85,
        severity="critical",
        placeholder="{JWT}",
        validator=_validate_jwt,
        tier=3,
    ),
    PIIDefinition(
        name="DISCORD_BOT_TOKEN",
        description="Discord Bot Token (3 base64 segments)",
        regex=re.compile(r"\b[A-Za-z0-9_]{22,26}\.[A-Za-z0-9_]{5,7}\.[A-Za-z0-9_]{27,}\b"),
        confidence=0.85,
        severity="critical",
        placeholder="{DISCORD_TOKEN}",
        validator=_validate_jwt,
        tier=3,
    ),
    PIIDefinition(
        name="UK_POSTCODE",
        description="UK Postcode",
        regex=re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]? \d[A-Z]{2}\b"),
        confidence=0.75,
        severity="low",
        placeholder="{POSTCODE}",
        tier=3,
    ),
    PIIDefinition(
        name="ZIP_CODE",
        description="US ZIP code (5 or 9-digit)",
        regex=re.compile(r"\b\d{5}(?:-\d{4})?\b"),
        confidence=0.60,
        severity="low",
        placeholder="{ZIP_CODE}",
        tier=3,
    ),
    PIIDefinition(
        name="VIN",
        description="Vehicle Identification Number (17-char)",
        regex=re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
        confidence=0.70,
        severity="medium",
        placeholder="{VIN}",
        tier=3,
    ),
    PIIDefinition(
        name="DEA_NUMBER",
        description="US DEA Registration Number",
        regex=re.compile(r"\b[ABFGMPSU][A-Z]\d{7}\b"),
        confidence=0.80,
        severity="high",
        placeholder="{DEA_NUMBER}",
        validator=_validate_dea,
        tier=3,
    ),
    PIIDefinition(
        name="MEDICAL_RECORD",
        description="Medical Record Number (MRN with prefix)",
        regex=re.compile(r"\b(MRN[-:]\s*\d{5,10}|MRN\d{5,10})\b", re.IGNORECASE),
        confidence=0.80,
        severity="high",
        placeholder="{MEDICAL_RECORD}",
        tier=3,
    ),

    # ── TIER 4: Low-medium confidence, context-dependent ─────────────────
    PIIDefinition(
        name="STREET_ADDRESS",
        description="US street address (number + street name + suffix)",
        regex=re.compile(
            r"\b\d{1,5}\s+[A-Za-z0-9\s.]+"
            r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|"
            r"Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Way|Place|Pl)\b",
            re.IGNORECASE
        ),
        confidence=0.55,
        severity="medium",
        placeholder="{ADDRESS}",
        tier=4,
    ),
    PIIDefinition(
        name="USERNAME",
        description="Username (@mention or user= patterns)",
        regex=re.compile(r"(?<![@\w])@[a-zA-Z][a-zA-Z0-9_]{2,30}\b"),
        confidence=0.50,
        severity="low",
        placeholder="{USERNAME}",
        tier=4,
    ),
    PIIDefinition(
        name="COOKIE",
        description="Session cookie / auth token",
        regex=re.compile(r"(session[_-]?id|auth[_-]?token|connect[_-]?sid)=[a-zA-Z0-9%]{20,}", re.IGNORECASE),
        confidence=0.70,
        severity="high",
        placeholder="{COOKIE}",
        tier=4,
    ),
    PIIDefinition(
        name="USER_AGENT",
        description="Browser User-Agent string",
        regex=re.compile(r"Mozilla/\d\.\d \([^)]+\)(?: [A-Za-z]+/\d\.\d)*"),
        confidence=0.60,
        severity="low",
        placeholder="{USER_AGENT}",
        tier=4,
    ),
    PIIDefinition(
        name="LAT_LONG",
        description="GPS coordinates (decimal degrees)",
        regex=re.compile(r"-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}"),
        confidence=0.60,
        severity="low",
        placeholder="{LAT_LONG}",
        tier=4,
    ),
    PIIDefinition(
        name="DEVICE_ID",
        description="Device identifier (UDID / IMEI / IMSI / IDFA)",
        regex=re.compile(r"\b(?:UDID|IMEI|IMSI|IDFA)[:\s]*[a-zA-Z0-9_-]{8,40}\b", re.IGNORECASE),
        confidence=0.75,
        severity="high",
        placeholder="{DEVICE_ID}",
        tier=4,
    ),
    PIIDefinition(
        name="ICD_CODE",
        description="ICD-9 / ICD-10 diagnosis code",
        regex=re.compile(r"\b[A-TV-Z][0-9][0-9AB]\.?\d{,4}\b"),
        confidence=0.50,
        severity="low",
        placeholder="{ICD_CODE}",
        tier=4,
    ),
    PIIDefinition(
        name="DATE_OF_BIRTH",
        description="Date of birth (multiple formats with context)",
        regex=re.compile(r"\b\d{4}[-/]\d{2}[-/]\d{2}\b|\b\d{2}[-/]\d{2}[-/]\d{4}\b"),
        confidence=0.45,
        severity="medium",
        placeholder="{DOB}",
        tier=4,
    ),
    PIIDefinition(
        name="HEX_TOKEN_32",
        description="32-character hex token (Datadog API key, Twilio Auth Token)",
        regex=re.compile(r"\b[a-fA-F0-9]{32}\b"),
        confidence=0.50,
        severity="medium",
        placeholder="{HEX_TOKEN}",
        tier=4,
    ),
]

PATTERNS_BY_NAME: dict[str, PIIDefinition] = {p.name: p for p in PATTERNS}

PATTERNS_BY_TIER: dict[int, list[PIIDefinition]] = {}
for p in PATTERNS:
    PATTERNS_BY_TIER.setdefault(p.tier, []).append(p)

TIER_LABELS = {
    1: "High confidence (checksum/rigorous validation)",
    2: "Medium-high confidence (format validation)",
    3: "Medium confidence (shape-based detection)",
    4: "Low-medium confidence (context-dependent)",
}

DEFAULT_ENABLED = [p.name for p in PATTERNS if p.tier <= 2]
