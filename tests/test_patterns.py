from __future__ import annotations

import pytest

from aigov_redact.patterns import PATTERNS, PATTERNS_BY_NAME


class TestPatternsCount:
    def test_50_patterns(self):
        assert len(PATTERNS) == 50

    def test_all_have_names(self):
        for p in PATTERNS:
            assert p.name, f"Pattern missing name: {p}"

    def test_all_have_placeholders(self):
        for p in PATTERNS:
            msg = f"{p.name} bad placeholder: {p.placeholder}"
            assert p.placeholder.startswith("{") and p.placeholder.endswith("}"), msg

    def test_unique_names(self):
        names = [p.name for p in PATTERNS]
        assert len(names) == len(set(names))


class TestEmail:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["EMAIL"]

    @pytest.mark.parametrize("value", [
        "john@gmail.com",
        "jane.doe@company.co.uk",
        "user+tag@domain.org",
        "test@sub.domain.com",
        "a.b@c.co",
    ])
    def test_valid(self, value):
        assert self.p.regex.fullmatch(value), f"Should match: {value}"

    @pytest.mark.parametrize("value", [
        "notanemail",
        "@domain.com",
        "user@@domain.com",
        "plainaddress",
        "",
    ])
    def test_invalid(self, value):
        assert not self.p.regex.fullmatch(value), f"Should NOT match: {value}"


class TestSSN:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["SSN"]

    @pytest.mark.parametrize("value", [
        "123-45-6789",
        "987-65-4320",
        "111-22-3333",
    ])
    def test_format(self, value):
        assert self.p.regex.search(value)

    def test_validate_valid(self):
        assert self.p.validator("123-45-6789")

    def test_validate_invalid_area_000(self):
        assert not self.p.validator("000-45-6789")

    def test_validate_invalid_area_666(self):
        assert not self.p.validator("666-45-6789")

    def test_validate_invalid_area_900(self):
        assert not self.p.validator("900-45-6789")

    def test_validate_zero_group(self):
        assert not self.p.validator("123-00-6789")

    def test_validate_zero_serial(self):
        assert not self.p.validator("123-45-0000")


class TestCreditCard:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["CREDIT_CARD"]

    @pytest.mark.parametrize("value", [
        "4111111111111111",
        "4111-1111-1111-1111",
        "5500 0000 0000 0004",
    ])
    def test_valid_luhn(self, value):
        cleaned = value.replace("-", "").replace(" ", "")
        assert self.p.validator(cleaned)

    @pytest.mark.parametrize("value", [
        "1234567890123456",
        "0000000000000000",
        "1111111111111111",
    ])
    def test_invalid_luhn(self, value):
        assert not self.p.validator(value)


class TestIPV4:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["IPV4"]

    def test_valid(self):
        assert self.p.regex.search("connect to 192.168.1.1 now")
        assert self.p.validator("192.168.1.1")

    def test_invalid_octet(self):
        assert not self.p.validator("256.1.2.3")

    def test_invalid_format(self):
        assert not self.p.validator("192.168.1")


class TestPhoneUS:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["PHONE_US"]

    def test_valid_formats(self):
        assert self.p.regex.search("call 555-123-4567")
        assert self.p.regex.search("call (555) 123-4567")
        assert self.p.regex.search("call 555.123.4567")

    def test_validate_valid(self):
        assert self.p.validator("5552345678")

    def test_invalid_area_100(self):
        assert not self.p.validator("1001234567")

    def test_invalid_exchange_100(self):
        assert not self.p.validator("5551001234")


class TestAPIKey:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["API_KEY"]

    def test_openai(self):
        assert self.p.regex.search("key is sk-123456789012345678901234567890")

    def test_github(self):
        assert self.p.regex.search("ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd")

    def test_aws(self):
        assert self.p.regex.search("AKIA0123456789ABCDEF")


class TestIBAN:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["IBAN"]

    def test_valid_iban(self):
        assert self.p.validator("DE89370400440532013000")

    def test_invalid_iban(self):
        assert not self.p.validator("DE89370400440532013001")


class TestJWT:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["JWT_TOKEN"]

    def test_valid_jwt(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqPndCYtR8M_xL1IyAqiXBn2QP0"
        assert self.p.regex.search(token)
        assert self.p.validator(token)


class TestUKNINO:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["UK_NINO"]

    def test_valid(self):
        assert self.p.validator("AB123456C")

    def test_invalid_prefix(self):
        assert not self.p.validator("GB123456C")


class TestCryptoWallet:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["CRYPTO_WALLET"]

    def test_bitcoin(self):
        assert self.p.regex.search("btc: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

    def test_ethereum(self):
        assert self.p.regex.search("eth: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e")


class TestDEANumber:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["DEA_NUMBER"]

    def test_valid_dea(self):
        assert self.p.validator("AB1234563")

    def test_invalid_dea(self):
        assert not self.p.validator("ZZ1234567")


class TestPrivateKey:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["PRIVATE_KEY"]

    def test_rsa_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        assert self.p.regex.search(text)


class TestAWSSecretKey:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["AWS_SECRET_KEY"]

    def test_valid(self):
        assert self.p.regex.search("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    def test_invalid_too_short(self):
        assert not self.p.regex.search("shortkey123")

    def test_invalid_with_dash(self):
        assert not self.p.regex.search("abc-def-ghi-jkl-mno-pqr-stu-vwx-yz0")


class TestHexToken32:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["HEX_TOKEN_32"]

    def test_valid_hex_token(self):
        assert self.p.regex.search("a1b2c3d4e5f6789012345678abcdef01")

    def test_invalid_too_short(self):
        assert not self.p.regex.search("a1b2c3d4e5f6")

    def test_invalid_with_gz_chars(self):
        assert not self.p.regex.search("a1b2c3d4e5f67890g12345678hijk01")


class TestTelegramBotToken:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["TELEGRAM_BOT_TOKEN"]

    def test_valid(self):
        assert self.p.regex.search("1234567890:A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R")

    def test_invalid_short_numeric(self):
        assert not self.p.regex.search("123456:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r")

    def test_invalid_no_colon(self):
        assert not self.p.regex.search("1234567890A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R")


class TestDiscordBotToken:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["DISCORD_BOT_TOKEN"]

    def test_valid(self):
        assert self.p.regex.search("MTAxMjM0NTY3ODkwMTIzNDU2.G1A2B3.placeholder_discord_token_for_testing_only")

    def test_invalid_too_short(self):
        assert not self.p.regex.search("abc123.def456.ghi789")

    def test_invalid_two_parts(self):
        assert not self.p.regex.search("abc123.def456")


class TestHashicorpTfToken:
    def setup_method(self):
        self.p = PATTERNS_BY_NAME["HASHICORP_TF_TOKEN"]

    def test_valid(self):
        tok = ("1a2b3c4d5e6f7g8h.atlasv1."
               "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a1b2c3d4e5f")
        assert self.p.regex.search(tok)

    def test_invalid_no_atlasv1(self):
        assert not self.p.regex.search("1a2b3c4d5e6f7g8h.other.1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p")

    def test_invalid_short_first_part(self):
        assert not self.p.regex.search("short.atlasv1.1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a1b2c3d4e5f")


class TestTierClassification:
    def test_tier_1_count(self):
        tier1 = [p for p in PATTERNS if p.tier == 1]
        assert len(tier1) == 12, f"Expected 12 Tier 1 patterns, got {len(tier1)}"

    def test_tier_2_count(self):
        tier2 = [p for p in PATTERNS if p.tier == 2]
        assert len(tier2) == 12, f"Expected 12 Tier 2 patterns, got {len(tier2)}"

    def test_tier_3_count(self):
        tier3 = [p for p in PATTERNS if p.tier == 3]
        assert len(tier3) == 17, f"Expected 17 Tier 3 patterns, got {len(tier3)}"

    def test_tier_4_count(self):
        tier4 = [p for p in PATTERNS if p.tier == 4]
        assert len(tier4) == 9, f"Expected 9 Tier 4 patterns, got {len(tier4)}"
