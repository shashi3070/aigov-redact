from aigov_redact.mapping.session import MappingSession
from aigov_redact.mapping.token_generator import TokenGenerator
from aigov_redact.mapping.vault import MappingVault


class TestMappingVault:
    def test_register_and_resolve(self):
        vault = MappingVault()
        token = vault.register("EMAIL", "john@example.com")
        assert token.startswith("<EMAIL_")
        assert vault.resolve(token) == "john@example.com"

    def test_deterministic_same_date(self):
        vault = MappingVault()
        t1 = vault.register("EMAIL", "john@example.com")
        t2 = vault.register("EMAIL", "john@example.com")
        assert t1 == t2

    def test_different_types_different_tokens(self):
        vault = MappingVault()
        t1 = vault.register("EMAIL", "john@example.com")
        t2 = vault.register("SSN", "john@example.com")
        assert t1 != t2

    def test_session_scope_unique_tokens(self):
        v1 = MappingVault(scope="session")
        v2 = MappingVault(scope="session")
        t1 = v1.register("EMAIL", "john@example.com")
        t2 = v2.register("EMAIL", "john@example.com")
        assert t1 != t2

    def test_resolve_text(self):
        vault = MappingVault()
        t1 = vault.register("EMAIL", "john@example.com")
        t2 = vault.register("SSN", "123-45-6789")
        text = f"Email {t1} and SSN {t2}"
        resolved = vault.resolve_text(text)
        assert "john@example.com" in resolved
        assert "123-45-6789" in resolved

    def test_export_mapping(self):
        vault = MappingVault()
        vault.register("EMAIL", "john@example.com")
        vault.register("SSN", "123-45-6789")
        mapping = vault.export_mapping()
        assert len(mapping) == 2

    def test_clear(self):
        vault = MappingVault()
        vault.register("EMAIL", "john@example.com")
        assert len(vault) == 1
        vault.clear()
        assert len(vault) == 0

    def test_ttl_expiration(self):
        vault = MappingVault(ttl=1)
        token = vault.register("EMAIL", "john@example.com")
        assert vault.resolve(token) == "john@example.com"

    def test_metadata(self):
        vault = MappingVault()
        token = vault.register("EMAIL", "john@example.com", {"source": "user"})
        assert token.startswith("<EMAIL_")

    def test_number_ops(self):
        vault = MappingVault()
        vault.register_number_op(100.0, 137.0, "scale", 1.37)
        assert vault.reverse_number(137.0) == 100.0
        assert vault.reverse_number(999.0) is None

    def test_date_ops(self):
        from datetime import datetime
        vault = MappingVault()
        d1 = datetime(2026, 1, 1)
        d2 = datetime(2026, 6, 23)
        vault.register_date_op(d1, d2)
        assert vault.reverse_date(d2) == d1


class TestTokenGenerator:
    def test_deterministic(self):
        gen = TokenGenerator()
        t1 = gen.generate("EMAIL", "john@example.com")
        t2 = gen.generate("EMAIL", "john@example.com")
        assert t1 == t2

    def test_format(self):
        gen = TokenGenerator()
        token = gen.generate("EMAIL", "john@example.com")
        assert token.startswith("<EMAIL_")
        assert token.endswith(">")
        hex_part = token[len("<EMAIL_") : -1]
        assert len(hex_part) == 8
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_different_types(self):
        gen = TokenGenerator()
        t1 = gen.generate("EMAIL", "john@example.com")
        t2 = gen.generate("SSN", "john@example.com")
        assert t1 != t2

    def test_random_mode(self):
        gen = TokenGenerator()
        t1 = gen.generate("EMAIL", "john@example.com", deterministic=False)
        t2 = gen.generate("EMAIL", "john@example.com", deterministic=False)
        assert t1 != t2

    def test_custom_date_scope(self):
        gen = TokenGenerator()
        t1 = gen.generate("EMAIL", "john@example.com", date_scope="2026-01-01")
        t2 = gen.generate("EMAIL", "john@example.com", date_scope="2026-12-31")
        assert t1 != t2


class TestMappingSession:
    def test_get_token(self):
        session = MappingSession()
        token = session.get_token("EMAIL", "john@example.com")
        assert token.startswith("<EMAIL_")

    def test_resolve(self):
        session = MappingSession()
        token = session.get_token("EMAIL", "john@example.com")
        assert session.resolve(token) == "john@example.com"

    def test_resolve_text(self):
        session = MappingSession()
        t1 = session.get_token("EMAIL", "john@example.com")
        t2 = session.get_token("SSN", "123-45-6789")
        text = f"Email {t1} and SSN {t2}"
        resolved = session.resolve_text(text)
        assert "john@example.com" in resolved
        assert "123-45-6789" in resolved

    def test_export(self):
        session = MappingSession()
        session.get_token("EMAIL", "john@example.com")
        mapping = session.export()
        assert len(mapping) == 1

    def test_clear(self):
        session = MappingSession()
        session.get_token("EMAIL", "john@example.com")
        session.clear()
        assert len(session.export()) == 0
