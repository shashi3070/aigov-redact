# Changelog

## v0.1.1 (2026-05-23)

- Updated README with corrected project name references and normalized comment markers

## v0.1.0 (2026-05-23)

- Renamed project to prompt-sanitizer
- Initial release
- 50 built-in PII patterns across 4 confidence tiers
- Library API: `redact()`, `detect()`, `mask()`
- 4 redaction modes: replace, mask, hash, remove
- 3 CLI commands: `check`, `redact`, `audit`
- Config file support (`.aigov-redact-config` JSON/YAML)
- Compliance profiles (HIPAA, PCI DSS, GDPR presets)
- Usage history auto-logged to `~/.aigov-redact/history.jsonl`
- `history` CLI command for aggregated stats
- Optional Presidio NER for names/organizations/locations
- CSV audit logging with timestamp, file, line, type, hash
- Stdin piping for all commands
- Overlap resolution and confidence-based entity merging
- Custom pattern injection via config
- Allowlist and exclusion patterns
- Luhn, MOD-97, MOD-11, weighted sum check digit validation
