# Changelog

## v0.2.0

**Breaking: none.** All existing public APIs remain backward compatible.

### New — Privacy Gateway for LLMs and AI Agents
- `PrivacyGateway` + `GatewaySession` for reversible protect → LLM → resolve workflows
- `MappingVault` — date-scoped, in-memory, thread-safe entity→token store
- `TokenGenerator` — HMAC-based deterministic opaque tokens (`<TYPE_8hex>`)
- `MappingSession` — lifecycle binding of vault + generator

### New — Policy Engine
- `Policy`, `Action`, `EntityRule`, `NumberRule`, `DateRule`
- Pre-built policies: `strict`, `enterprise`, `permissive`
- Numbers and dates preserved by default; scaling/shifting opt-in

### New — Transformations
- `NumberTransformer` — scale, range, percentile (reversible)
- `DateTransformer` — date shifting (reversible)
- `SemanticAbstracter` — semantic abstraction with user-provided metadata

### New — Secret Patterns
- Added `AZURE_OPENAI_KEY`, `PASSWORD`, `PASSWORD_JSON`, `HTTP_BASIC_AUTH`, `ENV_SECRET_VALUE`
- Extended `API_KEY` with Claude (`sk-ant-api03-`), Cohere, Hugging Face, Replicate, Groq, Fireworks, Perplexity, AWS STS prefixes
- Total patterns: 50 → 55

### Extended
- `RedactResult` now has optional `mapping`, `risk_score`, `risk_details` fields

## v0.1.4 (2026-05-23)

- History records now include `source` ("library"/"cli"/"stdin") and `file_path`
- Added `source` and `file_path` params to `detect()`, `redact()`, `mask()` public API

## v0.1.3 (2026-05-23)

- History written to both `~/.aigov-redact/history.jsonl` and `./.aigov-redact/history.jsonl`
- New `history_path` config option and library parameter for custom history location
- Fixed CLI app name still showing `prompt-sanitizer` instead of `aigov-redact`
- Fixed `.gitignore` and test fixture with old name references

## v0.1.2 (2026-05-23)

- Fixed history path still pointing to old `.prompt-sanitizer` folder instead of `.aigov-redact`

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
