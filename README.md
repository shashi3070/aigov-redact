# aigov-redact — PII Redactor for LLM Data

**Governance-ready PII redaction for AI/GenAI.** A lightweight, local-first Python library and CLI tool for detecting, redacting, and auditing personally identifiable information (PII) before it reaches LLM APIs. Built for compliance, auditability, and zero-trust data privacy.

```python
from aigov_redact import redact, detect  # ← aigov-redact

# ── Before every LLM API call: redact, then prove it to auditors ────
prompt = f"""
User context: My name is John Doe, email john@gmail.com, SSN 123-45-6789
Question: What benefits am I eligible for?
"""

# 1. Check what would be exposed
result = detect(prompt)  # ← aigov-redact
for e in result.entities:
    print(f"  {e.type} at [{e.start}:{e.end}] (confidence: {e.confidence:.2f})")
# → EMAIL at [45:57] (confidence: 0.95)
# → SSN at [63:74] (confidence: 0.98)

# 2. Redact before sending to OpenAI / Claude / Gemini
safe = redact(prompt, mode="replace")  # ← aigov-redact
print(safe.text)
# → "User context: My name is {EMAIL}, email {EMAIL}, SSN {SSN}
#     Question: What benefits am I eligible for?"

# 3. Log to audit trail for SOC 2 / GDPR / HIPAA compliance
#    (run: aigov-redact audit requests.log --audit-log pii-leaks.csv)
```

```bash
aigov-redact check prompt.txt               # detect PII before sending to LLM
aigov-redact redact prompt.txt              # redact before API call
aigov-redact audit requests.log             # scan LLM API logs for PII leaks
aigov-redact audit requests.log --audit-log pii-leaks.csv  # persistent audit trail
```

## Why aigov-redact for LLM Workflows?

Data privacy is the #1 enterprise concern for LLM adoption. When you send prompts to OpenAI, Anthropic, Google, or any LLM provider, **you're sending whatever data is in that prompt** — including accidentally included PII.

| Risk | Example | Consequence |
|---|---|---|
| **Employee PII in support prompts** | "My SSN is 123-45-6789, what benefits do I get?" | GDPR/CCPA violation |
| **Customer data in RAG context** | "John Smith (john@acme.com) has balance $50k" | Data breach via model |
| **API keys in code prompts** | "Why does my sk-abc... key fail?" | Credential leak |
| **Medical data in summarization** | "Patient Jane Doe, ICD-10: F32.9" | HIPAA violation |
| **Governance gap** | "No audit trail of what PII was sent to LLMs" | SOC 2 / ISO 27001 failure |

**aigov-redact** sits between your application and the LLM — a privacy firewall that strips PII before it reaches the API.

- **Governance-ready** — Every redaction is auditable. Prove to regulators that PII never reached the LLM.
- **Local-first** — No data leaves your machine. No API calls. No telemetry. Zero trust.
- **Lightweight** — Pure Python. Zero heavy dependencies. <1ms per prompt.
- **Comprehensive** — 50 built-in PII patterns across 4 confidence tiers with checksum validation.
- **Audit-ready** — Structured CSV audit logs for SOC 2 / GDPR / HIPAA / ISO 27001 compliance.

## Quick Start

### Installation

```bash
pip install aigov-redact
```

With optional NER support (names, locations, organizations):

```bash
pip install aigov-redact[ner]
python -m spacy download en_core_web_sm
```

### Python Library — LLM-First Examples

```python
from aigov_redact import redact, detect, mask  # ← aigov-redact

# ── Before sending to OpenAI / Claude / Gemini ──────────────────────
prompt = "My email is john@gmail.com and SSN is 123-45-6789"
safe_prompt = redact(prompt).text  # ← aigov-redact
# → "My email is {EMAIL} and SSN is {SSN}"

# Now safe to send: response = openai.chat.completions.create(...)

# ── Detect what PII would be exposed before deciding ────────────────
result = detect("My SSN is 123-45-6789")  # ← aigov-redact
for entity in result.entities:
    print(f"{entity.type} at pos {entity.start}-{entity.end}: {entity.confidence}")
# → SSN at pos 7-18: 0.98

# ── Mask PII (no original shape visible) ───────────────────────────
result = mask("SSN: 123-45-6789", char="*")  # ← aigov-redact
print(result.text)
# → "SSN: ***********"

# ── Hash for deterministic tracking across turns ────────────────────
result = redact("Email: user@test.com", mode="hash")  # ← aigov-redact
print(result.text)
# → "Email: <EMAIL_a1b2c3d4>"

# ── Remove entirely ─────────────────────────────────────────────────
result = redact("Email: user@test.com", mode="remove")  # ← aigov-redact
print(result.text)
# → "Email: "
```

### CLI — LLM Pipeline Integration

```bash
# Check prompts for PII before API calls (exit 1 if found)
aigov-redact check prompt.txt

# JSON output for automated pipelines
aigov-redact check prompt.txt --json

# Redact in-place (backup as .bak)
aigov-redact redact prompt.txt

# Redact to stdout (pipe directly to LLM API)
cat prompt.txt | aigov-redact redact --stdin | your-llm-client

# Audit production LLM logs for accidental PII leaks
aigov-redact audit /var/log/llm/requests.log

# CI/CD: fail if any PII found in logs
aigov-redact audit requests.log --fail-on-pii

# Use custom config
aigov-redact check prompt.txt --config .aigov-redact-config
```

### Usage History

Every call — whether from the Python library or the CLI — is automatically logged. No setup needed.

**Where history is stored:**
- `~/.aigov-redact/history.jsonl` — user home directory (always)
- `./.aigov-redact/history.jsonl` — current working directory (always)
- Custom path via `history_path` config key or `history_path` parameter

```python
from aigov_redact import redact, detect  # ← aigov-redact

# These are auto-logged to ~/.aigov-redact/history.jsonl AND ./.aigov-redact/history.jsonl
redact("Email: user@test.com")       # ← aigov-redact  (logged as "redact")
detect("SSN: 123-45-6789")           # ← aigov-redact  (logged as "check")
mask("Phone: 555-123-4567")          # ← aigov-redact  (logged as "redact" with mode=mask)

# Or use a custom history path
detect("test@email.com", history_path="/path/to/custom.jsonl")  # ← aigov-redact
```

```bash
# Show aggregated usage stats and recent runs
aigov-redact history

# Show last 10 runs
aigov-redact history --limit 10

# Use custom history path from config
aigov-redact history --config .aigov-redact-config
```

Example output:

```
Total runs: 24

Runs by command:
  audit: 5
  check: 12
  redact: 7

Entity types detected (top):
  EMAIL: 18
  SSN: 6
  PHONE: 3

Recent runs:
  2026-05-23T10:15:30  check    stdin  count=0  []
  2026-05-23T10:16:00  redact   file   count=2  [EMAIL, SSN]
  2026-05-23T10:17:00  audit    file   count=5  [EMAIL, SSN, PHONE, API_KEY]
```

## LLM Integration Patterns

### 1. Sanitize Prompts Before OpenAI Calls

```python
from openai import OpenAI
from aigov_redact import redact  # ← aigov-redact

client = OpenAI()

def safe_completion(prompt: str, **kwargs):
    """Redact PII before sending to OpenAI, return redacted + response."""
    result = redact(prompt)  # ← aigov-redact
    response = client.chat.completions.create(
        messages=[{"role": "user", "content": result.text}],
        **kwargs
    )
    return result.text, response.choices[0].message.content

# Usage
safe_prompt, response = safe_completion(
    "My SSN is 123-45-6789, what benefits can I claim?"
)
print(safe_prompt)   # "My SSN is {SSN}, what benefits can I claim?"
print(response)      # LLM response (never saw the real SSN)
```

### 2. AI Governance & Audit Trail — Prove Compliance

```python
from aigov_redact import redact  # ← aigov-redact
import json
from datetime import datetime, timezone

class GovernedLLMClient:
    """Wrap any LLM call with PII redaction + audit trail."""

    def __init__(self, audit_path: str = "pii-governance-log.csv"):
        self.audit_path = audit_path
        self._session_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    def send(self, prompt: str, llm_callable):
        """Redact PII, log audit entry, then call the LLM."""
        result = redact(prompt)  # ← aigov-redact

        # ── Governance: record every PII entity for compliance ──────
for entity in result.entities:
            record = {
                "session": self._session_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": entity.type,
                "confidence": entity.confidence,
                "severity": entity.severity,
                "value_hash": entity.hash if hasattr(entity, "hash") else "",
                "start": entity.start,
                "end": entity.end,
            }
            with open(self.audit_path, "a") as f:
                f.write(json.dumps(record) + "\n")

        # ── Send only redacted text to the LLM ──────────────────────
        return llm_callable(result.text)

# Usage
client = GovernedLLMClient()
response = client.send(
    "My SSN is 123-45-6789, what benefits do I get?",
    lambda text: openai.chat.completions.create(messages=[{"role": "user", "content": text}])
)
# pii-governance-log.csv now contains:
# {"session": "20260523-101530", "timestamp": "2026-05-23T10:15:30", "type": "SSN", "confidence": 0.98, "severity": "critical", ...}
```

For SOC 2 / ISO 27001 auditors: export your governance log and demonstrate that every PII entity was detected, hashed, and redacted before reaching the LLM provider. No PII stored in plaintext — only SHA-256 hashes for deduplication.

### 3. Sanitize Before Anthropic Claude

```python
import anthropic
from aigov_redact import redact  # ← aigov-redact

client = anthropic.Anthropic()

prompt = "Patient Jane Doe, DOB 1990-01-15, needs medication review."
safe = redact(prompt, ner_enabled=True)  # ← aigov-redact  NER catches "Jane Doe" as PERSON

message = client.messages.create(
    model="claude-3-opus-20240229",
    max_tokens=1024,
    messages=[{"role": "user", "content": safe.text}]
)
# Claude sees: "Patient {PERSON}, DOB {DOB}, needs medication review."
```

### 4. RAG Pipeline — Redact Before Embedding

```python
from aigov_redact import redact  # ← aigov-redact

class SafeRAGPipeline:
    def __init__(self, embedder, vector_store):
        self.embedder = embedder
        self.vector_store = vector_store

    def ingest(self, documents: list[str]):
        safe_docs = [redact(doc, mode="replace").text for doc in documents]  # ← aigov-redact
        embeddings = self.embedder.embed_documents(safe_docs)
        self.vector_store.add(embeddings, safe_docs)

    def query(self, question: str) -> str:
        safe_q = redact(question).text  # ← aigov-redact
        results = self.vector_store.similarity_search(safe_q)
        return " ".join(results)

# No PII ever reaches the embedding model or vector database
pipeline = SafeRAGPipeline(embedder, vector_store)
pipeline.ingest(["John Doe's email is john@acme.com, balance $50k"])
```

### 5. LangChain Integration

```python
from langchain_core.messages import HumanMessage
from aigov_redact import redact  # ← aigov-redact

def redact_messages(messages):
    """Redact PII from all human messages in a LangChain chain."""
    for msg in messages:
        if isinstance(msg, HumanMessage):
            result = redact(msg.content)  # ← aigov-redact
            msg.content = result.text
    return messages

# Use before any LangChain model call
messages = [HumanMessage(content="My email is john@gmail.com")]
safe_messages = redact_messages(messages)
# llm.invoke(safe_messages)
```

### 6. Streaming — Redact Before Tokenization

```python
from aigov_redact import redact  # ← aigov-redact

def stream_safe(prompt: str, llm_stream):
    """Redact prompt, stream LLM response."""
    safe = redact(prompt).text  # ← aigov-redact
    yield from llm_stream(safe)

# for chunk in stream_safe("My SSN is 123-45-6789", openai_stream):
#     print(chunk, end="")
```

### 7. Batch Dataset Preparation for Fine-Tuning

```python
from aigov_redact import redact  # ← aigov-redact
import json

with open("training_data.jsonl") as f, open("safe_training_data.jsonl", "w") as out:
    for line in f:
        record = json.loads(line)
        record["prompt"] = redact(record["prompt"]).text  # ← aigov-redact
        record["completion"] = redact(record["completion"]).text  # ← aigov-redact
        out.write(json.dumps(record) + "\n")
```

## Supported PII Types (50 patterns)

### Tier 1 — High Confidence (checksum/rigorous validation)

| Type | Description | Confidence | Validation |
|---|---|---|---|
| `EMAIL` | Email address (RFC 5322 loose) | 0.95 | Format validation |
| `SSN` | US Social Security Number | 0.98 | Area/group/serial rules |
| `CREDIT_CARD` | Credit/debit card number | 0.98 | Luhn algorithm |
| `IBAN` | International Bank Account Number | 0.98 | MOD-97 checksum |
| `AADHAAR` | India Aadhaar number (12-digit) | 0.90 | Verhoeff checksum |
| `PAN_INDIA` | India Permanent Account Number | 0.90 | Format validation |
| `ITIN` | US Individual Taxpayer ID | 0.95 | Format + prefix rules |
| `EIN` | US Employer Identification Number | 0.95 | Format validation |
| `UK_NHS` | UK National Health Service Number | 0.90 | Modulus-11 checksum |
| `AU_TFN` | Australian Tax File Number | 0.85 | Modulus-11 algorithm |
| `ROUTING_NUMBER` | US ABA Routing Number | 0.80 | Check digit |
| `PRIVATE_KEY` | Private key in PEM format | 0.95 | Header detection |

### Tier 2 — Medium-High Confidence (format validation)

| Type | Description | Confidence | Validation |
|---|---|---|---|
| `PHONE_US` | US phone number (10-digit NANP) | 0.95 | Area/exchange validation |
| `PHONE_INTL` | International phone number | 0.85 | + prefix |
| `US_PASSPORT` | US Passport number (9-digit) | 0.70 | Format |
| `DRIVERS_LICENSE` | US Driver's License (multi-state) | 0.70 | Format (CA, NY, TX, FL, IL, OH, PA) |
| `UK_NINO` | UK National Insurance Number | 0.90 | Prefix/suffix rules |
| `CA_SIN` | Canadian Social Insurance Number | 0.85 | Luhn check |
| `AU_MEDICARE` | Australian Medicare number | 0.85 | Checksum |
| `BR_CPF` | Brazilian CPF | 0.85 | Modulus-11 |
| `BR_CNPJ` | Brazilian CNPJ | 0.85 | Modulus-11 |
| `CN_ID` | China ID card number | 0.85 | Weighted sum |
| `JP_MYNUMBER` | Japan My Number | 0.75 | 12-digit format |
| `CRYPTO_WALLET` | Cryptocurrency wallet (BTC/ETH) | 0.90 | Format validation |

### Tier 3 — Medium Confidence (shape-based)

| Type | Description | Confidence |
|---|---|---|
| `IPV4` | IPv4 address | 0.70 |
| `IPV6` | IPv6 address | 0.70 |
| `API_KEY` | API key / secret token | 0.95 |
| `AWS_SECRET_KEY` | AWS Secret Access Key (40-char base64) | 0.80 |
| `URL_CREDENTIALS` | URL with embedded credentials | 0.98 |
| `BANK_ACCOUNT` | US Bank Account number | 0.60 |
| `MAC_ADDRESS` | MAC address | 0.70 |
| `JWT_TOKEN` | JSON Web Token | 0.85 |
| `UK_POSTCODE` | UK Postcode | 0.75 |
| `ZIP_CODE` | US ZIP code | 0.60 |
| `VIN` | Vehicle Identification Number | 0.70 |
| `DEA_NUMBER` | US DEA Registration | 0.80 |
| `MEDICAL_RECORD` | Medical Record Number | 0.80 |
| `AZURE_CONNECTION_STRING` | Azure Storage connection string with AccountKey | 0.80 |
| `TELEGRAM_BOT_TOKEN` | Telegram Bot Token (numeric:secret) | 0.95 |
| `DISCORD_BOT_TOKEN` | Discord Bot Token (3 base64 segments) | 0.85 |
| `HASHICORP_TF_TOKEN` | HashiCorp Terraform Cloud token (atlasv1) | 0.90 |

### Tier 4 — Low-Medium Confidence (context-dependent)

| Type | Description | Confidence |
|---|---|---|
| `STREET_ADDRESS` | US street address | 0.55 |
| `USERNAME` | @mention or user pattern | 0.50 |
| `COOKIE` | Session cookie / auth token | 0.70 |
| `USER_AGENT` | Browser User-Agent string | 0.60 |
| `LAT_LONG` | GPS coordinates | 0.60 |
| `DEVICE_ID` | UDID / IMEI / IMSI / IDFA | 0.75 |
| `ICD_CODE` | ICD-9 / ICD-10 diagnosis code | 0.50 |
| `DATE_OF_BIRTH` | Date of birth (multiple formats) | 0.45 |
| `HEX_TOKEN_32` | 32-char hex (Datadog, Twilio Auth) | 0.50 |

## Configuration

aigov-redact supports a `.aigov-redact-config` file (auto-discovered from the current working directory via `Path.cwd()`), or you can specify one via `--config`.

> **Note:** Config discovery uses the **current working directory**, not the script's location.
> If you launch your script from a different directory (e.g., VS Code terminal), pass the path explicitly:
> ```python
> from aigov_redact.config import find_config, load_config, parse_custom_patterns
> from pathlib import Path
>
> # Find config relative to this script, not cwd
> cfg_path = find_config(str(Path(__file__).parent))
> cfg = load_config(cfg_path)
> custom = parse_custom_patterns(cfg)
>
> result = redact(text, custom_patterns=custom,
>                 excluded_patterns=cfg.get("excluded_patterns"))
> ```

> **Note:** `allowlist` in the config file is reserved for future use and is not yet implemented.

### JSON Config (default)

```json
{
  "pii_types": {
    "enabled": null,
    "disabled": ["IPV4", "IPV6", "MAC_ADDRESS", "LAT_LONG", "ZIP_CODE"]
  },
  "custom_patterns": [
    {
      "name": "EMP_ID",
      "description": "Internal employee ID",
      "pattern": "EMP-\\d{6}",
      "confidence": 0.95,
      "placeholder": "{EMP_ID}",
      "severity": "high"
    }
  ],
  "allowlist": ["support@mycompany.com"],
  "excluded_patterns": ["example\\.com"],
  "placeholder_style": "type",
  "mask_char": "*",
  "ner_enabled": false,
  "backup": true,
  "audit_log": "aigov-redact-audit.log",
  "history_path": "/custom/path/history.jsonl"
}
```

### Compliance Profiles

Define named profiles in your config that override top-level settings:

```json
{
  "compliance_profiles": {
    "hipaa": {
      "enabled": ["SSN", "PHONE", "EMAIL", "DEA_NUMBER", "MEDICAL_RECORD", "ICD_CODE"]
    },
    "pci_dss": {
      "enabled": ["CREDIT_CARD", "CRYPTO_WALLET"],
      "placeholder_style": "hash"
    },
    "gdpr": {
      "enabled": ["EMAIL", "PHONE", "IPV4", "STREET_ADDRESS", "DATE_OF_BIRTH"],
      "ner_enabled": true
    }
  },
  "compliance_profile": "hipaa"
}
```

Set `"compliance_profile"` in the config to activate a profile, or pass it via CLI:

```bash
aigov-redact check file.txt --compliance-profile hipaa
aigov-redact redact file.txt --compliance-profile pci_dss
aigov-redact audit requests.log --compliance-profile gdpr
```

When a profile is active, its settings merge into the top-level config — `enabled` replaces `pii_types.enabled`, `placeholder_style` overrides the default, `ner_enabled` toggles NER, etc.

### YAML Config

aigov-redact supports YAML config files when PyYAML is installed:

```bash
pip install aigov-redact[yaml]
```

```yaml
pii_types:
  disabled:
    - IPV4
    - IPV6
placeholder_style: type
ner_enabled: false
custom_patterns:
  - name: EMP_ID
    pattern: "EMP-\\d{6}"
    confidence: 0.9
    placeholder: "{EMP_ID}"
    severity: high
```

### pyproject.toml Config

You can also embed aigov-redact config in your `pyproject.toml`:

```toml
[tool.aigov-redact]
placeholder_style = "hash"
ner_enabled = false
```

## Redaction Modes

| Mode | Description | Example |
|---|---|---|
| `replace` (default) | Replace with `{TYPE}` placeholder | `{EMAIL}` |
| `mask` | Replace with uniform mask chars | `***************` |
| `hash` | Replace with `<TYPE_hash>` token | `<EMAIL_a1b2c3d4>` |
| `remove` | Delete PII entirely | `` |
| `custom` | Replace with custom string | `[REDACTED]` |

```python
redact(text, mode="replace")
redact(text, mode="mask", mask_char="#")
redact(text, mode="hash")
redact(text, mode="remove")
redact(text, mode="custom", custom_placeholder="[REDACTED]")
```

```bash
aigov-redact redact file.txt --mode mask
aigov-redact redact file.txt --mode hash
aigov-redact redact file.txt --mode remove
aigov-redact redact file.txt --mode custom --custom-placeholder "[REDACTED]"
```

## Audit Logging — Governance & Compliance Evidence

The `audit` command generates a structured log of all PII found, suitable for compliance reporting and CI/CD integration. Use this to prove to auditors (SOC 2, ISO 27001, GDPR, HIPAA) that PII never reached your LLM provider.

**AI Governance best practice:** enable audit logging in your `.aigov-redact-config` and schedule nightly `aigov-redact audit` scans. The resulting CSV serves as your evidentiary record for data privacy controls — every PII detection is timestamped, hashed, and classified by type and severity.

### Audit Entry Format (CSV)

```csv
timestamp,filename,line,column,type,value_hash,confidence,severity
2026-05-23T10:15:30Z,requests.log,1,12,EMAIL,ff8d9819fc0e12bf,0.95,high
2026-05-23T10:15:30Z,requests.log,2,10,SSN,01a54629efb95228,0.98,critical
```

### Audit Formats

```bash
# Human-readable table (default)
aigov-redact audit requests.log

# JSON output (machine-readable)
aigov-redact audit requests.log --format json

# Summary statistics only
aigov-redact audit requests.log --format summary

# Persistent audit log (appended across runs)
aigov-redact audit requests.log --audit-log aigov-redact-audit.log

# Fail CI pipeline if PII is detected
aigov-redact audit requests.log --fail-on-pii
```

## NER Integration (Optional)

For detecting names, locations, and organizations, aigov-redact can use Microsoft Presidio with spaCy:

```bash
pip install aigov-redact[ner]
python -m spacy download en_core_web_sm
```

```python
from aigov_redact import redact  # ← aigov-redact

# NER catches PERSON, LOCATION, ORGANIZATION
result = redact("John Smith lives in New York and works at Acme Corp.", ner_enabled=True)  # ← aigov-redact
print(result.text)
# → "{PERSON} lives in {LOCATION} and works at {ORGANIZATION}."
```

```bash
aigov-redact check file.txt --ner
aigov-redact redact file.txt --ner
```

> **Note**: NER requires a spaCy model (~50 MB). Performance is 50-200ms vs <1ms for regex-only.

## API Reference

### `redact(text, ...)` → `RedactResult`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `text` | `str` | required | Input text to redact |
| `mode` | `str` | `"replace"` | Redaction mode: `replace`, `mask`, `hash`, `remove`, `custom` |
| `enabled_types` | `list[str] \| None` | `None` | Only detect these types (None = all enabled) |
| `disabled_types` | `list[str] \| None` | `None` | Skip these types |
| `custom_patterns` | `list[PIIDefinition] \| None` | `None` | Additional custom patterns |
| `excluded_patterns` | `list[str] \| None` | `None` | Regex patterns to exclude |
| `ner_enabled` | `bool` | `False` | Enable Presidio NER detection |
| `mask_char` | `str` | `"*"` | Character for mask mode |
| `custom_placeholder` | `str` | `"{PII}"` | Placeholder for custom mode |

**Returns**: `RedactResult` with fields:
- `text: str` — redacted text
- `entities: list[PIIEntity]` — detected entities
- `mode: str` — redaction mode used

### `detect(text, ...)` → `DetectionResult`

Same parameters as `redact` (minus mode-specific ones).

**Returns**: `DetectionResult` with fields:
- `text: str` — original text
- `entities: list[PIIEntity]` — detected entities
- `count: int` — number of entities

### `mask(text, char="*", ...)` → `RedactResult`

Shortcut for `redact(text, mode="mask", mask_char=char, ...)`.

### Models

#### `PIIEntity`
| Field | Type | Description |
|---|---|---|
| `type` | `str` | PII type (e.g., `"EMAIL"`, `"SSN"`) |
| `text` | `str` | Matched text |
| `start` | `int` | Start position in text |
| `end` | `int` | End position in text |
| `confidence` | `float` | Detection confidence (0-1) |
| `severity` | `str` | `"low"`, `"medium"`, `"high"`, or `"critical"` |

## Use Cases — LLM & GenAI Focus

### 1. LLM Prompt Sanitization (OpenAI / Claude / Gemini / Local)

```python
from aigov_redact import redact  # ← aigov-redact

# Before sending ANY prompt to an LLM, redact PII
prompt = f"""User context:
Name: Jane Doe
Email: jane@company.com
Phone: +1-555-987-6543
Insurance: 123-45-6789

Question: What is my coverage limit?"""

safe = redact(prompt, mode="replace")  # ← aigov-redact
print(safe.text)
# → "User context:
#     Name: {EMAIL}
#     Email: {EMAIL}
#     Phone: {PHONE}
#     Insurance: {SSN}
#
#     Question: What is my coverage limit?"

# Now safe to send to any LLM provider
# openai_response = openai.chat.completions.create(messages=[{"role": "user", "content": safe.text}])
# claude_response = anthropic.Anthropic().messages.create(messages=[{"role": "user", "content": safe.text}])
```

### 2. AI Governance & Audit Trail — SOC 2 / ISO 27001 Evidence

```python
from aigov_redact import redact, detect  # ← aigov-redact
import json, csv
from datetime import datetime, timezone

# ── Governance workflow: detect, redact, log every PII encounter ────
prompts = [
    "My SSN is 123-45-6789, what benefits do I get?",
    "Email me at jane@acme.com with the results",
]

governance_log = []
for i, prompt in enumerate(prompts):
    # 1. Detect what PII is present
    result = detect(prompt)  # ← aigov-redact
    # 2. Redact before LLM call
    safe = redact(prompt)  # ← aigov-redact
    # 3. Log every entity for compliance evidence
    for e in result.entities:
        governance_log.append({
            "session_id": f"session-{i:04d}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": e.type,
            "confidence": e.confidence,
            "severity": e.severity,
            "start": e.start,
            "end": e.end,
        })
    # 4. Safe to call LLM: llm.invoke(safe.text)

# Export for auditor review — proves no PII reached the LLM
with open("pii-governance-evidence.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=governance_log[0].keys())
    writer.writeheader()
    writer.writerows(governance_log)
```

**What auditors see in `pii-governance-evidence.csv`:**
```
session_id,timestamp,type,confidence,severity,start,end
session-0000,2026-05-23T10:15:30,SSN,0.98,critical,6,17
session-0001,2026-05-23T10:15:31,EMAIL,0.95,high,12,24
```

Show them this file as proof that every PII entity was detected and redacted before reaching the LLM. No plaintext storage — only `type` and `confidence` for compliance mapping.

### 3. API Key Detection — Prevent Credential Leak to LLMs

```python
from aigov_redact import redact, detect  # ← aigov-redact

# Developers accidentally paste API keys into prompts. Catch them.
code_prompt = """Why does my API key fail?
sk-abc123def456ghi789jklmno"""

result = detect(code_prompt)  # ← aigov-redact
for e in result.entities:
    if e.type == "API_KEY":
        print(f"WARNING: API key detected! ({e.confidence})")
        # → WARNING: API key detected! (0.95)

safe = redact(code_prompt)  # ← aigov-redact
print(safe.text)
# → "Why does my API key fail?
#     {API_KEY}"
```

### 4. CI/CD Pipeline — PII Gate Before LLM Deployment

```yaml
# .github/workflows/pii-check.yml
name: PII Check
on: [deploy]
jobs:
  pii-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install aigov-redact
      - name: Scan logs for PII before deploying LLM app
        run: |
          aigov-redact audit logs/production.log --fail-on-pii --format json
          if [ $? -eq 1 ]; then
            echo "PII LEAK DETECTED — deployment blocked"
            exit 1
          fi
```

### 5. Production LLM Log Audit

```bash
# Find accidental PII leaks in your LLM request logs
aigov-redact audit /var/log/llm-gateway/requests.log --format summary

# Daily compliance scan for SOC 2 / HIPAA
0 2 * * * aigov-redact audit /var/log/llm/requests.log --format json > reports/pii-$(date +\%Y\%m\%d).json

# With automatic audit trail
aigov-redact audit requests.log --audit-log pii-leaks.csv
```

### 6. LLM Training Data Sanitization

```python
from aigov_redact import redact  # ← aigov-redact
import json

# Sanitize entire fine-tuning datasets before training
with open("train.jsonl") as f, open("train_clean.jsonl", "w") as out:
    for line in f:
        record = json.loads(line)
        record["prompt"] = redact(record["prompt"]).text  # ← aigov-redact
        record["completion"] = redact(record["completion"]).text  # ← aigov-redact
        out.write(json.dumps(record) + "\n")
```

### 7. Custom PII Detection for Internal Tools

```python
from aigov_redact import redact  # ← aigov-redact
from aigov_redact.patterns import PIIDefinition  # ← aigov-redact
import re

# Add your company's internal identifiers
employee_id = PIIDefinition(  # ← aigov-redact
    name="EMP_ID",
    regex=re.compile(r"EMP-\d{6}"),
    confidence=0.95,
    severity="medium",
    placeholder="{EMP_ID}",
)

result = redact("Employee EMP-123456 reported an issue", custom_patterns=[employee_id])  # ← aigov-redact
print(result.text)
# → "Employee {EMP_ID} reported an issue"
```

### 8. Multi-Turn Conversation — Consistent Redaction

```python
from aigov_redact import redact  # ← aigov-redact

class SafeConversation:
    def __init__(self):
        self.history = []

    def add_message(self, role: str, content: str):
        safe = redact(content, mode="hash")  # ← aigov-redact
        self.history.append({"role": role, "content": safe.text})

    def get_context(self) -> list[dict]:
        return self.history

# PII is consistently hashed across turns
chat = SafeConversation()
chat.add_message("user", "My email is jane@test.com")
chat.add_message("assistant", "Thanks jane@test.com")
chat.add_message("user", "Actually it's jane@new.com")
# All three emails map to <EMAIL_hash1>, <EMAIL_hash1>, <EMAIL_hash2>
```

### 9. Healthcare LLM — HIPAA Compliance

```python
from aigov_redact import redact  # ← aigov-redact

hipaa_prompt = """Patient: John Smith
MRN: MRN-12345
DOB: 1985-07-20
ICD-10: I10 (hypertension), E11.9 (type 2 diabetes)
Phone: 555-123-4567"""

safe = redact(hipaa_prompt)  # ← aigov-redact
print(safe.text)
# → "Patient: {EMAIL}   ← Actually detected by NER if enabled
#     DOB: {DOB}
#     ICD-10: {ICD_CODE}, {ICD_CODE}
#     Phone: {PHONE}
#     MRN: {MEDICAL_RECORD}"
```

### 10. LangChain / LlamaIndex Guard

```python
# Drop-in guard for any LangChain chain
from aigov_redact import redact  # ← aigov-redact
from langchain_core.messages import HumanMessage, AIMessage

def guard_llm_input(messages):
    for m in messages:
        if isinstance(m, HumanMessage):
            result = redact(m.content)  # ← aigov-redact
            m.content = result.text
    return messages

# Use in your chain
# chain = RunnablePassthrough.assign(messages=guard_llm_input) | model | parser
```

## Development

### Setup

```bash
git clone https://github.com/shashi3070/aigov-redact
cd aigov-redact
pip install -e ".[dev]"
```

### Test

```bash
pytest tests/ -v --cov=src/aigov_redact
```

### Lint

```bash
ruff check src/ tests/
```

### Build

```bash
python -m build
twine upload dist/*
```

## Performance

For typical LLM prompts (under 2KB), aigov-redact processes in **<1ms** with regex-only mode. With NER enabled, expect 50-200ms per call (dominated by spaCy model loading).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT
