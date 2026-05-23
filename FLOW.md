# aigov-redact Execution Flow

## Overview

```
Input ──► detect() ──► DetectionResult
         ├── redact() ──► RedactResult
         ├── mask() ──► RedactResult
         ├── audit ──► AuditResult
         └── history ──► UsageRecord[]
```

---

## 1. `detect()` Flow (public API, `redactor.py`)

```python
def detect(text, enabled_types, disabled_types, custom_patterns,
           excluded_patterns, ner_enabled, history_path, file_path, source):
```

### Step-by-step

```
Input: text = "Email: john@test.com, SSN: 123-45-6789"
       ner_enabled = False
```

#### Step 1 — Create Detector

```python
detector = create_detector(
    enabled_types=None,     # None → use all 50 patterns
    disabled_types=None,    # None → nothing excluded
    custom_patterns=None,   # None → no extras
    excluded_patterns=None, # None → no regex exclusions
)
```

**`Detector.__init__` produces:**
```
self._definitions = [
    # Sorted by .tier ascending:
    PIIDefinition(name="CREDIT_CARD", tier=1, regex=r'\b(?:\d[ -]*?){13,19}\b',
                  validator=_luhn_checksum, confidence=0.95, severity="high"),
    PIIDefinition(name="SSN", tier=1, regex=r'\b\d{3}-\d{2}-\d{4}\b',
                  validator=_validate_ssn, confidence=0.95, severity="high"),
    PIIDefinition(name="EMAIL", tier=2, regex=r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b',
                  validator=_always_valid, confidence=0.9, severity="medium"),
    ... 48 more ...
]
self._excluded = []
```

#### Step 2 — detector.detect(text)

```python
raw = []
for definition in self._definitions:  # iterates tier 1 → 4
    for match in definition.regex.finditer(text):
        value = match.group()
        # Excluded filter
        if self._is_excluded(value):  # checks self._excluded patterns
            continue
        # Validator check
        if definition.validator and not definition.validator(value):
            continue
        raw.append(PIIEntity(
            type=definition.name,
            text=value,
            start=match.start(),
            end=match.end(),
            confidence=definition.confidence,
            severity=definition.severity,
            placeholder=definition.placeholder,
        ))
```

**Intermediate `raw` after all regex passes:**
```
raw = [
    PIIEntity(type="EMAIL", text="john@test.com", start=7, end=21,
              confidence=0.9, severity="medium", placeholder="{EMAIL}"),
    PIIEntity(type="SSN", text="123-45-6789", start=28, end=40,
              confidence=0.95, severity="high", placeholder="{SSN}"),
]
```

#### Step 3 — _resolve_overlaps(raw)

```python
sorted_ents = sorted(raw, key=lambda e: (e.start, -e.end))
# [(EMAIL, 7), (SSN, 28)]  → no overlaps, both pass through
```

**If overlaps existed (e.g., "4111-1111-1111-1111" matches both CC and HEX_TOKEN):**
```
raw = [
    PIIEntity(type="CREDIT_CARD", start=0, end=19, confidence=0.95),
    PIIEntity(type="HEX_TOKEN_32", start=0, end=19, confidence=0.7),
]
# → _resolve_overlaps keeps CREDIT_CARD (higher confidence)
```

#### Step 4 — NER (optional, skipped here)

```python
if ner_enabled:
    from aigov_redact.ner.presidio import detect_ner
    ner_entities = detect_ner(text)
    entities.extend(ner_entities)
    entities = Detector._resolve_overlaps(entities)
```

#### Step 5 — Build DetectionResult

```python
result = DetectionResult(text=text, entities=entities)
# result.count → @computed_field = 2
```

#### Step 6 — record_usage (skipped if called from redact())

```python
record_usage(
    command="check",
    source="library",          # or "cli", "stdin"
    file_path=None,
    entity_count=2,
    entity_types=["EMAIL", "SSN"],
    ner_enabled=False,
)
```

**Written to:**
```
~/.aigov-redact/history.jsonl
./.aigov-redact/history.jsonl
```

#### Final Output

```python
DetectionResult(
    text="Email: john@test.com, SSN: 123-45-6789",
    entities=[
        PIIEntity(type="EMAIL", text="john@test.com", start=7, end=21,
                  confidence=0.9, severity="medium", placeholder="{EMAIL}"),
        PIIEntity(type="SSN", text="123-45-6789", start=28, end=40,
                  confidence=0.95, severity="high", placeholder="{SSN}"),
    ],
    # computed: count = 2
)
```

---

## 2. `redact()` Flow (public API, `redactor.py`)

```python
def redact(text, mode="replace", enabled_types=None, disabled_types=None,
           custom_patterns=None, excluded_patterns=None, ner_enabled=False,
           placeholder_style="type", mask_char="*",
           custom_placeholder="{PII}", history_path=None,
           file_path=None, source=None):
```

### Step-by-step (mode="replace")

```
Input: text = "Email: john@test.com, SSN: 123-45-6789"
       mode = "replace"
       placeholder_style = "type"
```

#### Step 1 — Set _in_detect guard

```python
_in_detect = True   # prevents detect() from logging usage
```

#### Step 2 — Call detect() internally

```python
detection = detect(text, ...)  # returns DetectionResult (same as §1)
# _in_detect flag ensures no usage log written here
```

```
detection.entities = [
    PIIEntity(type="EMAIL", text="john@test.com", start=7, end=21, placeholder="{EMAIL}"),
    PIIEntity(type="SSN", text="123-45-6789", start=28, end=40, placeholder="{SSN}"),
]
```

#### Step 3 — Clear guard

```python
_in_detect = False
```

#### Step 4 — Dispatch to _apply_*()

```python
if mode == "remove":
    result = _apply_remove(text, entities)
elif mode == "mask":
    result = _apply_mask(text, entities, mask_char)
elif mode == "hash":
    result = _apply_hash(text, entities)
elif mode == "custom":
    result = _apply_custom(text, entities, custom_placeholder)
else:  # "replace" (default)
    result = _apply_replace(text, entities, placeholder_style)
```

#### Step 4a — _apply_replace (style="type")

```python
result = list(text)
# ['E','m','a','i','l',':',' ','j','o','h','n','@','t','e','s','t','.','c','o','m',',',' ','S','S','N',':',' ','1','2','3','-','4','5','-','6','7','8','9']

entities sorted by start DESC:
  SSN(start=28) first, EMAIL(start=7) second

ent = SSN → placeholder = "{SSN}"  (6 chars)
  result[28:40] = "{SSN}"
  # replaces '1','2','3','-','4','5','-','6','7','8','9' (12 chars → 6 chars)

ent = EMAIL → placeholder = "{EMAIL}"  (7 chars)
  result[7:21] = "{EMAIL}"
  # replaces 'j','o','h','n','@','t','e','s','t','.','c','o','m' (14 chars → 7 chars)
```

**Intermediate `result` list after both replacements:**
```
['E','m','a','i','l',':',' ','{','E','M','A','I','L','}',',',' ','S','S','N',':',' ','{','S','S','N','}']
```

```python
"".join(result) → "Email: {EMAIL}, SSN: {SSN}"
```

#### Step 4b — _apply_mask (mode="mask", char="*")

```python
ent = SSN(start=28) → 12 chars → "************" (12 asterisks)
ent = EMAIL(start=7) → 14 chars → "**************" (14 asterisks)
```
```
Output: "Email: **************, SSN: ************"
```

#### Step 4c — _apply_hash (style="hash" or mode="hash")

```python
ent = SSN → hash_val = sha256("123-45-6789".encode())[:8]  → e.g. "a1b2c3d4"
    replacement = "<SSN_a1b2c3d4>"

ent = EMAIL → hash_val = sha256("john@test.com".encode())[:8] → e.g. "e5f6g7h8"
    replacement = "<EMAIL_e5f6g7h8>"
```
```
Output: "Email: <EMAIL_e5f6g7h8>, SSN: <SSN_a1b2c3d4>"
```

#### Step 4d — _apply_remove (mode="remove")

```python
ent = SSN(start=28) → del result[28:40]
ent = EMAIL(start=7) → del result[7:21]
```
```
Output: "Email: , SSN: "
```

#### Step 4e — _apply_custom (mode="custom")

```python
Both entities replaced with "{PII}":
```
```
Output: "Email: {PII}, SSN: {PII}"
```

#### Step 5 — record_usage

```python
record_usage(
    command="redact",
    source="library",
    entity_count=2,
    entity_types=["EMAIL", "SSN"],
    mode="replace",
    ner_enabled=False,
)
```

#### Final Output

```python
RedactResult(
    text="Email: {EMAIL}, SSN: {SSN}",
    entities=[
        PIIEntity(type="EMAIL", text="john@test.com", start=7, end=21, ...),
        PIIEntity(type="SSN", text="123-45-6789", start=28, end=40, ...),
    ],
    mode="replace",
)
```

---

## 3. `mask()` Flow (convenience wrapper, `redactor.py`)

```python
def mask(text, char="*", enabled_types=None, disabled_types=None,
         custom_patterns=None, excluded_patterns=None,
         history_path=None, file_path=None):
```

### Internally

```python
return redact(
    text=text,
    mode="mask",
    mask_char=char,
    ...
)
```

Same flow as §2 but forced into `_apply_mask`. Output:
```
Input:  "Email: john@test.com"
Output: "Email: **************"
```

---

## 4. `check` CLI Command Flow (`cli/main.py`)

```
$ aigov-redact check file.txt --json --compliance-profile hipaa
```

```
_parse_config("--config path or None", "hipaa")
  └── load_config(path) → dict from .aigov-redact-config / pyproject.toml
  └── merge_config_with_cli(cfg, {"compliance_profile": "hipaa"})
       └── resolve_compliance_profile(cfg)
            └── looks up cfg["compliance_profiles"]["hipaa"]
            └── merges profile keys into top-level:
                enabled = ["SSN","PHONE_US",...]
                disabled = ["CREDIT_CARD","CRYPTO_WALLET",...]
                placeholder_style = "type"
                ner_enabled = True
                mask_char = "*"

_detector_options(cfg):
  → {"custom_patterns": [],       # parsed from config
     "excluded_patterns": None,
     "enabled_types": ["SSN","PHONE_US",...],   # HIPAA profile
     "disabled_types": ["CREDIT_CARD",...]}

detect_lib(text, ner_enabled=False, source="cli", file_path="file.txt",
           history_path=cfg.get("history_path"), **opts)
  → DetectionResult

if JSON → print JSON, exit 1 if count > 0
else    → print table, exit 1 if entities found
```

---

## 5. `redact` CLI Command Flow

```
$ aigov-redact redact file.txt --mode mask --mask-char #
```

```
_resolve_config(cfg, compliance_profile=None)
  └── load_config(None) → walks parents for .aigov-redact-config

CLI overrides: mode="mask", mask_char="#"
  └── merge_config_with_cli(cfg, {"mode":"mask","mask_char":"#"})

detector_options + mode/mask_char sourced from merged config

redact_lib(text, mode="mask", mask_char="#", source="cli",
           file_path="file.txt", ...)
  → RedactResult

if not no_backup → copy file → file.bak
write result.text → overwrite original file
```

---

## 6. `audit` Command Flow (`auditor.py`)

```
$ aigov-redact audit requests.log --format json --audit-log audit.csv
```

```
_build_detector(cfg)
  └── Detector(enabled, disabled, custom, excluded)

auditor = Auditor(detector, audit_log_path="audit.csv")

auditor.scan_file("requests.log")
  ├── open file
  ├── for line_no, line in enumerate(file, 1):
  │     entities = detector.detect(line.strip("\n"))
  │     for entity in entities:
  │         entry = AuditEntry(
  │             filename="requests.log",
  │             line=line_no,
  │             column=entity.start,
  │             type=entity.type,
  │             value_hash=detector.hash_value(entity.text),  # sha256[:16]
  │             confidence=entity.confidence,
  │             severity=entity.severity,
  │         )
  │         entries.append(entry)
  │         if audit_log_path:
  │             _append_to_log(entry)
  │             # → appends CSV row to audit.csv
  │             #   "2026-05-23T12:00:00,requests.log,1,0,EMAIL,abc123...,0.9,medium"
  │
  └── return AuditResult(
          entries=[...],
          total_files=1,
          summary={"EMAIL": 5, "SSN": 2, ...},
      )
```

**Audit CSV format:**
```
timestamp,filename,line,column,type,value_hash,confidence,severity
2026-05-23T12:00:00,requests.log,1,0,EMAIL,a1b2c3d4e5f6g7h8,0.9,medium
2026-05-23T12:00:00,requests.log,3,15,SSN,deadbeef12345678,0.95,high
```

---

## 7. `history` Command Flow (`usage.py`)

```
$ aigov-redact history --limit 10
```

```
$cfg = load_config(None)

records = get_history(limit=10, history_path=cfg.get("history_path"))
  ├── _resolve_paths(history_path)
  │     if custom path → [Path(custom_path)]
  │     else → [~/.aigov-redact/history.jsonl, ./.aigov-redact/history.jsonl]
  │
  ├── for path in paths:
  │     read JSONL lines
  │     dedup: skip lines already seen
  │     parse into UsageRecord
  │
  └── sort records by .timestamp
      return records[-10:]  (last 10)

summary = get_history_summary(records)
  → {"total_runs": 100,
     "commands": {"check": 40, "redact": 50, "mask": 10},
     "entity_types_detected": {"EMAIL": 60, "SSN": 30, "CREDIT_CARD": 20}}
```

**UsageRecord (written to JSONL):**
```json
{"timestamp":"2026-05-23T12:00:00","command":"redact","source":"cli",
 "file_path":"/path/to/file.txt","entity_count":2,
 "entity_types":["EMAIL","SSN"],"mode":"replace","ner_enabled":false}
```

---

## 8. Config Loading & Compliance Profile Flow (`config.py`)

```
Input: config_path = None (auto-discover)
```

```
find_config(start_path=None)
  ├── start from Path.cwd()
  ├── walk up parent directories
  │     check for: .aigov-redact-config (bare, JSON, YAML)
  │     check for: pyproject.toml containing [tool.aigov-redact]
  └── return first match path or None

load_config(config_path)
  ├── if TOML → _load_toml_config(path)
  │               parse [tool.aigov-redact] section lines
  │               return {"mode":"mask", "placeholder_style":"hash", ...}
  │
  ├── if YAML → yaml.safe_load() → dict
  │
  ├── else → json.loads() → dict
  │
  └── return resolve_compliance_profile(config)
```

### Compliance Profile Resolution

```
resolve_compliance_profile(config)
  │
  ├── config["compliance_profile"] = "hipaa"
  │
  ├── config["compliance_profiles"]["hipaa"] = {
  │     "enabled": ["SSN", "PHONE_US", ...],
  │     "disabled": ["CREDIT_CARD", "CRYPTO_WALLET", ...],
  │     "placeholder_style": "type",
  │     "ner_enabled": true,
  │     "mask_char": "*",
  │   }
  │
  ├── Merge into top-level:
  │     merged = {**config}
  │     merged["pii_types"]["enabled"] = ["SSN", "PHONE_US", ...]
  │     merged["pii_types"]["disabled"] = ["CREDIT_CARD", ...]
  │     merged["placeholder_style"] = "type"
  │     merged["ner_enabled"] = true
  │     merged["mask_char"] = "*"
  │
  └── return merged

# CLI flag can override further:
merge_config_with_cli(merged, {"placeholder_style": "hash"})
  → final["placeholder_style"] = "hash"
```

---

## 9. NER Flow (optional, `ner/presidio.py`)

```
Input: text = "John Smith lives in New York"
       score_threshold = 0.35
```

```
detect_ner(text, score_threshold=0.35)
  ├── _get_engine()
  │     → AnalyzerEngine() singleton (lazy init)
  │
  ├── results = engine.analyze(text=text, language="en")
  │     → [RecognizerResult(entity_type="PERSON", start=0, end=10, score=0.85),
  │        RecognizerResult(entity_type="LOCATION", start=20, end=28, score=0.9)]
  │
  ├── for r in results:
  │     if r.score < 0.35 → skip
  │     mapped = NER_MAP.get("PERSON", "PERSON") → "PERSON"
  │     entities.append(PIIEntity(
  │         type="PERSON",
  │         text="John Smith",
  │         start=0,
  │         end=10,
  │         confidence=0.85,
  │         severity="medium",      # PERSON/LOCATION/ORG → "medium", else "high"
  │     ))
  │
  └── return [PIIEntity(type="PERSON", ...), PIIEntity(type="LOCATION", ...)]
```

NER entities are then merged with regex entities and resolved for overlaps in `redactor.py:detect()`.

---

## 10. Overlap Resolution Detail (`detector.py:_resolve_overlaps`)

```
Input: raw = [
    PIIEntity(type="CREDIT_CARD", start=0, end=19, confidence=0.95),
    PIIEntity(type="HEX_TOKEN_32", start=0, end=19, confidence=0.7),
]

sorted_ents = sorted(raw, key=lambda e: (e.start, -e.end))
# [(CC,0..19,0.95), (HEX,0..19,0.7)]

# Pass 1: merge overlapping segments
merged = []
for ent in sorted_ents:
    if merged and ent.start < merged[-1].end:
        prev = merged[-1]
        if ent.end > prev.end:
            if ent.confidence > prev.confidence:
                merged[-1] = ent     # higher confidence wins
            elif ent.confidence == prev.confidence and ...
                merged[-1] = ent     # longer match wins on tie
    else:
        merged.append(ent)
# → merged = [CREDIT_CARD(start=0, end=19, conf=0.95)]

# Pass 2: final non-overlapping filter
final = []
for ent in merged:
    if not final or ent.start >= final[-1].end:
        final.append(ent)
    elif ent.end > final[-1].end and ent.confidence > final[-1].confidence:
        final[-1] = ent
# → final = [CREDIT_CARD(start=0, end=19, conf=0.95)]

Output: [PIIEntity(type="CREDIT_CARD", ...)]
```

---

## Complete End-to-End Example

### Input
```
text = "Patient: John, SSN: 123-45-6789, CREDIT CARD: 4111-1111-1111-1111"
```

### Using HIPAA compliance profile

```
config = load_config(".aigov-redact-config")
config["compliance_profile"] = "hipaa"
config = resolve_compliance_profile(config)
# enabled = ["SSN", "PHONE_US", "EMAIL", ...]  (no CREDIT_CARD)
# disabled = ["CREDIT_CARD", "CRYPTO_WALLET", ...]

result = redact(text, compliance_profile="hipaa")
```

### Execution Trace

| Step | Variable | Value |
|------|----------|-------|
| 1 | `create_detector(enabled=["SSN",...], disabled=["CREDIT_CARD",...])` | Detector with ~15 definitions |
| 2 | `_definitions` filtered | SSNAPI_KEY、EMAIL、PHONE_US、DEA_NUMBER... (no CREDIT_CARD) |
| 3 | `detector.detect(text)` raw entities | `[PII(SSN, 123-45-6789, 28→40, conf=0.95)]` |
| 4 | NER (enabled) detects "John" | `[PII(PERSON, John, 9→13, conf=0.85)]` |
| 5 | `_resolve_overlaps([SSN, PERSON])` | No overlap → both kept |
| 6 | `DetectionResult(count=2)` | EMAIL、SSN、DEA... 可能还有更多 |
| 7 | `_apply_replace(entities, style="type")` | "Patient: {PERSON}, SSN: {SSN}, CREDIT CARD: 4111-1111-1111-1111" |
| 8 | `RedactResult(text="Patient: {PERSON}, SSN: {SSN}, CREDIT CARD: 4111-1111-1111-1111")` | 信用卡的原始文本不变 |

Note that credit card is NOT redacted — HIPAA profile disabled it.
