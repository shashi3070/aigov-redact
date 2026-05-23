# aigov-redact: PII Firewall for LLM Apps

> *One-line pitch:* Stop sending PII to OpenAI. Zero trust, local-first, audit-ready.

---

## The Problem

**Every prompt you send to an LLM is a compliance risk.**

```
"My SSN is 123-45-6789, what benefits can I claim?"
                              ↑
                    This goes to OpenAI's servers
```

- Employee PII, customer data, API keys, medical info — all accidentally pasted into prompts
- No audit trail of what was exposed
- GDPR fines: up to €20M or 4% of revenue
- HIPAA violations: $50k–$1.5M per incident
- SOC 2 auditors require evidence that PII is controlled before external transmission

---

## The Solution

**aigov-redact** — an open-source Python library that sits between your app and the LLM.

```python
from aigov_redact import redact  # ← aigov-redact

safe = redact(prompt).text      # strips PII before API call
response = openai.chat.completions.create(
    messages=[{"role": "user", "content": safe}]
)
```

| Before | After |
|---|---|
| "My SSN is 123-45-6789" | "My SSN is {SSN}" |
| "Email me at john@gmail.com" | "Email me at {EMAIL}" |
| "API key: sk-abc...def" | "API key: {API_KEY}" |

---

## Key Differentiators

| Feature | aigov-redact | Alternatives |
|---|---|---|
| **Local-first** | Zero data leaves your machine. No API calls. | Most send data to a cloud service for scanning |
| **50 patterns** | SSN, credit cards (Luhn), API keys (~35 formats), IBAN (MOD-97), Aadhaar (Verhoeff), private keys, JWT, crypto wallets, Azure connection strings, Telegram/Discord/HashiCorp tokens | Typical: 10–15 regexes |
| **4 confidence tiers** | Checksum-validated → format-validated → shape → context-dependent | Usually flat |
| **Audit trail** | Auto-logs every call to `~/.aigov-redact/history.jsonl`; CSV export for SOC 2/GDPR | None |
| **Compliance profiles** | HIPAA, PCI DSS, GDPR presets — one flag toggles the right patterns | Manual config |
| **CLI + Library** | `aigov-redact check file.txt` — drop-in CI/CD gate | Library-only |
| **Dependencies** | Pure Python. Zero heavy deps. <1ms per prompt. | Often require spaCy, ML models, or cloud SDKs |

---

## Quick Demo

```bash
# 1. Check a prompt for PII before sending to GPT
aigov-redact check prompt.txt --json

# 2. Redact in-place (keeps .bak backup)
aigov-redact redact prompt.txt

# 3. Pipe directly to your LLM client
cat prompt.txt | aigov-redact redact --stdin | your-llm-client

# 4. Audit your production logs for PII leaks
aigov-redact audit /var/log/llm/requests.log --fail-on-pii

# 5. Show governance history
aigov-redact history
```

---

## Compliance & Governance

```
                          ┌─────────────────┐
                          │   Your App       │
                          └────────┬────────┘
                                   │
                          ┌────────▼────────┐
                          │  aigov-redact   │ ← SOC 2 / HIPAA / GDPR gate
                          │  - detect PII   │
                          │  - redact it    │
                          │  - log to audit │
                          └────────┬────────┘
                                   │ (clean text)
                          ┌────────▼────────┐
                          │  OpenAI / Claude│
                          │  / Gemini       │ ← never sees PII
                          └─────────────────┘
```

**For auditors:** `aigov-redact audit requests.log --audit-log pii-leaks.csv`

> *"Prove that every PII entity was detected, hashed, and redacted before reaching the LLM provider. No PII stored in plaintext — only SHA-256 hashes for deduplication."*

---

## Adoption

- **Install:** `pip install aigov-redact`
- **GitHub:** [shashi3070/aigov-redact](https://github.com/shashi3070/aigov-redact)
- **PyPI:** [aigov-redact 0.1.1](https://pypi.org/project/aigov-redact/)
- **License:** MIT — free for commercial use
- **Patterns covered:** 50 PII types across email, SSN, credit cards, API keys, crypto wallets, medical codes, passports, driver's licenses, and more

---

## Call to Action

1. **Try it now:** `pip install aigov-redact && aigov-redact check README.md`
2. **Add it to your LLM pipeline** — 3 lines of code guards every API call
3. **Run it in CI/CD** — fail deployments that leak PII
4. **Generate your compliance evidence** — `aigov-redact audit` for SOC 2 / HIPAA

> *"If you're sending prompts to an LLM without redacting PII first, you're already leaking data."*
