# Argus

**AI-powered web application vulnerability scanner.**

Argus crawls a web application, probes it for common vulnerabilities (XSS, SQL injection, security-header misconfigurations), and uses a Large Language Model to triage each finding into plain-English explanations and stack-specific remediation code. Output ships in three formats: a rich terminal summary, a machine-readable JSON file, and a standalone styled HTML report.

> **Status:** v0.1.0 — first working release. Suitable for learning, CTF targets, and scanning your own applications. Not yet production-grade; see the [roadmap](#roadmap) below.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests: 67 passing](https://img.shields.io/badge/tests-67%20passing-brightgreen.svg)](#tests)

---

## Highlights

- **Three detectors:** reflected XSS (CWE-79), SQL injection (CWE-89, error-based + status-change + boolean-based), security headers + cookie audit (CWE-693, CWE-614, CWE-1004).
- **AI-powered triage:** every finding is sent to an LLM that produces an independent confidence rating, a plain-English explanation, and stack-specific remediation code with examples.
- **AI executive summary:** a one-paragraph overview generated per scan, suitable as the opening of a pen-test report.
- **Three output formats:** rich terminal output, machine-readable JSON, and a standalone styled HTML report. No external dependencies in the HTML file.
- **Graceful LLM degradation:** if the LLM API is slow, down, or unreachable, the scan still completes and reports are still generated; only the AI layer is missing.
- **Seed forms:** declare SPA or API endpoints the static crawler cannot discover, via a simple YAML file.
- **CI/CD-friendly exit codes:** `0` on clean scans, `1` on HIGH/CRITICAL findings, `2` on configuration errors. Makes `argus scan && deploy` a real pattern.
- **LLM-agnostic:** default backend is DeepSeek, but any OpenAI-compatible provider works (OpenAI, Groq, Ollama, and others). Native Claude and Gemini planned for v0.2.
- **67/67 tests passing** including live integration tests against the real DeepSeek API and OWASP Juice Shop.

---

## Demo

Scan OWASP Juice Shop, find five real vulnerabilities in under 50 seconds, including the famous Login Admin SQL injection challenge:

![Argus terminal output showing scan results](docs/images/hero-terminal.png)

![Argus HTML report with AI executive summary](docs/images/hero-html-top.png)

![Expanded SQLi finding with AI-generated remediation code](docs/images/hero-sqli-expanded.png)

*Screenshots from a real scan on April 20, 2026. Five findings (two HIGH SQLi, one MEDIUM, one LOW, one INFO), zero false positives, 48.53 seconds total scan time with AI triage enabled.*

---

## Requirements

- Python 3.10 or newer
- A DeepSeek API key (get one free at [platform.deepseek.com](https://platform.deepseek.com))
- A target web application you own or have explicit written permission to test

---

## Installation

```bash
git clone https://github.com/Kentunji/argus.git
cd argus
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Then configure your environment:

```bash
cp .env.example .env
# Open .env in your editor and paste your DeepSeek API key
```

After `pip install -e .`, the `argus` command is available on your PATH.

---

## Usage

```bash
# Run a full scan with AI triage and all three report formats
argus scan http://localhost:3000

# Skip the LLM triage for faster, cheaper scans
argus scan http://localhost:3000 --no-triage

# Skip individual report formats
argus scan http://localhost:3000 --no-html --no-json

# Override crawl depth and page limits
argus scan https://example.com --depth 2 --max-pages 50

# Version and help
argus version
argus --help
```

Reports are written to `reports/scan_YYYYMMDD_HHMMSS.json` and `reports/scan_YYYYMMDD_HHMMSS.html` by default.

### Scanning SPAs (Single Page Applications)

Argus v0.1 uses a static HTML crawler and cannot see forms rendered client-side by JavaScript frameworks such as Angular, React, or Vue. For SPAs, declare the endpoints you want scanned in a `seed_forms.yml` file:

```bash
cp seed_forms.example.yml seed_forms.yml
# Edit seed_forms.yml to declare your target's forms and API endpoints
```

A full Playwright-based dynamic crawler is planned for v0.3.

### CI/CD integration

Argus returns exit code `1` when any HIGH or CRITICAL severity findings are present, making it safe to gate deployments:

```yaml
# .github/workflows/security.yml (example)
- name: Security scan
  run: argus scan https://staging.example.com --no-triage
# Subsequent steps run only if the scan exit code was 0
```

---

## What's in v0.1

**Detectors:**
- Reflected Cross-Site Scripting (XSS)
- SQL Injection (error-based, status-change, boolean-based; probes both form-encoded and JSON bodies)
- Security header audit (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Cookie flag audit (Secure, HttpOnly, SameSite)

**Output formats:**
- Rich terminal table with severity colours and AI confidence column
- JSON (machine-readable, structured, future-proofed for SARIF)
- Standalone HTML (dark-mode, portable, emailable, no external dependencies)

**AI layer:**
- Per-finding confidence rating, explanation, and tailored remediation (with code snippets when relevant)
- Per-scan executive summary paragraph
- Graceful degradation if the LLM is unavailable

**Built on:** Python 3.10+, `requests`, `beautifulsoup4`, `openai` (as a DeepSeek-compatible client), `rich`, `python-dotenv`, `pyyaml`.

---

## What's not in v0.1

Be aware of these limitations before pointing Argus at real targets:

- **No JavaScript rendering.** Static HTML crawler only. SPAs expose little without seed forms. (Fixed in v0.3 with Playwright.)
- **No authenticated scanning.** Cannot log in, manage sessions, or reach authenticated endpoints. (Fixed in v0.2.)
- **Three vulnerability classes only.** No SSRF, XXE, CSRF, IDOR, command injection, or similar. (Each added in later versions; see roadmap.)
- **Sequential LLM calls.** Triage runs one finding at a time. On large scans this adds up. (Parallel triage in v0.2.)
- **No rate limiting.** The scanner probes as fast as your network allows. Not safe against production targets without external throttling. (Fixed in v0.4.)
- **No SARIF output.** GitHub Security tab integration requires SARIF. (Fixed in v0.3.)

Use v0.1 for learning, CTF challenges, and scanning applications you own. For real engagements, wait for v1.0.

---

## Roadmap

- **v0.2** — authenticated scanning, IDOR detector, stored XSS, native Claude + Gemini support
- **v0.3** — Playwright-based dynamic crawler, CSRF detector, SARIF output, GitHub Actions integration
- **v0.4** — SSRF, XXE, command injection, parallel scanning, rate limiting
- **v0.5** — LLM-driven adaptive payloads, false-positive reduction, scan resume
- **v1.0** — production-grade: SSO flows, WAF evasion, distributed workers, compliance mappings, WebSocket + GraphQL support

---

## Tests

```bash
# Run the full test suite
pytest

# Fast subset (skip live tests)
pytest -k "not live"
```

The full suite includes live integration tests against the DeepSeek API and OWASP Juice Shop; live tests auto-skip if the target or API is unreachable.

---

## Responsible use

Argus is intended for authorised security testing only. Do not use it against systems you do not own or have explicit written permission to test. Unauthorised scanning may violate local laws including, depending on jurisdiction, the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and various national criminal codes.

See [SECURITY.md](SECURITY.md) for how to responsibly report vulnerabilities in Argus itself.

---

## Contributing

Contributions are welcome. Open an issue to discuss substantial changes before submitting a pull request. For small fixes (typos, doc improvements, obvious bugs), go straight to a PR.

Development setup:

```bash
git clone https://github.com/Kentunji/argus.git
cd argus
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## Author

Kehinde Adetunji Tosin
[github.com/Kentunji](https://github.com/Kentunji)

---

## License

[MIT](LICENSE) © 2026 Kehinde Adetunji Tosin
