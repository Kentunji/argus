# Argus

AI-powered web application vulnerability scanner. Uses LLM-assisted exploit generation to detect and verify security flaws in modern web apps.

> **Status:** Early development. Not yet ready for use.

## Overview

Argus combines traditional web crawling with LLM reasoning to identify and verify vulnerabilities in web applications. The scanner uses DeepSeek as its language model backend, and is designed to be tested against deliberately vulnerable targets such as [OWASP Juice Shop](https://github.com/juice-shop/juice-shop).

## Requirements

- Python 3.10+
- A DeepSeek API key ([platform.deepseek.com](https://platform.deepseek.com))
- A target web application you own or have permission to test

## Installation

```bash
git clone git@github.com:kentunji/argus.git
cd argus
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your DeepSeek API key
```

## Usage

> *Coming soon — scanner is under active development.*

## Responsible Use

Argus is intended for authorized security testing only. Do not use against systems you do not own or have explicit written permission to test. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Kehinde Adetunji Tosin
