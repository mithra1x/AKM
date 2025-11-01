# DoubleThink — Explainable URL & Email Analyzer

DoubleThink is a lightweight, offline-friendly toolkit for demonstrating how
phishing detection works. It inspects URLs as well as saved HTML or raw e-mail
messages, applies a transparent set of heuristic rules, and produces an
explainable risk score between 0 and 100. The repository ships with a ready to
run CLI, bundled rules, demo samples, and unit tests so you can showcase the
analysis flow end-to-end in just a few minutes.

## Features

- **Explainable scoring** – each triggered rule contributes a weighted score and
  includes a short explanation.
- **URL heuristics** – punycode decoding, homograph detection, typosquatting,
  suspicious TLD detection, excessive subdomains, `@` symbol checks, credential
  keywords in paths, long/base64 paths, and more.
- **HTML / email heuristics** – phishing keywords, hidden fields, obfuscated
  JavaScript, and off-domain form submissions.
- **Offline friendly** – no external lookups; everything runs locally.
- **Flexible output** – table or JSON output in the terminal, plus optional JSON
  report files for later review.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the `doublethink` CLI entrypoint. To run without installing, you
can also execute `python -m doublethink` inside the repository.

## Usage

### Analyze a URL

```bash
doublethink url https://accounts-g00gle.com/login --output table
```

### Analyze a saved HTML/e-mail file

```bash
doublethink file samples/phish_login.html --output json --report report.json
```

The HTML analyzer can optionally take an expected origin domain. If one is not
provided, DoubleThink attempts to infer it from meta tags or HTML comments.

```bash
doublethink file phish_login.html --origin example.com
```

### Verbose explanations

Add `--verbose` to surface additional evidence for each triggered rule.

```bash
doublethink url https://xn--80ak6aa92e.com --verbose
```

## Demo walkthrough

The `samples/` directory includes four ready-to-use examples that pair with
`solution.md` for classroom or CTF-style demos:

1. `benign_url.txt` – Safe URL for baseline comparison.
2. `typosquat_url.txt` – Typosquatted domain with phishing keywords.
3. `homograph_url.txt` – Punycode-hosted homograph impersonation.
4. `phish_login.html` – Credential harvesting form posting off-domain.

Use `solution.md` as a script to explain why the analyzer flags each case and
which rules trigger.

## Configuration

Weights and descriptions for each detection rule live in `rules/weights.yml`.
You can adjust the weights, add new rules, or tweak severity thresholds without
changing code. Run the unit tests after modifying rules to confirm behaviour.

## Development

Run the unit test suite with `pytest`:

```bash
pytest
```

Key modules:

- `doublethink/cli.py` – command-line interface and output formatting.
- `doublethink/url_analyzer.py` – URL-focused heuristics.
- `doublethink/html_analyzer.py` – HTML/e-mail heuristics.
- `doublethink/rules.py` – rule loading, scoring, and explainability helpers.

## License

Distributed under the MIT License. See `LICENSE` for details.
