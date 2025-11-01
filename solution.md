# LinkSentry Demo Script

Use this guide to run a fast classroom or CTF walk-through of the LinkSentry
CLI. Each sample demonstrates a different class of phishing signal and maps to
the bundled heuristics.

## 1. Baseline (benign)

```bash
linksentry url "$(cat samples/benign_url.txt)"
```

*Expected:* score remains below the "low" threshold with no rule hits.

## 2. Typosquat phishing URL

```bash
linksentry url "$(cat samples/typosquat_url.txt)" --verbose
```

*Highlights:*

- `typosquat` rule fires because the hostname closely resembles `google.com`.
- `sensitive_path_keyword` triggers thanks to `/login` appearing in the path.
- Overall score ~55 (high severity) in the default configuration.

## 3. Homograph via punycode

```bash
linksentry url "$(cat samples/homograph_url.txt)"
```

*Highlights:*

- `punycode_hostname` decodes the unicode impersonation of `apple.com`.
- Combined weight pushes the score above the critical threshold (>70).

## 4. Credential harvesting form

```bash
linksentry file samples/phish_login.html --output table --verbose
```

*Highlights:*

- Meta tag or HTML comment provides the expected origin `accounts.example.com`.
- The `<form>` action posts to `login.example-security-support.com`, firing the
  `form_action_offsite` rule.
- `hidden_inputs`, `suspicious_input_names`, `phishing_keywords`, and
  `obfuscated_js` all contribute to the critical score (~80).

Remind the audience that the CLI also supports `--report report.json` for
producing a machine-readable explanation.
