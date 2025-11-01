"""HTML and e-mail analysis for LinkSentry."""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from .rules import AnalysisResult, RuleBook, RuleMatch

PHISHING_KEYWORDS = (
    "login",
    "verify",
    "password",
    "update",
    "account",
    "security",
)

OBFUSCATED_JS_PATTERNS = (
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"atob\s*\(", re.IGNORECASE),
    re.compile(r"fromCharCode", re.IGNORECASE),
    re.compile(r"\\x[0-9a-fA-F]{2}", re.IGNORECASE),
)

HIDDEN_INPUT_PATTERN = re.compile(r"<input[^>]+type=['\"]hidden['\"][^>]*>", re.IGNORECASE)
SUSPICIOUS_INPUT_NAMES = re.compile(r"name=['\"][^'\"]*(pass|pwd|token|otp)['\"]", re.IGNORECASE)
FORM_PATTERN = re.compile(r"<form[^>]*>", re.IGNORECASE)
ACTION_PATTERN = re.compile(r"action=['\"]([^'\"]+)['\"]", re.IGNORECASE)
ORIGIN_META_PATTERN = re.compile(r"<meta[^>]+name=['\"]origin-domain['\"][^>]+content=['\"]([^'\"]+)['\"]", re.IGNORECASE)
ORIGIN_COMMENT_PATTERN = re.compile(r"origin-domain\s*:\s*([^\s>]+)")


def analyze_html(path: Path, rulebook: RuleBook, origin_domain: Optional[str] = None) -> AnalysisResult:
    content = path.read_text(encoding="utf-8")
    inferred_origin = origin_domain or infer_origin_domain(content)
    matches: List[RuleMatch] = []

    for func in _HTML_RULES:
        matches.extend(func(content, rulebook, inferred_origin))

    target = str(path)
    score = rulebook.score(matches)
    severity = rulebook.classify(score)
    metadata = {"origin_domain": inferred_origin or "", "filesize": str(path.stat().st_size)}
    return AnalysisResult(target=target, score=score, severity=severity, matches=matches, metadata=metadata)


def infer_origin_domain(content: str) -> Optional[str]:
    meta_match = ORIGIN_META_PATTERN.search(content)
    if meta_match:
        return meta_match.group(1).strip()
    comment_match = ORIGIN_COMMENT_PATTERN.search(content)
    if comment_match:
        return comment_match.group(1).strip()
    return None


def _keyword_rules(content: str, rulebook: RuleBook, origin_domain: Optional[str]) -> Iterable[RuleMatch]:
    lowered = unescape(content.lower())
    hits = []
    for keyword in PHISHING_KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", lowered):
            hits.append(rulebook.make_match("phishing_keywords", f"Keyword '{keyword}' found"))
    return hits


def _hidden_inputs(content: str, rulebook: RuleBook, origin_domain: Optional[str]) -> Iterable[RuleMatch]:
    if HIDDEN_INPUT_PATTERN.search(content):
        return [rulebook.make_match("hidden_inputs", "Hidden form inputs detected")]
    return []


def _suspicious_input_names(content: str, rulebook: RuleBook, origin_domain: Optional[str]) -> Iterable[RuleMatch]:
    if SUSPICIOUS_INPUT_NAMES.search(content):
        return [rulebook.make_match("suspicious_input_names", "Suspicious input field names located")]
    return []


def _obfuscated_js(content: str, rulebook: RuleBook, origin_domain: Optional[str]) -> Iterable[RuleMatch]:
    for pattern in OBFUSCATED_JS_PATTERNS:
        if pattern.search(content):
            return [rulebook.make_match("obfuscated_js", "Potentially obfuscated JavaScript detected")]
    return []


def _form_action_mismatch(content: str, rulebook: RuleBook, origin_domain: Optional[str]) -> Iterable[RuleMatch]:
    matches: List[RuleMatch] = []
    for form_match in FORM_PATTERN.finditer(content):
        end_index = content.find("</form>", form_match.end())
        if end_index == -1:
            end_index = form_match.end()
        form_html = content[form_match.start() : end_index]
        action_match = ACTION_PATTERN.search(form_html)
        if not action_match:
            continue
        action_url = action_match.group(1).strip()
        if action_url.startswith(("mailto:", "javascript:")):
            continue
        if origin_domain and action_url.startswith(("http://", "https://")):
            parsed = urlparse(action_url)
            host = parsed.hostname or ""
            if host and not _same_domain(host, origin_domain):
                matches.append(
                    rulebook.make_match(
                        "form_action_offsite",
                        f"Form posts to {host} instead of {origin_domain}",
                        evidence=action_url,
                    )
                )
        elif action_url.startswith(("http://", "https://")):
            parsed = urlparse(action_url)
            host = parsed.hostname or ""
            if host:
                matches.append(
                    rulebook.make_match(
                        "form_action_offsite",
                        f"Form posts to external domain {host}",
                        evidence=action_url,
                    )
                )
    return matches


def _same_domain(candidate: str, origin: str) -> bool:
    candidate = candidate.lower()
    origin = origin.lower()
    return candidate == origin or candidate.endswith("." + origin)


_HTML_RULES = (
    _keyword_rules,
    _hidden_inputs,
    _suspicious_input_names,
    _obfuscated_js,
    _form_action_mismatch,
)
