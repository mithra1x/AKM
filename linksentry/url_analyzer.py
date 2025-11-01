"""URL analysis heuristics for LinkSentry."""
from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Set
from urllib.parse import urlparse

from .rules import AnalysisResult, RuleBook, RuleMatch

BRAND_DOMAINS: Sequence[str] = (
    "google.com",
    "paypal.com",
    "microsoft.com",
    "apple.com",
    "facebook.com",
    "amazon.com",
)

SUSPICIOUS_TLDS: Sequence[str] = (
    "zip",
    "review",
    "country",
    "stream",
    "click",
    "gq",
    "work",
    "ml",
)

PATH_KEYWORDS: Sequence[str] = (
    "login",
    "signin",
    "verify",
    "update",
    "secure",
)


@dataclass
class URLContext:
    url: str
    parsed: object
    host: str
    path: str


def analyze_url(url: str, rulebook: RuleBook) -> AnalysisResult:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    context = URLContext(url=url, parsed=parsed, host=host, path=path)
    matches: List[RuleMatch] = []

    for func in _URL_RULES:
        matches.extend(func(context, rulebook))

    score = rulebook.score(matches)
    severity = rulebook.classify(score)
    metadata = {
        "scheme": parsed.scheme or "",
        "host": host,
        "path": path,
        "query": parsed.query or "",
    }
    return AnalysisResult(target=url, score=score, severity=severity, matches=matches, metadata=metadata)


def _punycode_and_homograph(context: URLContext, rulebook: RuleBook) -> Iterable[RuleMatch]:
    host = context.host or ""
    if "xn--" not in host:
        return []
    try:
        decoded = host.encode("ascii").decode("idna")
    except UnicodeError:
        decoded = host
    message = f"Hostname uses punycode ({host} → {decoded})"
    return [
        rulebook.make_match(
            "punycode_hostname",
            message,
            evidence=decoded,
        ),
    ]


def _host_is_ip(context: URLContext, rulebook: RuleBook) -> Iterable[RuleMatch]:
    host = context.host
    if not host:
        return []
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return []
    return [rulebook.make_match("ip_host", f"Hostname is an IP address ({host})")]


def _has_at_symbol(context: URLContext, rulebook: RuleBook) -> Iterable[RuleMatch]:
    prefix = context.url.split("?")[0]
    if "@" in prefix:
        return [rulebook.make_match("at_symbol", "URL contains @ symbol, possible credential hiding")]
    return []


def _many_subdomains(context: URLContext, rulebook: RuleBook) -> Iterable[RuleMatch]:
    host = context.host
    if not host:
        return []
    if host.count(".") >= 4:
        return [rulebook.make_match("many_subdomains", f"Hostname has many subdomains ({host})")]
    return []


def _suspicious_tld(context: URLContext, rulebook: RuleBook) -> Iterable[RuleMatch]:
    host = context.host
    if not host or "." not in host:
        return []
    tld = host.rsplit(".", 1)[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        return [rulebook.make_match("suspicious_tld", f"TLD {tld} frequently abused in phishing")]
    return []


def _long_path(context: URLContext, rulebook: RuleBook) -> Iterable[RuleMatch]:
    if len(context.path) > 60:
        return [rulebook.make_match("long_path", f"URL path is unusually long ({len(context.path)} chars)")]
    return []


def _base64_in_path(context: URLContext, rulebook: RuleBook) -> Iterable[RuleMatch]:
    if not context.path:
        return []
    candidate = context.path.replace("/", "")
    if len(candidate) < 16:
        return []
    try:
        base64.b64decode(candidate + "==", validate=True)
    except Exception:  # noqa: BLE001
        pass
    else:
        return [rulebook.make_match("base64_path", "URL path looks like base64-encoded payload")]
    if re.search(r"[A-Za-z0-9+/]{32,}={0,2}", candidate):
        return [rulebook.make_match("base64_path", "URL path resembles base64 data")]
    return []


def _path_keywords(context: URLContext, rulebook: RuleBook) -> Iterable[RuleMatch]:
    path = context.path.lower()
    for keyword in PATH_KEYWORDS:
        if keyword in path:
            return [
                rulebook.make_match(
                    "sensitive_path_keyword",
                    f"Path contains sensitive keyword '{keyword}'",
                )
            ]
    return []


def _typosquat(context: URLContext, rulebook: RuleBook) -> Iterable[RuleMatch]:
    host = context.host
    if not host:
        return []
    host = host.lower()
    labels = host.split(".")
    domain_candidate = ".".join(labels[-2:]) if len(labels) >= 2 else host
    sld = labels[-2] if len(labels) >= 2 else labels[0]
    domain_candidates: Set[str] = {host, domain_candidate}
    segment_candidates: Set[str] = {sld}
    segment_candidates.update(part for part in re.split(r"[-_]", sld) if part)

    hits: List[RuleMatch] = []
    for brand in BRAND_DOMAINS:
        brand_lower = brand.lower()
        brand_sld = brand_lower.split(".")[0]
        evidence = None
        distance = None
        for candidate in domain_candidates:
            distance = _levenshtein(candidate, brand_lower)
            if 0 < distance <= 2:
                evidence = candidate
                break
        if evidence is None:
            for candidate in segment_candidates:
                distance = _levenshtein(candidate, brand_sld)
                if 0 < distance <= 2:
                    evidence = candidate
                    break
        if evidence is not None and distance is not None:
            hits.append(
                rulebook.make_match(
                    "typosquat",
                    f"Hostname resembles {brand} (distance {distance})",
                    evidence=evidence,
                )
            )
    return hits


def _levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein distance between two strings."""

    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (char_a != char_b)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


_URL_RULES = (
    _punycode_and_homograph,
    _host_is_ip,
    _has_at_symbol,
    _many_subdomains,
    _suspicious_tld,
    _long_path,
    _base64_in_path,
    _path_keywords,
    _typosquat,
)
