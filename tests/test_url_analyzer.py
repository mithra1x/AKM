from pathlib import Path

import pytest

from linksentry.rules import default_rulebook
from linksentry.url_analyzer import analyze_url


@pytest.fixture(scope="module")
def rulebook():
    return default_rulebook()


def test_punycode_detection(rulebook):
    result = analyze_url("https://xn--80ak6aa92e.com/", rulebook)
    rule_ids = {match.rule_id for match in result.matches}
    assert "punycode_hostname" in rule_ids
    assert result.score >= 70


def test_typosquat_detection(rulebook):
    result = analyze_url("https://accounts-g00gle.com/login", rulebook)
    rule_ids = {match.rule_id for match in result.matches}
    assert "typosquat" in rule_ids
    assert "sensitive_path_keyword" in rule_ids
    assert result.score >= 55


def test_ip_host(rulebook):
    result = analyze_url("http://192.168.0.15/login", rulebook)
    rule_ids = {match.rule_id for match in result.matches}
    assert "ip_host" in rule_ids


def test_suspicious_tld(rulebook):
    result = analyze_url("https://contoso.attacker.click/", rulebook)
    rule_ids = {match.rule_id for match in result.matches}
    assert "suspicious_tld" in rule_ids


def test_base64_path(rulebook):
    payload = "https://example.com/" + "aGVsbG93b3JsZGFz"  # base64("hellowordfas")
    result = analyze_url(payload, rulebook)
    rule_ids = {match.rule_id for match in result.matches}
    assert "base64_path" in rule_ids
