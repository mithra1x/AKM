from pathlib import Path

import pytest

from linksentry.html_analyzer import analyze_html, infer_origin_domain
from linksentry.rules import default_rulebook


@pytest.fixture(scope="module")
def rulebook():
    return default_rulebook()


def test_infer_origin_meta():
    html = """
    <html><head><meta name=\"origin-domain\" content=\"example.com\"></head></html>
    """
    assert infer_origin_domain(html) == "example.com"


def test_hidden_inputs(tmp_path, rulebook):
    path = tmp_path / "hidden.html"
    path.write_text("<form><input type='hidden' name='token'></form>", encoding="utf-8")
    result = analyze_html(path, rulebook)
    rule_ids = {match.rule_id for match in result.matches}
    assert "hidden_inputs" in rule_ids


def test_form_action_offsite(tmp_path, rulebook):
    html = """
    <html>
      <head><meta name=\"origin-domain\" content=\"example.com\"></head>
      <body>
        <form method=\"post\" action=\"https://evil.example.net/login\"></form>
      </body>
    </html>
    """
    path = tmp_path / "form.html"
    path.write_text(html, encoding="utf-8")
    result = analyze_html(path, rulebook)
    rule_ids = {match.rule_id for match in result.matches}
    assert "form_action_offsite" in rule_ids


def test_obfuscated_js(tmp_path, rulebook):
    html = "<script>eval(atob('ZGF0YQ=='))</script>"
    path = tmp_path / "script.html"
    path.write_text(html, encoding="utf-8")
    result = analyze_html(path, rulebook)
    rule_ids = {match.rule_id for match in result.matches}
    assert "obfuscated_js" in rule_ids


def test_phishing_keywords(tmp_path, rulebook):
    html = "<p>Please verify your account password</p>"
    path = tmp_path / "keywords.html"
    path.write_text(html, encoding="utf-8")
    result = analyze_html(path, rulebook)
    rule_ids = {match.rule_id for match in result.matches}
    assert "phishing_keywords" in rule_ids
