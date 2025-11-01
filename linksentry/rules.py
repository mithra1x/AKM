"""Rule loading and scoring helpers for LinkSentry."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:  # pragma: no cover - tiny import guard
    import yaml  # type: ignore
except Exception:  # noqa: BLE001 - gracefully handle missing dependency
    yaml = None


@dataclass
class RuleDefinition:
    """Static configuration for a detection rule."""

    rule_id: str
    title: str
    description: str
    weight: int


@dataclass
class RuleMatch:
    """Runtime information for a triggered rule."""

    rule_id: str
    title: str
    description: str
    weight: int
    message: str
    evidence: Optional[str] = None


@dataclass
class AnalysisResult:
    """Aggregate output from an analyzer."""

    target: str
    score: int
    severity: str
    matches: List[RuleMatch]
    metadata: Dict[str, str]


class RuleBook:
    """Holds rule definitions and handles scoring."""

    def __init__(self, rules: Dict[str, RuleDefinition], max_score: int, thresholds: Dict[str, int]):
        self._rules = rules
        self.max_score = max_score
        self.thresholds = thresholds

    def make_match(self, rule_id: str, message: str, evidence: Optional[str] = None) -> RuleMatch:
        if rule_id not in self._rules:
            raise KeyError(f"Unknown rule_id: {rule_id}")
        rule = self._rules[rule_id]
        return RuleMatch(
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            weight=rule.weight,
            message=message,
            evidence=evidence,
        )

    def score(self, matches: Iterable[RuleMatch]) -> int:
        total = sum(match.weight for match in matches)
        return min(total, self.max_score)

    def classify(self, score: int) -> str:
        levels = sorted(self.thresholds.items(), key=lambda item: item[1])
        severity = "informational"
        for name, threshold in levels:
            if score >= threshold:
                severity = name
        return severity

    def to_dict(self) -> Dict[str, Dict[str, int]]:
        return {
            "rules": {rule_id: rule.weight for rule_id, rule in self._rules.items()},
            "thresholds": self.thresholds,
            "max_score": self.max_score,
        }


def load_rulebook(path: Path) -> RuleBook:
    """Load a :class:`RuleBook` from a YAML file."""

    raw = _load_yaml(path)

    rules = {
        rule_id: RuleDefinition(
            rule_id=rule_id,
            title=payload["title"],
            description=payload.get("description", payload["title"]),
            weight=int(payload.get("weight", 0)),
        )
        for rule_id, payload in raw["rules"].items()
    }
    scoring = raw.get("scoring", {})
    max_score = int(scoring.get("max_score", 100))
    thresholds = scoring.get(
        "thresholds",
        {"low": 20, "medium": 40, "high": 60, "critical": 80},
    )
    return RuleBook(rules, max_score=max_score, thresholds=thresholds)


def default_rulebook() -> RuleBook:
    """Load the default rule configuration bundled with the project."""

    root = Path(__file__).resolve().parents[1]
    rules_path = root / "rules" / "weights.yml"
    return load_rulebook(rules_path)


def _load_yaml(path: Path) -> Dict[str, dict]:
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        return yaml.safe_load(text)
    return _parse_simple_yaml(text)


def _parse_simple_yaml(text: str) -> Dict[str, dict]:
    """Parse a minimal YAML subset for fallback operation."""

    result: Dict[str, dict] = {}
    current_section: Optional[str] = None
    current_subsection: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        key, value = _split_key_value(line)
        if indent == 0:
            current_section = key
            result.setdefault(current_section, {})
            current_subsection = None
        elif indent == 2 and value == "":
            if current_section is None:
                raise ValueError("Invalid YAML structure: subsection without section")
            current_subsection = key
            section = result.setdefault(current_section, {})
            section.setdefault(current_subsection, {})
        elif indent == 2:
            if current_section is None:
                raise ValueError("Invalid YAML structure: value without section")
            section = result.setdefault(current_section, {})
            section[key] = _coerce_yaml_value(value)
        elif indent == 4:
            if current_section is None or current_subsection is None:
                raise ValueError("Invalid YAML structure: nested value without context")
            subsection = result.setdefault(current_section, {}).setdefault(current_subsection, {})
            subsection[key] = _coerce_yaml_value(value)
    return result


def _split_key_value(line: str) -> tuple[str, str]:
    if ":" not in line:
        raise ValueError(f"Invalid YAML line: {line}")
    key, value = line.split(":", 1)
    return key.strip(), value.strip()


def _coerce_yaml_value(value: str):
    if value == "":
        return ""
    if value.isdigit():
        return int(value)
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if (value.startswith("\"") and value.endswith("\"")) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value
