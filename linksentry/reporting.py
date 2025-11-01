"""Output helpers for LinkSentry."""
from __future__ import annotations

import json
from typing import Iterable

from .rules import AnalysisResult, RuleMatch


def result_to_dict(result: AnalysisResult) -> dict:
    return {
        "target": result.target,
        "score": result.score,
        "severity": result.severity,
        "metadata": result.metadata,
        "matches": [match_to_dict(match) for match in result.matches],
    }


def match_to_dict(match: RuleMatch) -> dict:
    payload = {
        "rule_id": match.rule_id,
        "title": match.title,
        "description": match.description,
        "weight": match.weight,
        "message": match.message,
    }
    if match.evidence:
        payload["evidence"] = match.evidence
    return payload


def format_table(result: AnalysisResult, verbose: bool = False) -> str:
    lines = [f"Target : {result.target}", f"Score  : {result.score} ({result.severity})"]
    if result.matches:
        lines.append("\nTriggered rules:")
        for match in result.matches:
            base = f"- [{match.weight}] {match.title}: {match.message}"
            if verbose and match.evidence:
                base += f" (evidence: {match.evidence})"
            lines.append(base)
    else:
        lines.append("No rules triggered.")
    if verbose and result.metadata:
        lines.append("\nMetadata:")
        for key, value in result.metadata.items():
            lines.append(f"  {key}: {value}")
    return "\n".join(lines)


def to_json(result: AnalysisResult) -> str:
    return json.dumps(result_to_dict(result), indent=2)


def write_report(result: AnalysisResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result_to_dict(result), handle, indent=2)
