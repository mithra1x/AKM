# doublethink/output_rich.py
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
import json
import os

console = Console()

def score_to_severity(score: float) -> str:
    if score >= 75:
        return "high"   # red
    if score >= 40:
        return "medium" # yellow
    return "low"        # green

def severity_color(sev: str) -> str:
    return {"high": "red", "medium": "yellow", "low": "green"}[sev]

def render_score(score: float) -> None:
    sev = score_to_severity(score)
    color = severity_color(sev)
    txt = Text.assemble(
        ("Score: ", "bold"),
        (f"{score:.0f}", f"bold {color}"),
        (" — ", "dim"),
        (sev.upper(), f"bold {color}")
    )
    console.print(Panel(txt, expand=True))

def render_rules_table(rules: List[Dict[str, Any]], verbose: bool = False) -> None:
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("id", style="dim", width=8)
    table.add_column("title")
    table.add_column("weight", justify="right")
    table.add_column("reason")

    # Sort from highest to lowest weight.
    for r in sorted(rules, key=lambda x: float(x.get("weight", 0)), reverse=True):
        row_reason = r.get("reason", "")
        if verbose and r.get("evidence"):
            row_reason = f"{row_reason}\n[dim]{r['evidence']}[/dim]"
        table.add_row(str(r.get("id", "")), r.get("title", ""), str(r.get("weight", "")), row_reason)

    console.print(table)

def write_or_print_json(report: Dict[str, Any], path: Optional[str]) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        console.print(f"Report written: [underline]{os.path.abspath(path)}[/]")
    else:
        console.print_json(data=report)

def render_report(*, score: float, rules: List[Dict[str, Any]], meta: Dict[str, Any], report_path: Optional[str], verbose: bool) -> None:
    render_score(score)
    console.print("\n[bold underline]Rules-hit[/]\n")
    render_rules_table(rules, verbose=verbose)
    report_obj = {"score": score, "severity": score_to_severity(score), "rules_hit": rules, "meta": meta}
    console.print()
    write_or_print_json(report_obj, report_path)
