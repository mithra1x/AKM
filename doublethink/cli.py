"""Command-line interface for DoubleThink with Rich visual output."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlparse

try:
    import typer
except ImportError:  # pragma: no cover - optional dependency for enhanced CLI
    typer = None  # type: ignore

try:
    from colorama import just_fix_windows_console
except ImportError:  # pragma: no cover - colorama optional in tests
    def just_fix_windows_console() -> None:  # type: ignore
        return None
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from . import __version__
from .html_analyzer import analyze_html
from .reporting import to_json, write_report
from .rules import AnalysisResult, RuleBook, RuleMatch, default_rulebook, load_rulebook
from .url_analyzer import analyze_url


app = typer.Typer(add_completion=False, help="Explainable URL & HTML analyzer.") if typer else None
console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Explainable URL & HTML analyzer")
    parser.add_argument(
        "command",
        choices=["url", "file"],
        help="Select analyzer target type.",
    )
    parser.add_argument("target", help="URL string or file path to analyze.")
    parser.add_argument("--rules", type=Path, default=None, help="Optional path to rules/weights.yml.")
    parser.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Choose between Rich table output or raw JSON.",
    )
    parser.add_argument("--report", type=Path, default=None, help="Write JSON report to this path.")
    parser.add_argument("--origin", default=None, help="Expected origin domain for HTML analysis.")
    parser.add_argument("--verbose", action="store_true", help="Show evidence details in the rules table.")
    parser.add_argument("--version", action="version", version=f"DoubleThink {__version__}")
    return parser


def _load_rulebook(path: Path | None) -> RuleBook:
    return load_rulebook(path) if path else default_rulebook()


def _severity_color(severity: str) -> str:
    mapping = {
        "critical": "bright_red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "informational": "cyan",
    }
    return mapping.get(severity.lower(), "white")


def _classify_weight(weight: int, rulebook: RuleBook) -> str:
    severity = "informational"
    for name, threshold in sorted(rulebook.thresholds.items(), key=lambda item: item[1]):
        if weight >= threshold:
            severity = name
    return severity


def _render_risk_meter(result: AnalysisResult, rulebook: RuleBook) -> None:
    severity = rulebook.classify(result.score)
    bar_length = 30
    filled = max(0, min(bar_length, round(result.score / rulebook.max_score * bar_length)))
    bar = "#" * filled + "-" * (bar_length - filled)
    color = _severity_color(severity)
    text = Text.assemble(
        ("Total Risk Score\n", "bold"),
        (f"{result.score}/{rulebook.max_score}\n", f"bold {color}"),
        (bar, f"bold {color}"),
    )
    console.print(Panel(text, border_style=color, title="Risk Meter", expand=False))


def _render_url_breakdown(target: str) -> None:
    if not _is_http_url(target):
        return
    parsed = urlparse(target)
    tree = Tree("[bold]URL Breakdown[/bold]", guide_style="cyan")
    tree.add(f"[cyan]Scheme[/cyan]: {parsed.scheme or '-'}")
    host_node = tree.add(f"[cyan]Host[/cyan]: {parsed.netloc or '-'}")
    path_node = host_node.add("[cyan]Path[/cyan]")
    if parsed.path:
        parts = [segment for segment in parsed.path.split("/") if segment]
        if not parts:
            path_node.add("/")
        else:
            for part in parts:
                path_node.add(part)
    else:
        path_node.add("/")
    query_node = host_node.add("[cyan]Query Parameters[/cyan]")
    if parsed.query:
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            display_value = value if value else '""'
            query_node.add(f"{key} = {display_value}")
    else:
        query_node.add("<none>")
    console.print(tree)


def _render_rules_table(result: AnalysisResult, rulebook: RuleBook, *, verbose: bool) -> None:
    table = Table(
        title="Triggered Rules",
        header_style="bold white",
        expand=True,
    )
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Title", style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Weight", justify="right")
    table.add_column("Message", style="white")
    table.add_column("Evidence", style="dim")

    if not result.matches:
        console.print(Panel("No rules were triggered.", title="Rules", border_style="green"))
        return

    for match in sorted(result.matches, key=lambda item: item.weight, reverse=True):
        severity = _classify_weight(match.weight, rulebook)
        color = _severity_color(severity)
        evidence = match.evidence or "—"
        if not verbose and match.evidence:
            evidence = "(enable --verbose to show evidence)"
        table.add_row(
            match.rule_id,
            match.title,
            f"[{color}]{severity.upper()}[/]",
            str(match.weight),
            match.message,
            evidence,
        )

    console.print(table)


def _render_rule_weight_chart(matches: Iterable[RuleMatch]) -> None:
    matches = list(matches)
    if not matches:
        return
    total_weight = max(sum(match.weight for match in matches), 1)
    width = 28
    lines = []
    for match in sorted(matches, key=lambda item: item.weight, reverse=True):
        share = match.weight / total_weight
        filled = max(1, int(round(share * width)))
        bar = "|" * filled
        padding = " " * (width - filled)
        lines.append(f"{match.rule_id:<18} [{share*100:5.1f}%] |{bar}{padding}|")
    body = "\n".join(lines)
    console.print(Panel(body, title="Rule Weight Share", border_style="blue", expand=False))


def _render_metadata(result: AnalysisResult) -> None:
    if not result.metadata:
        return
    table = Table(title="Metadata", header_style="bold white", show_edge=False)
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    for key, value in result.metadata.items():
        table.add_row(key, str(value))
    console.print(table)


def _display_rich_report(result: AnalysisResult, rulebook: RuleBook, *, verbose: bool) -> None:
    console.print(Align.center(Text(f"DoubleThink v{__version__}", style="bold magenta")))
    console.print()
    _render_risk_meter(result, rulebook)
    console.print()
    _render_url_breakdown(result.target)
    console.print()
    _render_rules_table(result, rulebook, verbose=verbose)
    console.print()
    _render_rule_weight_chart(result.matches)
    console.print()
    _render_metadata(result)


def _is_http_url(text: str) -> bool:
    """Return True if the provided text looks like an HTTP(S) URL."""
    try:
        parsed = urlparse(text)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _dispatch(args: argparse.Namespace, rulebook: RuleBook) -> AnalysisResult:
    if args.command == "url":
        if not _is_http_url(args.target):
            raise ValueError("Target must be an HTTP/HTTPS URL when using the 'url' command.")
        return analyze_url(args.target, rulebook)
    if args.command == "file":
        if _is_http_url(args.target):
            raise ValueError("Target appears to be a URL; use the 'url' command instead.")
        file_path = Path(args.target)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        return analyze_html(file_path, rulebook, origin_domain=args.origin)
    raise ValueError(f"Unsupported command: {args.command}")


if typer:

    @app.command(help="Analyze an HTTP or HTTPS URL.")
    def url(  # type: ignore[misc]
        target: str = typer.Argument(..., help="URL to analyze."),
        rules: Path | None = typer.Option(None, "--rules", help="Optional path to a rules file."),
        output: str = typer.Option(
            "table",
            "--output",
            "-o",
            help="Select output format.",
            show_default=True,
            metavar="[table|json]",
            rich_help_panel="Output",
            type=typer.Choice(["table", "json"], case_sensitive=False),
        ),
        report: Path | None = typer.Option(None, "--report", help="Write JSON report to this path."),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Show evidence in the rules table."),
    ) -> None:
        rulebook = _load_rulebook(rules)
        args = argparse.Namespace(command="url", target=target)
        result = _dispatch(args, rulebook)
        _emit_result(result, rulebook, output=output, report=report, verbose=verbose)


    @app.command(help="Analyze a local HTML file.")
    def file(  # type: ignore[misc]
        target: Path = typer.Argument(..., exists=True, readable=True, help="Path to the HTML file."),
        origin: str | None = typer.Option(None, "--origin", help="Expected origin domain for off-site checks."),
        rules: Path | None = typer.Option(None, "--rules", help="Optional path to a rules file."),
        output: str = typer.Option(
            "table",
            "--output",
            "-o",
            help="Select output format.",
            show_default=True,
            metavar="[table|json]",
            rich_help_panel="Output",
            type=typer.Choice(["table", "json"], case_sensitive=False),
        ),
        report: Path | None = typer.Option(None, "--report", help="Write JSON report to this path."),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Show evidence in the rules table."),
    ) -> None:
        rulebook = _load_rulebook(rules)
        args = argparse.Namespace(command="file", target=str(target), origin=origin)
        result = _dispatch(args, rulebook)
        _emit_result(result, rulebook, output=output, report=report, verbose=verbose)


def _emit_result(
    result: AnalysisResult,
    rulebook: RuleBook,
    *,
    output: str,
    report: Path | None,
    verbose: bool,
) -> None:
    format_choice = output.lower()
    if format_choice == "json":
        console.print(to_json(result))
    else:
        _display_rich_report(result, rulebook, verbose=verbose)
    if report:
        write_report(result, str(report))
        console.print(f"Report written to [underline]{Path(report).resolve()}[/]")


def main(argv: list[str] | None = None) -> int:
    just_fix_windows_console()
    if typer and app is not None:
        command = typer.main.get_command(app)
        try:
            command.main(args=argv, prog_name="doublethink", standalone_mode=False)
        except SystemExit as exc:  # pragma: no cover - Click raises SystemExit
            return int(exc.code or 0)
        return 0

    parser = build_parser()
    parsed_args = parser.parse_args(argv)
    try:
        rulebook = _load_rulebook(parsed_args.rules)
        result = _dispatch(parsed_args, rulebook)
    except Exception as exc:  # noqa: BLE001
        parser.error(str(exc))
        return 2

    _emit_result(
        result,
        rulebook,
        output=parsed_args.output,
        report=parsed_args.report,
        verbose=parsed_args.verbose,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
