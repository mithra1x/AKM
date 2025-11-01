"""Command-line interface for DoubleThink."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .html_analyzer import analyze_html
from .reporting import format_table, to_json, write_report
from .rules import AnalysisResult, RuleBook, default_rulebook, load_rulebook
from .url_analyzer import analyze_url

# Optional Rich console for pretty table output
try:
    from rich.console import Console  # type: ignore
except Exception:  # pragma: no cover
    Console = None  # type: ignore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Explainable URL & HTML analyzer")
    parser.add_argument("command", choices=["url", "file"], help="Analyze a URL or a local file")
    parser.add_argument("target", help="URL string or file path to analyze")
    parser.add_argument(
        "--rules",
        type=Path,
        default=None,
        help="Optional path to rules/weights.yml",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format for the CLI",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional path to write a JSON report",
    )
    parser.add_argument(
        "--origin",
        default=None,
        help="Expected origin domain for HTML analysis",
    )
    parser.add_argument("--verbose", action="store_true", help="Show extra evidence in table output")
    parser.add_argument("--version", action="version", version=f"DoubleThink {__version__}")
    return parser


def _load_rulebook(path: Path | None) -> RuleBook:
    if path:
        return load_rulebook(path)
    return default_rulebook()


def _dispatch(args: argparse.Namespace, rulebook: RuleBook) -> AnalysisResult:
    if args.command == "url":
        # analyze_url ancaq (target, rulebook) qəbul edirsə, bu sətiri olduğu kimi saxlayın.
        # Əgər verbose dəstəyi əlavə ediləcəksə: analyze_url(args.target, rulebook, verbose=args.verbose)
        return analyze_url(args.target, rulebook)
    if args.command == "file":
        file_path = Path(args.target)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        # analyze_html(verbose=...) dəstəkləyirsə, buraya verbose=args.verbose əlavə edə bilərsiniz.
        return analyze_html(file_path, rulebook, origin_domain=args.origin)
    raise ValueError(f"Unsupported command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        rulebook = _load_rulebook(args.rules)
        result = _dispatch(args, rulebook)
    except Exception as exc:  # noqa: BLE001
        parser.error(str(exc))
        return 2

    # Output
    if args.output == "json":
        output = to_json(result)
        print(output)
    else:
        # table output — Rich varsa, rəngli print; yoxdursa, sadə print
        table_renderable = format_table(result, verbose=args.verbose)
        if Console is not None:
            console = Console()
            console.print(table_renderable)
        else:
            # Fallback: format_table string qayıdırsa birbaşa çap ediləcək
            print(table_renderable)

    # Optional JSON report file
    if args.report:
        write_report(result, str(args.report))
        # İstifadəçiyə yazılan fayl yolunu da göstərək (Rich varsa vurğulu çıxar)
        msg = f"Report written: {Path(args.report).resolve()}"
        if Console is not None and args.output == "table":
            Console().print(f"[underline]{msg}[/]")
        else:
            print(msg)

    return 0


if __name__ == "__main__":
    sys.exit(main())
