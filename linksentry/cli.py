"""Command-line interface for LinkSentry."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .html_analyzer import analyze_html
from .reporting import format_table, to_json, write_report
from .rules import AnalysisResult, RuleBook, default_rulebook, load_rulebook
from .url_analyzer import analyze_url


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
    parser.add_argument("--version", action="version", version=f"LinkSentry {__version__}")
    return parser


def _load_rulebook(path: Path | None) -> RuleBook:
    if path:
        return load_rulebook(path)
    return default_rulebook()


def _dispatch(args: argparse.Namespace, rulebook: RuleBook) -> AnalysisResult:
    if args.command == "url":
        return analyze_url(args.target, rulebook)
    if args.command == "file":
        file_path = Path(args.target)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
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

    if args.output == "json":
        output = to_json(result)
    else:
        output = format_table(result, verbose=args.verbose)

    print(output)

    if args.report:
        write_report(result, str(args.report))

    return 0


if __name__ == "__main__":
    sys.exit(main())
