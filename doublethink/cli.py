"""Command-line interface for DoubleThink."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .html_analyzer import analyze_html
from .reporting import format_table, to_json, write_report
from .rules import AnalysisResult, RuleBook, default_rulebook, load_rulebook
from .url_analyzer import analyze_url

# Optional Rich & Figlet
try:
    from rich.console import Console  # type: ignore
    from rich.text import Text        # type: ignore
    from rich.align import Align      # type: ignore
except Exception:  # pragma: no cover
    Console = None  # type: ignore
    Text = None     # type: ignore
    Align = None    # type: ignore

try:
    from pyfiglet import Figlet  # type: ignore
except Exception:  # pragma: no cover
    Figlet = None  # type: ignore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Explainable URL & HTML analyzer")
    parser.add_argument("command", choices=["url", "file"], help="Analyze a URL or a local file")
    parser.add_argument("target", help="URL string or file path to analyze")
    parser.add_argument("--rules", type=Path, default=None, help="Optional path to rules/weights.yml")
    parser.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--report", type=Path, default=None, help="Optional path to write a JSON report")
    parser.add_argument("--origin", default=None, help="Expected origin domain for HTML analysis")
    parser.add_argument("--verbose", action="store_true", help="Show extra evidence in table output")
    parser.add_argument("--version", action="version", version=f"DoubleThink {__version__}")
    return parser


def _load_rulebook(path: Path | None) -> RuleBook:
    return load_rulebook(path) if path else default_rulebook()


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


# ===================== Banner + Interactive =====================
def _print_banner() -> None:
    """Color ASCII banner with chosen font and author."""
    if Console is None:
        print("\n==== DOUBLETHINK ====")
        return

    console = Console()
    art = None
    if Figlet is not None:
        # Try different fonts in order of preference.
        for f in ("slant", "ansi_shadow", "block", "standard"):
            try:
                art = Figlet(font=f).renderText("DOUBLETHINK")
                break
            except Exception:
                art = None

    if art and Text is not None:
        t = Text(art)
        t.stylize("bold")
        try:
            t.apply_gradient("#00e0ff", "#8be9fd")
        except Exception:
            pass
        console.print(t)
    else:
        console.print("[bold cyan]DOUBLETHINK[/]")

    if Align is not None and Text is not None:
        console.print(Align.center(Text("Version 1.0", style="bold white")))
        console.print(Align.right(Text("By: mithra", style="bold magenta")))

def _interactive_run() -> int:
    """Run when user types just `doublethink` with no args."""
    _print_banner()

    # Menu
    if Console is not None:
        console = Console()
        console.print("\nPlease Choose:")
        console.print("[1] URL\n[2] FILE")
        choice = console.input("\n[bold]Enter here:[/] ").strip() or "1"
    else:
        print("\nPlease Choose:\n[1] URL\n[2] FILE")
        choice = input("\nEnter here: ").strip() or "1"

    if choice == "2":
        command = "file"; prompt = "Enter file path: "
    else:
        command = "url";  prompt = "Enter URL: "

    target = (console.input(prompt) if Console is not None else input(prompt)).strip()

    # Analyze
    try:
        rulebook = _load_rulebook(None)
        if command == "url":
            if not _is_http_url(target):
                raise ValueError("Type mismatch: provide an HTTP/HTTPS address for URL mode.")
            result = analyze_url(target, rulebook)
        else:
            if _is_http_url(target):
                raise ValueError("Type mismatch: provide a local file path for file mode.")
            fp = Path(target)
            if not fp.exists():
                (console.print(f"[red]File not found:[/] {fp}") if Console is not None else print(f"File not found: {fp}"))
                return 2
            result = analyze_html(fp, rulebook, origin_domain=None)
    except Exception as exc:  # noqa: BLE001
        (console.print(f"[red]Error:[/] {exc}") if Console is not None else print(f"Error: {exc}"))
        return 2

    # Output (default: table pretty)
    renderable = format_table(result, verbose=True)
    if Console is not None:
        try:
            console.print(renderable)
        except Exception:
            print(renderable)
    else:
        print(renderable)
    return 0
# ===============================================================


def main(argv: list[str] | None = None) -> int:
    # No args → interactive banner + menu
    if argv is None and len(sys.argv) <= 1:
        return _interactive_run()

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
        print(to_json(result))
    else:
        table_renderable = format_table(result, verbose=args.verbose)
        if Console is not None:
            console = Console()
            try:
                console.print(table_renderable)
            except Exception:
                print(table_renderable)
        else:
            print(table_renderable)

    # Optional report
    if args.report:
        write_report(result, str(args.report))
        msg = f"Report written: {Path(args.report).resolve()}"
        if Console is not None and args.output == "table":
            Console().print(f"[underline]{msg}[/]")
        else:
            print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
