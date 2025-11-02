"""Textual TUI for viewing DoubleThink analysis results."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .rules import AnalysisResult, RuleMatch

try:  # pragma: no cover - import guard for optional UI dependency
    from textual.app import App, ComposeResult
    from textual.containers import Container, Horizontal, VerticalScroll
    from textual.widgets import DataTable, Footer, Header, Input, Static, TabbedContent, TabPane
except Exception as exc:  # pragma: no cover - propagate for caller to handle
    raise RuntimeError("Textual dependency is required to render the interactive TUI") from exc


@dataclass
class _RuleRow:
    """Helper data structure for table rows."""

    key: str
    match: RuleMatch


def _severity_style(severity: str) -> str:
    mapping = {
        "critical": "bold red",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "bold green",
        "informational": "bold cyan",
    }
    return mapping.get(severity.lower(), "bold white")


class DoubleThinkReportApp(App[None]):
    """Interactive report viewer built with Textual."""

    CSS = """
    Screen {
        layout: vertical;
    }

    #tabs {
        height: 1fr;
    }

    #overview-panel, #meta-panel, #rules-layout {
        padding: 1;
    }

    #rules-layout {
        layout: vertical;
        gap: 1;
    }

    #rules-panels {
        layout: horizontal;
        gap: 1;
        height: 1fr;
    }

    #left-panel {
        width: 45%;
    }

    #rules-table, #rule-details {
        height: 1fr;
    }

    #rule-details Static {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("f", "focus_search", "Focus search"),
    ]

    def __init__(self, result: AnalysisResult) -> None:
        super().__init__()
        self._result = result
        self._all_rows: List[_RuleRow] = []

    def compose(self) -> ComposeResult:  # noqa: D401 - textual protocol
        overview = Static(self._build_overview_panel(), id="overview-panel")
        meta = Static(self._build_metadata_panel(), id="meta-panel")

        rules_tab = Container(
            Input(placeholder="Search title, id or message…", id="search"),
            Horizontal(
                Container(DataTable(id="rules-table"), id="left-panel"),
                Container(
                    VerticalScroll(Static(id="rule-details")),
                    id="right-panel",
                ),
            id="rules-panels",
            ),
            id="rules-layout",
        )

        yield Header(show_clock=False)
        yield TabbedContent(
            TabPane("Overview", overview),
            TabPane("Rules", rules_tab, id="rules-tab"),
            TabPane("Metadata", meta),
            id="tabs",
        )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#rules-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("ID", "Title", "Weight", "Message")
        self._all_rows = [
            _RuleRow(key=f"rule-{index}", match=match)
            for index, match in enumerate(self._result.matches)
        ]
        self._populate_table(self._all_rows)
        if self._all_rows:
            self._select_row(self._all_rows[0].key)
            self._update_detail(self._all_rows[0].match)
        else:
            self._clear_detail("No rules were triggered.")

    def _build_overview_panel(self) -> Panel:
        table = Table.grid(padding=(0, 1))
        table.add_row("Target", Text(self._result.target, style="bold"))
        table.add_row(
            "Score",
            Text(f"{self._result.score} ({self._result.severity})", style=_severity_style(self._result.severity)),
        )
        table.add_row("Matches", str(len(self._result.matches)))
        return Panel(table, title="Analysis Overview", border_style="cyan")

    def _build_metadata_panel(self) -> Panel:
        if not self._result.metadata:
            return Panel(Text("No metadata provided.", style="dim"), title="Metadata", border_style="blue")
        table = Table.grid(padding=(0, 1))
        for key, value in self._result.metadata.items():
            table.add_row(Text(key, style="bold"), Text(str(value)))
        return Panel(table, title="Metadata", border_style="blue")

    def _populate_table(self, rows: Iterable[_RuleRow]) -> None:
        table = self.query_one("#rules-table", DataTable)
        table.clear(columns=False)
        for row in rows:
            match = row.match
            table.add_row(match.rule_id, match.title, str(match.weight), match.message, key=row.key)
        if table.row_count:
            table.move_cursor(row=0, column=0)
        else:
            self._clear_detail("No rules available.")

    def _select_row(self, key: str) -> None:
        table = self.query_one("#rules-table", DataTable)
        if table.row_count == 0:
            return
        for row_index, row_key in enumerate(table.rows.keys()):
            if row_key == key:
                table.move_cursor(row=row_index, column=0)
                table.action_select_cursor()
                break

    def _update_detail(self, match: RuleMatch) -> None:
        detail_table = Table.grid(padding=(0, 1))
        detail_table.add_row("Rule", Text(match.title, style="bold"))
        detail_table.add_row("Identifier", match.rule_id)
        detail_table.add_row("Weight", str(match.weight))
        detail_table.add_row("Description", match.description)
        detail_table.add_row("Message", match.message)
        if match.evidence:
            detail_table.add_row("Evidence", match.evidence)

        panel = Panel(detail_table, title="Rule details", border_style="magenta")
        self.query_one("#rule-details", Static).update(panel)

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "search":
            return
        term = event.value.strip().lower()
        if not term:
            filtered = self._all_rows
        else:
            filtered = [
                row
                for row in self._all_rows
                if term in row.match.rule_id.lower()
                or term in row.match.title.lower()
                or term in row.match.message.lower()
                or (row.match.evidence or "").lower().find(term) >= 0
            ]
        self._populate_table(filtered)
        if filtered:
            self._update_detail(filtered[0].match)
        else:
            self._clear_detail("No matches for current filter.")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:  # noqa: D401 - textual hook
        key = event.row_key.value if event.row_key else None
        if key is None:
            return
        for row in self._all_rows:
            if row.key == key:
                self._update_detail(row.match)
                break

    def _clear_detail(self, message: str) -> None:
        panel = Panel(Text(message, style="dim"), title="Rule details", border_style="magenta")
        self.query_one("#rule-details", Static).update(panel)


def run_textual_report(result: AnalysisResult) -> None:
    """Run the Textual application to display an analysis result."""

    app = DoubleThinkReportApp(result)
    app.run()
