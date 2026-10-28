"""Command-line interface for Last Signal using Typer and Rich."""

import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

from lastsignal import __version__
from lastsignal.detector import detect_failures
from lastsignal.report import (
    ReportExportError,
    export_markdown_report,
    format_terminal_report,
)
from lastsignal.trace_reader import TraceError, read_trace

app = typer.Typer(
    name="lastsignal",
    help="Last Signal: Forensic investigation CLI for failed AI-agent executions.",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


@app.command(name="analyze")
def analyze(
    trace_path: Path = typer.Argument(
        ...,
        help="Path to JSONL execution trace file to analyze.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional destination path for exported Markdown autopsy report.",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable ANSI colors and terminal styling.",
    ),
):
    """Analyze an AI-agent trace file and print forensic findings."""
    try:
        read_res = read_trace(trace_path)
    except TraceError as exc:
        err_console.print(f"[bold red]Error reading trace:[/bold red] {exc}")
        raise typer.Exit(code=1)

    analysis = detect_failures(read_res.events)

    terminal_report = format_terminal_report(read_res, analysis, str(trace_path))
    if no_color:
        typer.echo(terminal_report)
    else:
        # Print with forensic green/amber aesthetic
        console.print(terminal_report)

    if output:
        try:
            saved_path = export_markdown_report(read_res, analysis, str(trace_path), output)
            console.print(f"\n[bold green][+] Markdown report exported to:[/bold green] {saved_path}")
        except ReportExportError as exc:
            err_console.print(f"\n[bold red][!] Export failed:[/bold red] {exc}")
            raise typer.Exit(code=1)

    # Return exit code 1 if failures or errors detected
    if analysis.has_failures or read_res.error_count > 0:
        raise typer.Exit(code=1)


@app.command(name="report")
def report(
    trace_path: Path = typer.Argument(
        ...,
        help="Path to JSONL execution trace file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        "-o",
        help="Destination path for Markdown autopsy report.",
    ),
):
    """Generate and export a Markdown investigation report for a trace file."""
    try:
        read_res = read_trace(trace_path)
    except TraceError as exc:
        err_console.print(f"[bold red]Error reading trace:[/bold red] {exc}")
        raise typer.Exit(code=1)

    analysis = detect_failures(read_res.events)

    try:
        saved_path = export_markdown_report(read_res, analysis, str(trace_path), output)
        console.print(f"[bold green][+] Forensic Markdown report written to:[/bold green] {saved_path}")
    except ReportExportError as exc:
        err_console.print(f"[bold red][!] Report export failed:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if analysis.has_failures or read_res.error_count > 0:
        raise typer.Exit(code=1)


@app.command(name="doctor")
def doctor():
    """Verify local environment and dependencies for Last Signal."""
    console.print("[bold cyan]=== LAST SIGNAL SYSTEM DIAGNOSTICS ===[/bold cyan]\n")
    console.print(f"[*] Last Signal Version: {__version__}")
    console.print(f"[*] Python Version:      {sys.version.split()[0]}")
    console.print(f"[*] Python Executable:   {sys.executable}")
    console.print("[+] Offline Core:        AVAILABLE (Parser, Detector, Reporter ready)")
    console.print("[-] Local Ollama:        NOT CONNECTED (Optional; deterministic mode active)")
    console.print("\n[bold green]Environment ready for offline trace investigation.[/bold green]")


def main():
    app()


if __name__ == "__main__":
    main()
