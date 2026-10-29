"""Command-line interface for Last Signal using Typer and Rich."""

import sys
import tempfile
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from lastsignal import __version__
from lastsignal.detector import detect_failures
from lastsignal.llm import (
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    OllamaClient,
    diagnose_with_local_ai,
)
from lastsignal.models import TraceEvent, TraceReadResult
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


def get_terminal_width(fallback: int = 80) -> int:
    """Determine safe terminal display width."""
    try:
        import shutil
        width = shutil.get_terminal_size((fallback, 24)).columns
        return max(50, min(width, 100))
    except Exception:
        return fallback


def build_startup_interface(width: Optional[int] = None) -> str:
    """Construct the Last Signal startup dashboard text.

    Formats branding, forensic description, untruncated commands,
    offline explanation, and copyable examples, adapting safely to terminal width.
    """
    w = width or get_terminal_width()
    sep = "=" * w
    sub_sep = "-" * w

    lines = [
        sep,
        f"LAST SIGNAL // FORENSIC INVESTIGATION CLI (v{__version__})",
        '"Ghost in the Machine" — Offline-First Digital Autopsy for AI Agents',
        sep,
        "",
        "Last Signal investigates failed AI-agent executions. It reconstructs recorded",
        "traces, detects failure patterns (repeated tool errors, unproductive retry",
        "loops, and unhandled terminal crashes), and produces evidence-grounded",
        "digital autopsy reports.",
        "",
        "REGISTERED COMMANDS:",
        sub_sep,
        "  analyze",
        "    Syntax:      lastsignal analyze <TRACE_FILE> [OPTIONS]",
        "    Description: Ingest trace, detect failure patterns, and display autopsy.",
        "    Example:     lastsignal analyze examples/repeated_tool_failure.jsonl",
        "",
        "  report",
        "    Syntax:      lastsignal report <TRACE_FILE> --output <PATH> [OPTIONS]",
        "    Description: Generate and export a Markdown autopsy report to destination file.",
        "    Example:     lastsignal report examples/repeated_tool_failure.jsonl -o reports/autopsy.md",
        "",
        "  doctor",
        "    Syntax:      lastsignal doctor [OPTIONS]",
        "    Description: Verify local environment, report file write, and Ollama status.",
        "    Example:     lastsignal doctor",
        "",
        "  help",
        "    Syntax:      lastsignal help [COMMAND]",
        "    Description: Show available commands and detailed usage reference.",
        "    Example:     lastsignal help analyze",
        "",
        "OFFLINE & DETERMINISTIC ANALYSIS:",
        sub_sep,
        "  Last Signal is 100% offline-first. Deterministic failure detection and report",
        "  export run without external network access or local LLM inference.",
        "  To enforce purely deterministic analysis without contacting Ollama:",
        "    lastsignal analyze <TRACE_FILE> --no-ai",
        "",
        "COMMON FLAGS & OPTIONS:",
        sub_sep,
        "  --no-ai               Run 100% offline deterministic rules (no LLM calls).",
        "  --output, -o <PATH>   Export forensic autopsy report to a Markdown (.md) file.",
        "  --model, -m <NAME>    Configure local Ollama model (default: llama3.2:latest).",
        "  --ollama-url <URL>    Configure local Ollama daemon endpoint (default: http://localhost:11434).",
        "  --no-color            Disable terminal ANSI color formatting.",
        "",
        "QUICK START:",
        sub_sep,
        "  1. Run diagnostics:        lastsignal doctor",
        "  2. Run sample analysis:    lastsignal analyze examples/repeated_tool_failure.jsonl",
        "  3. Force offline analysis: lastsignal analyze examples/repeated_tool_failure.jsonl --no-ai",
        "  4. Export Markdown report: lastsignal report examples/repeated_tool_failure.jsonl -o reports/autopsy.md",
        sep,
    ]
    return "\n".join(lines)


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable ANSI colors and terminal styling.",
    ),
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show Last Signal version and exit.",
    ),
):
    """Last Signal: Forensic investigation CLI for failed AI-agent executions."""
    if version:
        typer.echo(f"Last Signal v{__version__}")
        raise typer.Exit(code=0)

    # When lastsignal is run with no arguments, launch startup interface
    if ctx.invoked_subcommand is None:
        startup_text = build_startup_interface()
        if no_color or os.environ.get("NO_COLOR"):
            typer.echo(startup_text)
        else:
            console.print(startup_text)
        raise typer.Exit(code=0)


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
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Skip all local LLM calls and perform deterministic trace analysis only.",
    ),
    model: str = typer.Option(
        DEFAULT_OLLAMA_MODEL,
        "--model",
        "-m",
        help="Name of local Ollama model to use for grounded diagnosis.",
    ),
    ollama_url: str = typer.Option(
        DEFAULT_OLLAMA_URL,
        "--ollama-url",
        help="Base URL for local Ollama daemon.",
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

    # 1. Deterministic failure detection (immutable ground truth)
    analysis = detect_failures(read_res.events)

    # 2. Local AI interpretation (strictly optional, with graceful fallback)
    ai_diag = diagnose_with_local_ai(
        report=analysis,
        events=read_res.events,
        base_url=ollama_url,
        model=model,
        disabled=no_ai,
    )
    analysis.ai_diagnosis = ai_diag

    # 3. Format terminal report
    terminal_report = format_terminal_report(read_res, analysis, str(trace_path))
    if no_color:
        typer.echo(terminal_report)
    else:
        console.print(terminal_report)

    # 4. Optional Markdown export
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
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Skip local LLM inference in the exported report.",
    ),
    model: str = typer.Option(
        DEFAULT_OLLAMA_MODEL,
        "--model",
        "-m",
        help="Name of local Ollama model to use for grounded diagnosis.",
    ),
    ollama_url: str = typer.Option(
        DEFAULT_OLLAMA_URL,
        "--ollama-url",
        help="Base URL for local Ollama daemon.",
    ),
):
    """Generate and export a Markdown investigation report for a trace file."""
    try:
        read_res = read_trace(trace_path)
    except TraceError as exc:
        err_console.print(f"[bold red]Error reading trace:[/bold red] {exc}")
        raise typer.Exit(code=1)

    analysis = detect_failures(read_res.events)

    # Local AI diagnosis
    ai_diag = diagnose_with_local_ai(
        report=analysis,
        events=read_res.events,
        base_url=ollama_url,
        model=model,
        disabled=no_ai,
    )
    analysis.ai_diagnosis = ai_diag

    try:
        saved_path = export_markdown_report(read_res, analysis, str(trace_path), output)
        console.print(f"[bold green][+] Forensic Markdown report written to:[/bold green] {saved_path}")
    except ReportExportError as exc:
        err_console.print(f"[bold red][!] Report export failed:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if analysis.has_failures or read_res.error_count > 0:
        raise typer.Exit(code=1)


@app.command(name="doctor")
def doctor(
    ollama_url: str = typer.Option(
        DEFAULT_OLLAMA_URL,
        "--ollama-url",
        help="Base URL of local Ollama instance to test.",
    ),
    model: str = typer.Option(
        DEFAULT_OLLAMA_MODEL,
        "--model",
        "-m",
        help="Target local model to verify.",
    ),
):
    """Verify local environment, report generation, and Ollama connectivity."""
    console.print("[bold cyan]=== LAST SIGNAL SYSTEM DIAGNOSTICS ===[/bold cyan]\n")

    # 1. Environment & Core
    console.print(f"[*] Last Signal Version: {__version__}")
    console.print(f"[*] Python Version:      {sys.version.split()[0]}")
    console.print(f"[*] Python Executable:   {sys.executable}")
    console.print("[bold green][+] Core Engine:[/bold green]         READY (Trace reader & deterministic detector)")

    # 2. Markdown Export Check
    can_export = False
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_target = Path(tmp_dir) / "test_report.md"
            sample_read = TraceReadResult(
                events=[TraceEvent(line_number=1, event_type="agent_start", status="started")],
                total_lines=1,
            )
            sample_analysis = detect_failures(sample_read.events)
            export_markdown_report(sample_read, sample_analysis, "test.jsonl", tmp_target)
            if tmp_target.exists():
                can_export = True
    except Exception as exc:
        can_export = False

    if can_export:
        console.print("[bold green][+] Report Exporter:     READY (File system write & directory creation verified)[/bold green]")
    else:
        console.print("[bold red][-] Report Exporter:     FAILED (File system write issue)[/bold red]")

    # 3. Local Ollama Connectivity & Model Check
    client = OllamaClient(base_url=ollama_url, model=model, connect_timeout=2.0)
    connected, version_or_err = client.check_connectivity()

    if connected:
        console.print(f"[bold green][+] Local Ollama:        ONLINE (Daemon v{version_or_err} at {client.base_url})[/bold green]")
        models = client.list_models()
        if models:
            console.print(f"[*] Installed Models:   {', '.join(models)}")
        else:
            console.print("[!] Installed Models:   None found in local library")

        available, _ = client.is_model_available(model)
        if available:
            console.print(f"[bold green][+] Target Model:        READY ('{model}' available for local inference)[/bold green]")
        else:
            console.print(f"[bold yellow][-] Target Model:        NOT FOUND ('{model}' not installed; run 'ollama pull {model}')[/bold yellow]")
    else:
        console.print(f"[bold yellow][-] Local Ollama:        OFFLINE ({version_or_err})[/bold yellow]")
        console.print("    [dim]Deterministic analysis and report export remain 100% operational offline.[/dim]")
        console.print(f"    [dim]To enable local AI assistance: install Ollama and run 'ollama serve'.[/dim]")

    console.print("\n[bold green]Environment check completed.[/bold green]")


@app.command(name="help")
def show_help(
    command_name: Optional[str] = typer.Argument(
        None,
        help="Specific command to get detailed help for (analyze, report, doctor).",
    )
):
    """Show available commands and their usage."""
    if command_name:
        cmd = command_name.lower().strip()
        if cmd == "analyze":
            console.print("[bold cyan]COMMAND: lastsignal analyze[/bold cyan]\n")
            console.print("Ingest a JSONL trace, detect failure patterns, and output forensic autopsy.\n")
            console.print("[bold]Usage:[/bold]")
            console.print("  lastsignal analyze <TRACE_FILE> [OPTIONS]\n")
            console.print("[bold]Options:[/bold]")
            console.print("  --output, -o <PATH>   Export forensic report to Markdown file")
            console.print("  --no-ai               Skip local LLM calls; run 100% offline deterministic rules")
            console.print("  --model, -m <NAME>    Local Ollama model name (default: llama3.2:latest)")
            console.print("  --ollama-url <URL>    Ollama endpoint (default: http://localhost:11434)")
            console.print("  --no-color            Disable terminal ANSI color formatting\n")
            console.print("[bold]Examples:[/bold]")
            console.print("  lastsignal analyze examples/repeated_tool_failure.jsonl")
            console.print("  lastsignal analyze examples/repeated_tool_failure.jsonl --no-ai")
            console.print("  lastsignal analyze examples/repeated_tool_failure.jsonl -o reports/autopsy.md")
            return

        elif cmd == "report":
            console.print("[bold cyan]COMMAND: lastsignal report[/bold cyan]\n")
            console.print("Generate and export a Markdown investigation report for a trace file.\n")
            console.print("[bold]Usage:[/bold]")
            console.print("  lastsignal report <TRACE_FILE> --output <PATH> [OPTIONS]\n")
            console.print("[bold]Options:[/bold]")
            console.print("  --output, -o <PATH>   (Required) Destination path for Markdown report")
            console.print("  --no-ai               Skip local LLM calls in the exported report")
            console.print("  --model, -m <NAME>    Local Ollama model name (default: llama3.2:latest)")
            console.print("  --ollama-url <URL>    Ollama endpoint (default: http://localhost:11434)\n")
            console.print("[bold]Example:[/bold]")
            console.print("  lastsignal report examples/repeated_tool_failure.jsonl -o reports/autopsy.md")
            return

        elif cmd == "doctor":
            console.print("[bold cyan]COMMAND: lastsignal doctor[/bold cyan]\n")
            console.print("Verify local environment, report generation, and Ollama connectivity.\n")
            console.print("[bold]Usage:[/bold]")
            console.print("  lastsignal doctor [OPTIONS]\n")
            console.print("[bold]Options:[/bold]")
            console.print("  --ollama-url <URL>    Ollama endpoint to test (default: http://localhost:11434)")
            console.print("  --model, -m <NAME>    Target model name to verify (default: llama3.2:latest)\n")
            console.print("[bold]Example:[/bold]")
            console.print("  lastsignal doctor")
            return

        else:
            console.print(f"[bold yellow]Unknown command '{command_name}'.[/bold yellow] Available commands: analyze, report, doctor, help\n")

    # General overview table
    console.print("[bold cyan]================================================================================[/bold cyan]")
    console.print("[bold cyan]LAST SIGNAL // FORENSIC CLI COMMAND REFERENCE[/bold cyan]")
    console.print("[dim]Offline-first digital autopsy for investigating failed AI-agent executions.[/dim]")
    console.print("[bold cyan]================================================================================[/bold cyan]\n")

    table = Table(title="Available Commands", border_style="dim", show_header=True)
    table.add_column("Command", style="bold green", width=12)
    table.add_column("Purpose", style="white", width=42)
    table.add_column("Example Usage", style="cyan", width=38)

    table.add_row(
        "analyze",
        "Ingest trace, detect failure patterns, and display forensic autopsy.",
        "lastsignal analyze trace.jsonl",
    )
    table.add_row(
        "report",
        "Generate and export a Markdown autopsy report to a destination file.",
        "lastsignal report trace.jsonl -o out.md",
    )
    table.add_row(
        "doctor",
        "Run system diagnostics (core engine, export capability, local Ollama).",
        "lastsignal doctor",
    )
    table.add_row(
        "help",
        "Show available commands and usage guidelines.",
        "lastsignal help [analyze|report|doctor]",
    )

    console.print(table)
    console.print()
    console.print("[bold]Common Flags & Options:[/bold]")
    console.print("  [green]--no-ai[/green]               Force 100% offline analysis (skip all local LLM calls)")
    console.print("  [green]--output, -o[/green] <PATH>   Export forensic autopsy report to a Markdown (.md) file")
    console.print("  [green]--model, -m[/green] <NAME>    Configure local Ollama model (default: llama3.2:latest)")
    console.print("  [green]--ollama-url[/green] <URL>   Configure local Ollama endpoint (default: http://localhost:11434)")
    console.print("  [green]--no-color[/green]             Disable terminal ANSI color formatting")
    console.print("\n[dim]For detailed help on a specific command, run:[/dim] [cyan]lastsignal help <command>[/cyan]\n")


def main():
    app()


if __name__ == "__main__":
    main()
