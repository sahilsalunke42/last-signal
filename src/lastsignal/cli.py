"""Command-line interface for Last Signal using Typer and Rich."""

import os
import sys
import tempfile
from pathlib import Path
from typing import List, Optional
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
from lastsignal.runner import (
    CommandExecutionError,
    CommandNotFoundError,
    RunnerError,
    TraceWriteError,
    run_and_capture,
)
from lastsignal.trace_reader import TraceError, read_trace

# Last Signal Día de los Muertos / Forensic Theme Tokens (Design.md)
COLOR_BONE = "#E8E0D2"
COLOR_ASH = "#9297A1"
COLOR_MARIGOLD = "#E8A23A"
COLOR_CRIMSON = "#D64B55"
COLOR_SPECTRAL_TEAL = "#65B8A5"
COLOR_VIOLET = "#A78BFA"
COLOR_BORDER = "#343A44"

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
    inner_w = max(46, w - 4)
    box_w = inner_w + 4

    top_border = "┌" + "─" * (box_w - 2) + "┐"
    mid_border = "├" + "─" * (box_w - 2) + "┤"
    bot_border = "└" + "─" * (box_w - 2) + "┘"
    div_line = "─" * box_w
    sub_sep = "─" * box_w

    def box_row(text: str = "") -> str:
        truncated = text[:inner_w]
        return f"│ {truncated.ljust(inner_w)} │"

    lines = [
        top_border,
        box_row(""),
        box_row(f"  LAST SIGNAL // FORENSIC INVESTIGATION CLI (v{__version__})"),
        box_row('  "Ghost in the Machine" — Digital Afterlife Forensics'),
        box_row(""),
        box_row("  Every failed agent leaves a trace."),
        box_row(""),
        mid_border,
        box_row("  MODE       LOCAL / OFFLINE (100% Zero-Cloud Telemetry)"),
        box_row("  ANALYSIS   DETERMINISTIC RULES + OPTIONAL LOCAL AI (OLLAMA)"),
        bot_border,
        "",
        "Last Signal investigates failed AI-agent executions. It reconstructs recorded",
        "traces, detects failure patterns (repeated tool errors, unproductive retry",
        "loops, and unhandled terminal crashes), and produces evidence-grounded",
        "digital autopsy reports.",
        "",
        "REGISTERED COMMANDS:",
        sub_sep,
        "  run",
        "    Syntax:      lastsignal run [OPTIONS] -- <COMMAND> [ARGS...]",
        "    Description: Execute a command, capture trace, and auto-diagnose on failure.",
        "    Example:     lastsignal run -- python examples/demo_agent.py",
        "",
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
        div_line,
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


@app.command(
    name="run",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def run_command(
    ctx: typer.Context,
    command: Optional[List[str]] = typer.Argument(
        None,
        help="Target command and arguments to execute.",
    ),
    trace_out: Optional[Path] = typer.Option(
        None,
        "--trace-out",
        "-t",
        help="Path where captured JSONL trace should be saved.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination path for Markdown autopsy report if process fails.",
    ),
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Skip local LLM calls and perform deterministic analysis only.",
    ),
    model: str = typer.Option(
        DEFAULT_OLLAMA_MODEL,
        "--model",
        "-m",
        help="Local Ollama model name for grounded interpretation.",
    ),
    ollama_url: str = typer.Option(
        DEFAULT_OLLAMA_URL,
        "--ollama-url",
        help="Base URL of local Ollama instance.",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable ANSI colors and terminal styling.",
    ),
):
    """Execute an agent command, capture its trace, and auto-diagnose on failure."""
    target_cmd = list(command or []) + ctx.args
    if not target_cmd:
        err_console.print("[bold red]Error:[/bold red] No command provided to run.")
        console.print("Usage:   lastsignal run [OPTIONS] -- <COMMAND> [ARGS...]")
        console.print("Example: lastsignal run -- python examples/demo_agent.py")
        raise typer.Exit(code=2)

    try:
        exit_code, trace_path, _ = run_and_capture(
            command=target_cmd,
            trace_output_path=trace_out,
            stream_output=True,
        )
    except CommandNotFoundError as exc:
        err_console.print(f"\n[bold red]Execution Error:[/bold red] {exc}")
        raise typer.Exit(code=127)
    except RunnerError as exc:
        err_console.print(f"\n[bold red]Execution Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # 1. Successful execution
    if exit_code == 0:
        console.print(f"\n[bold {COLOR_SPECTRAL_TEAL}][+] Process completed successfully (exit code 0).[/bold {COLOR_SPECTRAL_TEAL}]")
        console.print(f"[bold {COLOR_ASH}][*] Execution trace saved to:[/bold {COLOR_ASH}] [{COLOR_BONE}]{trace_path}[/{COLOR_BONE}]")
        raise typer.Exit(code=0)

    # 2. Failed execution: automatically trigger forensic investigation
    console.print(f"\n[bold {COLOR_CRIMSON}][!] Process failed with exit code {exit_code}. Launching forensic autopsy...[/bold {COLOR_CRIMSON}]\n")

    read_res = read_trace(trace_path)
    analysis = detect_failures(read_res.events)

    # Local AI interpretation (with graceful fallback)
    ai_diag = diagnose_with_local_ai(
        report=analysis,
        events=read_res.events,
        base_url=ollama_url,
        model=model,
        disabled=no_ai,
    )
    analysis.ai_diagnosis = ai_diag

    terminal_report = format_terminal_report(read_res, analysis, str(trace_path))
    if no_color or os.environ.get("NO_COLOR"):
        typer.echo(terminal_report)
    else:
        console.print(terminal_report)

    if output:
        try:
            saved_path = export_markdown_report(read_res, analysis, str(trace_path), output)
            console.print(f"\n[bold {COLOR_SPECTRAL_TEAL}][+] Markdown report exported to:[/bold {COLOR_SPECTRAL_TEAL}] [{COLOR_BONE}]{saved_path}[/{COLOR_BONE}]")
        except ReportExportError as exc:
            err_console.print(f"\n[bold {COLOR_CRIMSON}][!] Report export failed:[/bold {COLOR_CRIMSON}] {exc}")

    console.print(f"\n[bold {COLOR_SPECTRAL_TEAL}][+] Execution trace saved to:[/bold {COLOR_SPECTRAL_TEAL}] [{COLOR_BONE}]{trace_path}[/{COLOR_BONE}]")

    # Preserve child process exit code
    raise typer.Exit(code=exit_code)


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
            console.print(f"\n[bold {COLOR_SPECTRAL_TEAL}][+] Markdown report exported to:[/bold {COLOR_SPECTRAL_TEAL}] [{COLOR_BONE}]{saved_path}[/{COLOR_BONE}]")
        except ReportExportError as exc:
            err_console.print(f"\n[bold {COLOR_CRIMSON}][!] Export failed:[/bold {COLOR_CRIMSON}] {exc}")
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
        err_console.print(f"[bold {COLOR_CRIMSON}]Error reading trace:[/bold {COLOR_CRIMSON}] {exc}")
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
        console.print(f"[bold {COLOR_SPECTRAL_TEAL}][+] Forensic Markdown report written to:[/bold {COLOR_SPECTRAL_TEAL}] [{COLOR_BONE}]{saved_path}[/{COLOR_BONE}]")
    except ReportExportError as exc:
        err_console.print(f"[bold {COLOR_CRIMSON}][!] Report export failed:[/bold {COLOR_CRIMSON}] {exc}")
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
    console.print(f"[bold {COLOR_MARIGOLD}]=== LAST SIGNAL SYSTEM DIAGNOSTICS ===[/bold {COLOR_MARIGOLD}]\n")

    # 1. Environment & Core
    console.print(f"[*] Last Signal Version: {__version__}")
    console.print(f"[*] Python Version:      {sys.version.split()[0]}")
    console.print(f"[*] Python Executable:   {sys.executable}")
    console.print(f"[bold {COLOR_SPECTRAL_TEAL}][+] Core Engine:[/bold {COLOR_SPECTRAL_TEAL}]         READY [dim](Trace reader & deterministic detector)[/dim]")

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
    except Exception:
        can_export = False

    if can_export:
        console.print(f"[bold {COLOR_SPECTRAL_TEAL}][+] Report Exporter:[/bold {COLOR_SPECTRAL_TEAL}]     READY [dim](File system write & directory creation verified)[/dim]")
    else:
        console.print(f"[bold {COLOR_CRIMSON}][-] Report Exporter:[/bold {COLOR_CRIMSON}]     FAILED [dim](File system write issue)[/dim]")

    # 3. Local Ollama Connectivity & Model Check
    client = OllamaClient(base_url=ollama_url, model=model, connect_timeout=2.0)
    connected, version_or_err = client.check_connectivity()

    if connected:
        console.print(f"[bold {COLOR_SPECTRAL_TEAL}][+] Local Ollama:[/bold {COLOR_SPECTRAL_TEAL}]        ONLINE [dim](Daemon v{version_or_err} at {client.base_url})[/dim]")
        models = client.list_models()
        if models:
            console.print(f"[*] Installed Models:   {', '.join(models)}")
        else:
            console.print(f"[bold {COLOR_MARIGOLD}][!] Installed Models:  [/bold {COLOR_MARIGOLD}] None found in local library")

        available, _ = client.is_model_available(model)
        if available:
            console.print(f"[bold {COLOR_SPECTRAL_TEAL}][+] Target Model:       [/bold {COLOR_SPECTRAL_TEAL}] READY [dim]('{model}' available for local inference)[/dim]")
        else:
            console.print(f"[bold {COLOR_MARIGOLD}[-] Target Model:       [/bold {COLOR_MARIGOLD}] NOT FOUND [dim]('{model}' not installed; run 'ollama pull {model}')[/dim]")
    else:
        console.print(f"[bold {COLOR_MARIGOLD}][-] Local Ollama:        OFFLINE ({version_or_err})[/bold {COLOR_MARIGOLD}]")
        console.print("    [dim]Deterministic analysis and report export remain 100% operational offline.[/dim]")
        console.print("    [dim]To enable local AI assistance: install Ollama and run 'ollama serve'.[/dim]")

    console.print(f"\n[bold {COLOR_SPECTRAL_TEAL}]Environment check completed.[/bold {COLOR_SPECTRAL_TEAL}]")


@app.command(name="help")
def show_help(
    command_name: Optional[str] = typer.Argument(
        None,
        help="Specific command to get detailed help for (run, analyze, report, doctor).",
    )
):
    """Show available commands and their usage."""
    if command_name:
        cmd = command_name.lower().strip()
        if cmd == "run":
            console.print(f"[bold {COLOR_MARIGOLD}]COMMAND: lastsignal run[/bold {COLOR_MARIGOLD}]\n")
            console.print("Execute an agent command, capture execution trace, and auto-diagnose on failure.\n")
            console.print(f"[bold {COLOR_BONE}]Usage:[/bold {COLOR_BONE}]")
            console.print("  lastsignal run [OPTIONS] -- <COMMAND> [ARGS...]\n")
            console.print(f"[bold {COLOR_BONE}]Options:[/bold {COLOR_BONE}]")
            console.print("  --trace-out, -t <PATH> Destination path for saved JSONL trace")
            console.print("  --output, -o <PATH>    Destination path for Markdown autopsy report if process fails")
            console.print("  --no-ai                Skip local LLM calls; run 100% offline deterministic rules")
            console.print("  --model, -m <NAME>     Local Ollama model name (default: llama3.2:latest)")
            console.print("  --ollama-url <URL>     Ollama endpoint (default: http://localhost:11434)")
            console.print("  --no-color             Disable terminal ANSI color formatting\n")
            console.print(f"[bold {COLOR_BONE}]Examples:[/bold {COLOR_BONE}]")
            console.print("  lastsignal run -- python examples/demo_agent.py")
            console.print("  lastsignal run --no-ai -- python examples/demo_agent.py")
            console.print("  lastsignal run -t traces/custom.jsonl -o reports/fail.md -- node agent.js")
            return

        elif cmd == "analyze":
            console.print(f"[bold {COLOR_MARIGOLD}]COMMAND: lastsignal analyze[/bold {COLOR_MARIGOLD}]\n")
            console.print("Ingest a JSONL trace, detect failure patterns, and output forensic autopsy.\n")
            console.print(f"[bold {COLOR_BONE}]Usage:[/bold {COLOR_BONE}]")
            console.print("  lastsignal analyze <TRACE_FILE> [OPTIONS]\n")
            console.print(f"[bold {COLOR_BONE}]Options:[/bold {COLOR_BONE}]")
            console.print("  --output, -o <PATH>   Export forensic report to Markdown file")
            console.print("  --no-ai               Skip local LLM calls; run 100% offline deterministic rules")
            console.print("  --model, -m <NAME>    Local Ollama model name (default: llama3.2:latest)")
            console.print("  --ollama-url <URL>    Ollama endpoint (default: http://localhost:11434)")
            console.print("  --no-color            Disable terminal ANSI color formatting\n")
            console.print(f"[bold {COLOR_BONE}]Examples:[/bold {COLOR_BONE}]")
            console.print("  lastsignal analyze examples/repeated_tool_failure.jsonl")
            console.print("  lastsignal analyze examples/repeated_tool_failure.jsonl --no-ai")
            console.print("  lastsignal analyze examples/repeated_tool_failure.jsonl -o reports/autopsy.md")
            return

        elif cmd == "report":
            console.print(f"[bold {COLOR_MARIGOLD}]COMMAND: lastsignal report[/bold {COLOR_MARIGOLD}]\n")
            console.print("Generate and export a Markdown investigation report for a trace file.\n")
            console.print(f"[bold {COLOR_BONE}]Usage:[/bold {COLOR_BONE}]")
            console.print("  lastsignal report <TRACE_FILE> --output <PATH> [OPTIONS]\n")
            console.print(f"[bold {COLOR_BONE}]Options:[/bold {COLOR_BONE}]")
            console.print("  --output, -o <PATH>   (Required) Destination path for Markdown report")
            console.print("  --no-ai               Skip local LLM calls in the exported report")
            console.print("  --model, -m <NAME>    Local Ollama model name (default: llama3.2:latest)")
            console.print("  --ollama-url <URL>    Ollama endpoint (default: http://localhost:11434)\n")
            console.print(f"[bold {COLOR_BONE}]Example:[/bold {COLOR_BONE}]")
            console.print("  lastsignal report examples/repeated_tool_failure.jsonl -o reports/autopsy.md")
            return

        elif cmd == "doctor":
            console.print(f"[bold {COLOR_MARIGOLD}]COMMAND: lastsignal doctor[/bold {COLOR_MARIGOLD}]\n")
            console.print("Verify local environment, report generation, and Ollama connectivity.\n")
            console.print(f"[bold {COLOR_BONE}]Usage:[/bold {COLOR_BONE}]")
            console.print("  lastsignal doctor [OPTIONS]\n")
            console.print(f"[bold {COLOR_BONE}]Options:[/bold {COLOR_BONE}]")
            console.print("  --ollama-url <URL>    Ollama endpoint to test (default: http://localhost:11434)")
            console.print("  --model, -m <NAME>    Target model name to verify (default: llama3.2:latest)\n")
            console.print(f"[bold {COLOR_BONE}]Example:[/bold {COLOR_BONE}]")
            console.print("  lastsignal doctor")
            return

        else:
            console.print(f"[bold {COLOR_MARIGOLD}]Unknown command '{command_name}'.[/bold {COLOR_MARIGOLD}] Available commands: run, analyze, report, doctor, help\n")

    # General overview
    w = get_terminal_width()
    sep = "=" * w
    sub_sep = "-" * w

    lines = [
        sep,
        f"LAST SIGNAL // COMMAND REFERENCE (v{__version__})",
        '"Ghost in the Machine" — Offline-First Digital Autopsy for AI Agents',
        sep,
        "",
        "REGISTERED COMMANDS:",
        sub_sep,
        "  run",
        "    Syntax:      lastsignal run [OPTIONS] -- <COMMAND> [ARGS...]",
        "    Description: Execute a command, capture trace, and auto-diagnose on failure.",
        "    Example:     lastsignal run -- python examples/demo_agent.py",
        "",
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
        "  Last Signal runs 100% offline. To bypass all local LLM calls and enforce",
        "  purely deterministic rule-based analysis, pass --no-ai:",
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
        "For detailed help on a specific command, run: lastsignal help <command>",
        sep,
    ]
    console.print("\n".join(lines))


def main():
    app()


if __name__ == "__main__":
    main()
