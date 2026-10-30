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


ASCII_WORDMARK = (
    r" _                 _      _____ _                   _ " + "\n"
    r"| |               | |    / ____(_)                 | |" + "\n"
    r"| |     __ _  ___ | |_  | (___  _  __ _ _ __   __ _| |" + "\n"
    r"| |    / _` |/ __|| __|  \___ \| |/ _` | '_ \ / _` | |" + "\n"
    r"| |___| (_| |\__ \| |_   ____) | | (_| | | | | (_| | |" + "\n"
    r"|______\__,_||___/ \__| |_____/|_|\__, |_| |_|\__,_|_|" + "\n"
    r"                                   __/ |              " + "\n"
    r"                                  |___/               "
)


def get_terminal_width(fallback: int = 80) -> int:
    """Determine safe terminal display width."""
    try:
        import shutil
        width = shutil.get_terminal_size((fallback, 24)).columns
        return max(50, min(width, 100))
    except Exception:
        return fallback


def scan_workspace(root_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Auto-detect candidate agent entry points, recent traces, and failure state in workspace."""
    root = Path(root_dir or Path.cwd()).resolve()

    # 1. Detect candidate agent script
    detected_agent = None
    agent_candidates = [
        "examples/demo_agent.py",
        "demo_agent.py",
        "agent.py",
        "src/agent.py",
        "main.py",
        "app.py",
        "run.py",
        "bot.py",
    ]
    for rel in agent_candidates:
        p = root / rel
        if p.is_file():
            detected_agent = rel
            break

    if not detected_agent:
        try:
            for p in sorted(root.glob("*.py"))[:10]:
                if p.name.startswith("test_") or p.name in {"setup.py", "conftest.py"}:
                    continue
                content = p.read_text(encoding="utf-8", errors="ignore")[:1500].lower()
                if any(k in content for k in ["agent", "tool_call", "langchain", "crewai", "autogen", "openai", "ollama", "anthropic"]):
                    detected_agent = p.name
                    break
        except Exception:
            pass

    # If no local script found, detect installed autonomous CLI agents
    if not detected_agent:
        import shutil
        for cli_tool in ["claude", "agy", "aider", "codex", "openhands"]:
            if shutil.which(cli_tool):
                detected_agent = f"{cli_tool} (CLI)"
                break

    # 2. Detect recent traces in .lastsignal/traces or .lastsignal or traces/ or root
    candidate_dirs = [
        root / ".lastsignal" / "traces",
        root / ".lastsignal",
        root / "traces",
        root / ".traces",
        root / ".claude",
        root / ".openhands",
    ]
    trace_files: List[Path] = []
    for d in candidate_dirs:
        if d.is_dir():
            trace_files.extend([p for p in d.glob("*.jsonl") if p.is_file()])

    if not trace_files:
        trace_files.extend([p for p in root.glob("*.jsonl") if p.is_file() and not p.name.startswith(".")])

    unique_traces = list({p.resolve(): p for p in trace_files}.values())
    unique_traces.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    latest_trace = None
    latest_trace_rel = None
    latest_error_trace = None
    latest_error_trace_rel = None
    trace_status = None
    trace_summary = None

    if unique_traces:
        latest_trace = unique_traces[0]
        try:
            latest_trace_rel = str(latest_trace.relative_to(root))
        except ValueError:
            latest_trace_rel = str(latest_trace)

        # Inspect up to first 5 traces to identify failure status and locate latest error trace
        for tr in unique_traces[:5]:
            try:
                read_res = read_trace(tr)
                if not read_res.events:
                    continue
                analysis = detect_failures(read_res.events)
                is_fail = analysis.has_failures or any(e.is_failure for e in read_res.events) or read_res.error_count > 0
                if is_fail:
                    if latest_error_trace is None:
                        latest_error_trace = tr
                        try:
                            latest_error_trace_rel = str(tr.relative_to(root))
                        except ValueError:
                            latest_error_trace_rel = str(tr)

                    if tr == latest_trace and trace_status is None:
                        trace_status = "FAILED"
                        tool_fails = [e for e in read_res.events if e.is_failure and e.event_type in {"tool_call", "tool_result"}]
                        if tool_fails and tool_fails[-1].operation:
                            trace_summary = f"{len(tool_fails)} tool failure(s) in '{tool_fails[-1].operation}'"
                        elif analysis.findings:
                            trace_summary = analysis.findings[0].title
                        else:
                            trace_summary = "Non-zero exit / aborted execution"
                elif tr == latest_trace and trace_status is None:
                    trace_status = "SUCCESS"
                    trace_summary = f"{len(read_res.events)} event(s) completed cleanly"
            except Exception:
                if tr == latest_trace and trace_status is None:
                    trace_status = "RECORDED"
                    trace_summary = "Valid JSONL trace"

    traces_dir = root / ".lastsignal" / "traces"
    traces_display_dir = ".lastsignal/traces"
    if traces_dir.exists():
        traces_display_dir = ".lastsignal/traces"
    elif (root / "traces").exists():
        traces_display_dir = "traces"

    return {
        "detected_agent": detected_agent,
        "latest_trace": latest_trace,
        "latest_trace_rel": latest_trace_rel,
        "latest_error_trace": latest_error_trace,
        "latest_error_trace_rel": latest_error_trace_rel,
        "trace_status": trace_status,
        "trace_summary": trace_summary,
        "traces_dir": traces_display_dir,
    }


def build_startup_interface(width: Optional[int] = None, colorize: bool = False) -> str:
    """Construct the Claude Code-style Last Signal welcome screen.

    Renders an outlined forensic banner, custom 'Last Signal' ASCII wordmark,
    haunting welcome copy, workspace auto-detection, status block, and command
    shortcuts in Last Signal's Día de los Muertos / Digital Afterlife palette.
    """
    w = width or get_terminal_width()
    banner_title = "✳ LAST SIGNAL // FORENSIC TERMINAL"
    banner_inner_w = 48
    banner_w = banner_inner_w + 6  # 54 cols, matches ASCII wordmark width

    if w < 54:
        banner_inner_w = max(34, w - 6)
        banner_w = banner_inner_w + 6

    banner_top = "┌" + "─" * (banner_w - 2) + "┐"
    banner_bot = "└" + "─" * (banner_w - 2) + "┘"

    sep_w = max(54, min(w, 80))
    sep_line = "─" * sep_w

    ws = scan_workspace()
    detected_agent_str = ws["detected_agent"] or "examples/demo_agent.py"
    if detected_agent_str.endswith(" (CLI)"):
        cli_name = detected_agent_str.split()[0]
        run_example_str = f"lastsignal run -- {cli_name} '<task>'"
    else:
        run_example_str = f"lastsignal run -- python {detected_agent_str}"

    if ws["trace_status"] == "FAILED":
        trace_status_badge = f"[bold {COLOR_CRIMSON}][⚠️ FAILED: {ws['trace_summary']}][/bold {COLOR_CRIMSON}]"
        plain_status_badge = f"[⚠️ FAILED: {ws['trace_summary']}]"
    elif ws["trace_status"] == "SUCCESS":
        trace_status_badge = f"[bold {COLOR_SPECTRAL_TEAL}][✓ {ws['trace_summary']}][/bold {COLOR_SPECTRAL_TEAL}]"
        plain_status_badge = f"[✓ {ws['trace_summary']}]"
    elif ws["latest_trace_rel"]:
        trace_status_badge = f"[{COLOR_ASH}][RECORDED: {ws['trace_summary'] or 'Valid JSONL trace'}][/{COLOR_ASH}]"
        plain_status_badge = f"[RECORDED: {ws['trace_summary'] or 'Valid JSONL trace'}]"
    else:
        trace_status_badge = f"[dim {COLOR_ASH}][Awaiting first run][/dim {COLOR_ASH}]"
        plain_status_badge = "[Awaiting first run]"

    if colorize:
        pad_len = max(0, banner_inner_w - len(banner_title))
        padding = " " * pad_len
        banner_content = (
            f"│  [bold {COLOR_MARIGOLD}]✳[/] [bold {COLOR_BONE}]LAST SIGNAL // FORENSIC TERMINAL[/]{padding}  │"
        )

        banner_block = [
            f"[{COLOR_CRIMSON}]{banner_top}[/]",
            banner_content,
            f"[{COLOR_CRIMSON}]{banner_bot}[/]",
        ]

        logo_lines = [f"[bold {COLOR_CRIMSON}]{line}[/]" for line in ASCII_WORDMARK.splitlines()]

        lines = [
            "",
            *banner_block,
            "",
            *logo_lines,
            "",
            f"[bold {COLOR_BONE}]Every failed agent leaves a trace.[/bold {COLOR_BONE}]",
            f"[{COLOR_ASH}]Investigate execution failures. Preserve the evidence.[/{COLOR_ASH}]",
            f'[dim {COLOR_ASH}]"Ghost in the Machine" — Offline-first digital autopsy CLI for AI agents.[/dim {COLOR_ASH}]',
            f"[dim {COLOR_ASH}]Reconstructs recorded traces, detects failure patterns, and recovers terminal signals.[/dim {COLOR_ASH}]",
            "",
            f"[{COLOR_BORDER}]{sep_line}[/]",
            f"[bold {COLOR_MARIGOLD}]WORKSPACE AUTO-DETECTION:[/bold {COLOR_MARIGOLD}]",
            f"  [{COLOR_ASH}]Target Agent:[/]  [{COLOR_BONE}]{ws['detected_agent'] or 'None detected'}[/] [dim {COLOR_ASH}](auto-identified)[/dim {COLOR_ASH}]",
            f"  [{COLOR_ASH}]Latest Trace:[/]  [{COLOR_BONE}]{ws['latest_trace_rel'] or 'None recorded'}[/]",
            f"  [{COLOR_ASH}]Trace Status:[/]  {trace_status_badge}",
            f"[{COLOR_BORDER}]{sep_line}[/]",
            f"[bold {COLOR_MARIGOLD}]SYSTEM STATUS: (DIGITAL AUTOPSY ENVIRONMENT)[/bold {COLOR_MARIGOLD}]",
            f"  [{COLOR_ASH}]Version:[/]  [{COLOR_BONE}]v{__version__}[/] [dim {COLOR_ASH}](Deterministic Ground Truth Engine)[/dim {COLOR_ASH}]",
            f"  [{COLOR_ASH}]Mode:[/]     [bold {COLOR_SPECTRAL_TEAL}]LOCAL / OFFLINE[/bold {COLOR_SPECTRAL_TEAL}] [dim {COLOR_ASH}](100% Air-Gapped / Zero-Cloud Telemetry)[/dim {COLOR_ASH}]",
            f"  [{COLOR_ASH}]AI:[/]       [bold {COLOR_MARIGOLD}]OPTIONAL[/bold {COLOR_MARIGOLD}] [dim {COLOR_ASH}](Local Ollama: llama3.2:latest; pass --no-ai to silence)[/dim {COLOR_ASH}]",
            f"  [{COLOR_ASH}]Traces:[/]   [{COLOR_BONE}]{ws['traces_dir']}[/]",
            f"[{COLOR_BORDER}]{sep_line}[/]",
            "",
            f"[bold {COLOR_MARIGOLD}]COMMAND SHORTCUTS:[/bold {COLOR_MARIGOLD}]",
            f"  [bold {COLOR_BONE}]lastsignal run[/bold {COLOR_BONE}]       [{COLOR_ASH}]Capture and investigate an execution (live autopsy on fatal collapse)[/]",
            f"                      [dim {COLOR_ASH}]Example: {run_example_str}[/]",
            "",
            f"  [bold {COLOR_BONE}]lastsignal analyze[/bold {COLOR_BONE}]   [{COLOR_ASH}]Analyze an existing trace for failure patterns and anomalies[/]",
            f"                      [dim {COLOR_ASH}]Example: lastsignal analyze examples/repeated_tool_failure.jsonl[/]",
            "",
            f"  [bold {COLOR_BONE}]lastsignal doctor[/bold {COLOR_BONE}]    [{COLOR_ASH}]Check local dependencies and Ollama daemon connectivity[/]",
            f"                      [dim {COLOR_ASH}]Example: lastsignal doctor[/]",
            "",
            f"  [bold {COLOR_BONE}]lastsignal report[/bold {COLOR_BONE}]    [{COLOR_ASH}]Export a forensic Markdown autopsy report[/]",
            f"                      [dim {COLOR_ASH}]Example: lastsignal report <TRACE_FILE> --output <PATH>[/]",
            "",
            f"  [bold {COLOR_BONE}]lastsignal help[/bold {COLOR_BONE}]      [{COLOR_ASH}]View all commands and detailed documentation[/]",
            f"                      [dim {COLOR_ASH}]Example: lastsignal help analyze[/]",
            "",
            f"[{COLOR_BORDER}]{sep_line}[/]",
            f"[bold {COLOR_MARIGOLD}]OFFLINE & DETERMINISTIC ANALYSIS:[/bold {COLOR_MARIGOLD}]",
            f"  [{COLOR_ASH}]Last Signal is 100% offline-first. Deterministic failure detection and report[/]",
            f"  [{COLOR_ASH}]export run without external network access or local LLM inference.[/]",
            f"  [{COLOR_ASH}]To enforce purely deterministic analysis without contacting Ollama:[/{COLOR_ASH}]",
            f"    [bold {COLOR_BONE}]lastsignal analyze <TRACE_FILE> --no-ai[/bold {COLOR_BONE}]",
            f"[{COLOR_BORDER}]{sep_line}[/]",
            "",
            f"[italic {COLOR_MARIGOLD}]Type a command to begin your investigation.[/italic {COLOR_MARIGOLD}]",
            "",
        ]
    else:
        pad_len = max(0, banner_inner_w - len(banner_title))
        padding = " " * pad_len
        banner_content = f"│  {banner_title}{padding}  │"
        lines = [
            "",
            banner_top,
            banner_content,
            banner_bot,
            "",
            ASCII_WORDMARK,
            "",
            "Every failed agent leaves a trace.",
            "Investigate execution failures. Preserve the evidence.",
            '"Ghost in the Machine" — Offline-first digital autopsy CLI for AI agents.',
            "Reconstructs recorded traces, detects failure patterns, and recovers terminal signals.",
            "",
            sep_line,
            "WORKSPACE AUTO-DETECTION:",
            f"  Target Agent:  {ws['detected_agent'] or 'None detected'}",
            f"  Latest Trace:  {ws['latest_trace_rel'] or 'None recorded'}",
            f"  Trace Status:  {plain_status_badge}",
            sep_line,
            "SYSTEM STATUS: (DIGITAL AUTOPSY ENVIRONMENT)",
            f"  Version:  v{__version__} (Deterministic Ground Truth Engine)",
            "  Mode:     LOCAL / OFFLINE (100% Air-Gapped / Zero-Cloud Telemetry)",
            "  AI:       OPTIONAL (Local Ollama: llama3.2:latest; pass --no-ai to silence)",
            f"  Traces:   {ws['traces_dir']}",
            sep_line,
            "",
            "COMMAND SHORTCUTS:",
            "  lastsignal run       Capture and investigate an execution (live autopsy on fatal collapse)",
            f"                      Example: {run_example_str}",
            "",
            "  lastsignal analyze   Analyze an existing trace for failure patterns and anomalies",
            "                      Example: lastsignal analyze examples/repeated_tool_failure.jsonl",
            "",
            "  lastsignal doctor    Check local dependencies and Ollama daemon connectivity",
            "                      Example: lastsignal doctor",
            "",
            "  lastsignal report    Export a forensic Markdown autopsy report",
            "                      Example: lastsignal report <TRACE_FILE> --output <PATH>",
            "",
            "  lastsignal help      View all commands and detailed documentation",
            "                      Example: lastsignal help analyze",
            "",
            sep_line,
            "OFFLINE & DETERMINISTIC ANALYSIS:",
            "  Last Signal is 100% offline-first. Deterministic failure detection and report",
            "  export run without external network access or local LLM inference.",
            "  To enforce purely deterministic analysis without contacting Ollama:",
            "    lastsignal analyze <TRACE_FILE> --no-ai",
            sep_line,
            "",
            "Type a command to begin your investigation.",
            "",
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

    # When lastsignal is run with no arguments, launch welcome screen
    if ctx.invoked_subcommand is None:
        is_no_color = bool(no_color or os.environ.get("NO_COLOR"))
        startup_text = build_startup_interface(colorize=not is_no_color)
        if is_no_color:
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
        ws = scan_workspace()
        detected = ws.get("detected_agent")
        err_console.print("[bold red]Error:[/bold red] No command provided to run.")
        if detected:
            console.print(f"[bold {COLOR_ASH}][*] Candidate agent detected in workspace:[/bold {COLOR_ASH}] [{COLOR_BONE}]{detected}[/{COLOR_BONE}]")
            console.print(f"    Run with: [bold]lastsignal run -- python {detected}[/bold]\n")
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
    trace_path: Optional[Path] = typer.Argument(
        None,
        help="Path to JSONL execution trace file to analyze (auto-detects recent trace if omitted).",
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
    target_trace = trace_path
    if target_trace is None:
        ws = scan_workspace()
        chosen_trace = ws.get("latest_error_trace") or ws.get("latest_trace")
        chosen_rel = ws.get("latest_error_trace_rel") or ws.get("latest_trace_rel")
        if chosen_trace:
            target_trace = chosen_trace
            if ws.get("latest_error_trace") and chosen_trace == ws.get("latest_error_trace"):
                console.print(f"[bold {COLOR_CRIMSON}][*] Auto-detected failed execution trace:[/bold {COLOR_CRIMSON}] [{COLOR_BONE}]{chosen_rel or target_trace}[/{COLOR_BONE}]\n")
            else:
                console.print(f"[bold {COLOR_SPECTRAL_TEAL}][*] Auto-detected recent execution trace:[/bold {COLOR_SPECTRAL_TEAL}] [{COLOR_BONE}]{chosen_rel or target_trace}[/{COLOR_BONE}]\n")
        else:
            err_console.print(f"[bold {COLOR_CRIMSON}]Error:[/bold {COLOR_CRIMSON}] Missing argument 'TRACE_FILE' and no traces found in workspace.")
            console.print("Usage: lastsignal analyze <TRACE_FILE>")
            raise typer.Exit(code=2)

    if not Path(target_trace).is_file():
        err_console.print(f"[bold {COLOR_CRIMSON}]Error reading trace:[/bold {COLOR_CRIMSON}] File not found: '{target_trace}'")
        raise typer.Exit(code=1)

    try:
        read_res = read_trace(target_trace)
    except TraceError as exc:
        err_console.print(f"[bold {COLOR_CRIMSON}]Error reading trace:[/bold {COLOR_CRIMSON}] {exc}")
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
    terminal_report = format_terminal_report(read_res, analysis, str(target_trace))
    if no_color or os.environ.get("NO_COLOR"):
        typer.echo(terminal_report)
    else:
        console.print(terminal_report)

    # 4. Optional Markdown export
    if output:
        try:
            saved_path = export_markdown_report(read_res, analysis, str(target_trace), output)
            console.print(f"\n[bold {COLOR_SPECTRAL_TEAL}][+] Markdown report exported to:[/bold {COLOR_SPECTRAL_TEAL}] [{COLOR_BONE}]{saved_path}[/{COLOR_BONE}]")
        except ReportExportError as exc:
            err_console.print(f"\n[bold {COLOR_CRIMSON}][!] Export failed:[/bold {COLOR_CRIMSON}] {exc}")
            raise typer.Exit(code=1)

    # Return exit code 1 if failures or errors detected
    if analysis.has_failures or read_res.error_count > 0:
        raise typer.Exit(code=1)


@app.command(name="report")
def report(
    trace_path: Optional[Path] = typer.Argument(
        None,
        help="Path to JSONL execution trace file (auto-detects recent trace if omitted).",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination path for Markdown autopsy report (auto-defaults to reports/<trace>_autopsy.md).",
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
    target_trace = trace_path
    if target_trace is None:
        ws = scan_workspace()
        chosen_trace = ws.get("latest_error_trace") or ws.get("latest_trace")
        chosen_rel = ws.get("latest_error_trace_rel") or ws.get("latest_trace_rel")
        if chosen_trace:
            target_trace = chosen_trace
            if ws.get("latest_error_trace") and chosen_trace == ws.get("latest_error_trace"):
                console.print(f"[bold {COLOR_CRIMSON}][*] Auto-detected failed execution trace:[/bold {COLOR_CRIMSON}] [{COLOR_BONE}]{chosen_rel or target_trace}[/{COLOR_BONE}]\n")
            else:
                console.print(f"[bold {COLOR_SPECTRAL_TEAL}][*] Auto-detected recent execution trace:[/bold {COLOR_SPECTRAL_TEAL}] [{COLOR_BONE}]{chosen_rel or target_trace}[/{COLOR_BONE}]\n")
        else:
            err_console.print(f"[bold {COLOR_CRIMSON}]Error:[/bold {COLOR_CRIMSON}] Missing argument 'TRACE_PATH' and no traces found in workspace.")
            console.print("Usage: lastsignal report [TRACE_PATH] [--output <REPORT_PATH>]")
            raise typer.Exit(code=2)

    if not Path(target_trace).is_file():
        err_console.print(f"[bold {COLOR_CRIMSON}]Error reading trace:[/bold {COLOR_CRIMSON}] File not found: '{target_trace}'")
        raise typer.Exit(code=1)

    target_output = output
    if target_output is None:
        reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(target_trace).stem
        target_output = reports_dir / f"{stem}_autopsy.md"
        console.print(f"[bold {COLOR_ASH}][*] Auto-selected report destination:[/bold {COLOR_ASH}] [{COLOR_BONE}]{target_output}[/{COLOR_BONE}]\n")

    try:
        read_res = read_trace(target_trace)
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
        saved_path = export_markdown_report(read_res, analysis, str(target_trace), target_output)
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
        help="Specific command to get detailed help for (run, analyze, report, doctor, help).",
    )
):
    """Show available commands and their usage."""
    w = get_terminal_width()
    sep = "=" * w
    sub_sep = "-" * w

    if command_name:
        cmd = command_name.lower().strip()
        if cmd == "run":
            console.print(f"[bold {COLOR_MARIGOLD}]COMMAND: lastsignal run[/bold {COLOR_MARIGOLD}]\n")
            console.print("Supervise any agent process, capture execution trace, and auto-diagnose on failure.\n")
            console.print(f"[bold {COLOR_BONE}]Usage:[/bold {COLOR_BONE}]")
            console.print("  lastsignal run [OPTIONS] -- <COMMAND> [ARGS...]\n")
            console.print(f"[bold {COLOR_BONE}]Important:[/bold {COLOR_BONE}]")
            console.print("  The '--' delimiter separates Last Signal flags from your target command.")
            console.print("  Works with ANY executable: Python/Node scripts, CLI agents (claude, agy, aider), or test suites.\n")
            console.print(f"[bold {COLOR_BONE}]Options:[/bold {COLOR_BONE}]")
            console.print("  --trace-out, -t <PATH> Destination path for saved JSONL trace (default: .lastsignal/traces/)")
            console.print("  --output, -o <PATH>    Destination path for Markdown autopsy report if process fails")
            console.print("  --no-ai                Skip local LLM calls; run 100% offline deterministic rules")
            console.print("  --model, -m <NAME>     Local Ollama model name (default: llama3.2:latest)")
            console.print("  --ollama-url <URL>     Ollama endpoint (default: http://localhost:11434)")
            console.print("  --no-color             Disable terminal ANSI color formatting\n")
            console.print(f"[bold {COLOR_BONE}]Examples:[/bold {COLOR_BONE}]")
            console.print("  # Supervise Python agent:")
            console.print("  lastsignal run -- python examples/demo_agent.py\n")
            console.print("  # Supervise autonomous CLI agents:")
            console.print("  lastsignal run -- claude -p 'fix bug in auth.py'")
            console.print("  lastsignal run -- agy 'run tests and fix failures'")
            console.print("  lastsignal run -- aider --message 'add stripe billing'\n")
            console.print("  # Enforce 100% offline deterministic autopsy and save Markdown report:")
            console.print("  lastsignal run --no-ai -o reports/failure.md -- python agent.py")
            return

        elif cmd == "analyze":
            console.print(f"[bold {COLOR_MARIGOLD}]COMMAND: lastsignal analyze[/bold {COLOR_MARIGOLD}]\n")
            console.print("Ingest an execution trace, detect failure patterns, and output forensic autopsy.\n")
            console.print(f"[bold {COLOR_BONE}]Usage:[/bold {COLOR_BONE}]")
            console.print("  lastsignal analyze [TRACE_FILE] [OPTIONS]\n")
            console.print(f"[bold {COLOR_BONE}]Zero-Argument Auto-Detection:[/bold {COLOR_BONE}]")
            console.print("  If [TRACE_FILE] is omitted, Last Signal automatically scans the workspace and")
            console.print("  analyzes the most recent failed execution trace in .lastsignal/traces/!\n")
            console.print(f"[bold {COLOR_BONE}]Options:[/bold {COLOR_BONE}]")
            console.print("  --output, -o <PATH>   Export forensic autopsy report to Markdown (.md) file")
            console.print("  --no-ai               Skip local LLM calls; run 100% offline deterministic rules")
            console.print("  --model, -m <NAME>    Local Ollama model name (default: llama3.2:latest)")
            console.print("  --ollama-url <URL>    Ollama endpoint (default: http://localhost:11434)")
            console.print("  --no-color            Disable terminal ANSI color formatting\n")
            console.print(f"[bold {COLOR_BONE}]Examples:[/bold {COLOR_BONE}]")
            console.print("  lastsignal analyze                                        # Auto-inspects latest trace")
            console.print("  lastsignal analyze --no-ai                                # Auto-inspects offline")
            console.print("  lastsignal analyze examples/repeated_tool_failure.jsonl   # Inspects specific file")
            console.print("  lastsignal analyze path/to/trace.jsonl -o report.md       # Exports Markdown autopsy")
            return

        elif cmd == "report":
            console.print(f"[bold {COLOR_MARIGOLD}]COMMAND: lastsignal report[/bold {COLOR_MARIGOLD}]\n")
            console.print("Generate and export a forensic Markdown autopsy report for an agent trace.\n")
            console.print(f"[bold {COLOR_BONE}]Usage:[/bold {COLOR_BONE}]")
            console.print("  lastsignal report [TRACE_FILE] [OPTIONS]\n")
            console.print(f"[bold {COLOR_BONE}]Zero-Argument Auto-Detection:[/bold {COLOR_BONE}]")
            console.print("  If [TRACE_FILE] is omitted, Last Signal automatically scans the workspace,")
            console.print("  selects the most recent failed trace, and defaults output to reports/<trace>_autopsy.md!\n")
            console.print(f"[bold {COLOR_BONE}]Options:[/bold {COLOR_BONE}]")
            console.print("  --output, -o <PATH>   Destination path for Markdown report (.md) (auto-selected if omitted)")
            console.print("  --no-ai               Skip local LLM calls in the exported report")
            console.print("  --model, -m <NAME>    Local Ollama model name (default: llama3.2:latest)")
            console.print("  --ollama-url <URL>    Ollama endpoint (default: http://localhost:11434)\n")
            console.print(f"[bold {COLOR_BONE}]Examples:[/bold {COLOR_BONE}]")
            console.print("  lastsignal report                                         # Auto-exports latest trace")
            console.print("  lastsignal report --output reports/autopsy.md             # Custom destination")
            console.print("  lastsignal report examples/repeated_tool_failure.jsonl    # Specific trace file")
            return
            console.print("  --ollama-url <URL>    Ollama endpoint (default: http://localhost:11434)\n")
            console.print(f"[bold {COLOR_BONE}]Example:[/bold {COLOR_BONE}]")
            console.print("  lastsignal report examples/repeated_tool_failure.jsonl -o reports/autopsy.md")
            return

        elif cmd == "doctor":
            console.print(f"[bold {COLOR_MARIGOLD}]COMMAND: lastsignal doctor[/bold {COLOR_MARIGOLD}]\n")
            console.print("Verify local environment, report generation, and Ollama connectivity.\n")
            console.print(f"[bold {COLOR_BONE}]Checks Performed:[/bold {COLOR_BONE}]")
            console.print("  1. Python runtime and Last Signal engine integrity.")
            console.print("  2. Local file system write permissions for traces and reports.")
            console.print("  3. Local Ollama daemon status and diagnostic model availability.\n")
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

    # General complete reference overview
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
        "    Description: Supervise any agent process, capture trace, and auto-diagnose on failure.",
        "    Supports:    Custom Python/Node scripts, CLI agents (claude, agy, aider), test suites.",
        "    Example:     lastsignal run -- python examples/demo_agent.py",
        "",
        "  analyze",
        "    Syntax:      lastsignal analyze [TRACE_FILE] [OPTIONS]",
        "    Description: Ingest trace, detect failure patterns, and display forensic autopsy.",
        "    Note:        Auto-detects and analyzes latest failed trace when TRACE_FILE is omitted!",
        "    Example:     lastsignal analyze examples/repeated_tool_failure.jsonl",
        "",
        "  report",
        "    Syntax:      lastsignal report <TRACE_FILE> --output <PATH> [OPTIONS]",
        "    Description: Generate and export an evidence-grounded Markdown autopsy report (.md).",
        "    Example:     lastsignal report examples/repeated_tool_failure.jsonl -o reports/autopsy.md",
        "",
        "  doctor",
        "    Syntax:      lastsignal doctor [OPTIONS]",
        "    Description: Verify local environment, report file write, and Ollama connectivity.",
        "    Example:     lastsignal doctor",
        "",
        "  help",
        "    Syntax:      lastsignal help [COMMAND]",
        "    Description: Show available commands and detailed usage reference.",
        "    Example:     lastsignal help run",
        "",
        "HOW AGENT SUPERVISION WORKS (-- DELIMITER):",
        sub_sep,
        "  Always use '--' before your target command to prevent argument collision:",
        "    lastsignal run -- python agent.py",
        "    lastsignal run -- claude -p 'refactor auth module'",
        "    lastsignal run -- agy 'fix failing integration tests'",
        "  Output streams live. If the agent succeeds (exit 0), trace is archived quietly.",
        "  If the agent fails or crashes, Last Signal immediately displays the digital autopsy.",
        "",
        "OFFLINE & DETERMINISTIC ANALYSIS:",
        sub_sep,
        "  Last Signal runs 100% offline. To bypass all local LLM calls and enforce",
        "  purely deterministic rule-based analysis, pass --no-ai:",
        "    lastsignal analyze <TRACE_FILE> --no-ai",
        "    lastsignal run --no-ai -- python agent.py",
        "",
        "COMMON FLAGS & OPTIONS:",
        sub_sep,
        "  --no-ai               Run 100% offline deterministic rules (no LLM calls).",
        "  --output, -o <PATH>   Export forensic autopsy report to a Markdown (.md) file.",
        "  --trace-out, -t <PATH>Custom output path for captured JSONL trace.",
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
