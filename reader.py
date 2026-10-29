#!/usr/bin/env python3
"""Convenience runner script for Last Signal trace reader and forensic reporter."""

import argparse
import sys
from pathlib import Path

from lastsignal.detector import detect_failures
from lastsignal.llm import (
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    diagnose_with_local_ai,
)
from lastsignal.report import (
    ReportExportError,
    export_markdown_report,
    format_terminal_report,
)
from lastsignal.trace_reader import TraceError, read_trace


def main():
    parser = argparse.ArgumentParser(
        description="Last Signal - Forensic digital autopsy for failed AI-agent traces.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "trace_file",
        nargs="?",
        default="example/agentTrace.jsonl",
        help="Path to JSONL execution trace log.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Export forensic investigation report to Markdown file.",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip local LLM calls and perform deterministic trace analysis only.",
    )
    parser.add_argument(
        "--model",
        "-m",
        type=str,
        default=DEFAULT_OLLAMA_MODEL,
        help="Local Ollama model name for grounded interpretation.",
    )
    parser.add_argument(
        "--ollama-url",
        type=str,
        default=DEFAULT_OLLAMA_URL,
        help="Base URL of local Ollama instance.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI styling and color escapes.",
    )

    args = parser.parse_args()

    # Handle explicit 'help' argument
    if args.trace_file.lower() in ("help", "commands"):
        print("""
================================================================================
LAST SIGNAL // FORENSIC CLI RUNNER GUIDE
================================================================================
Usage:
  python3 reader.py [TRACE_FILE] [OPTIONS]
  lastsignal <COMMAND> [OPTIONS]

Available Commands:
  analyze   Ingest trace, detect failure patterns, and display autopsy.
  report    Generate and export a Markdown autopsy report.
  doctor    Run environment and Ollama diagnostics.
  help      Show available commands and their use.

Options:
  --output, -o <PATH>   Export forensic report to Markdown file.
  --no-ai               Run 100% offline deterministic analysis (no LLM).
  --model, -m <NAME>    Local Ollama model name (default: llama3.2:latest).
  --ollama-url <URL>    Ollama endpoint (default: http://localhost:11434).
  --no-color            Disable terminal ANSI color formatting.

Examples:
  python3 reader.py examples/repeated_tool_failure.jsonl
  python3 reader.py examples/repeated_tool_failure.jsonl --no-ai
  python3 reader.py examples/repeated_tool_failure.jsonl --output reports/autopsy.md
  lastsignal analyze examples/repeated_tool_failure.jsonl
  lastsignal doctor
================================================================================
""")
        sys.exit(0)

    path = Path(args.trace_file)

    if not path.exists():
        print(f"Error: Trace file not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        read_res = read_trace(path)
    except TraceError as exc:
        print(f"Error parsing trace file: {exc}", file=sys.stderr)
        sys.exit(1)

    # Deterministic failure detection
    analysis = detect_failures(read_res.events)

    # Local AI diagnosis (gracefully handled if offline or --no-ai)
    ai_diag = diagnose_with_local_ai(
        report=analysis,
        events=read_res.events,
        base_url=args.ollama_url,
        model=args.model,
        disabled=args.no_ai,
    )
    analysis.ai_diagnosis = ai_diag

    # Output formatted terminal report
    terminal_report = format_terminal_report(read_res, analysis, str(path))
    print(terminal_report)

    # Optional Markdown export
    if args.output:
        try:
            saved_path = export_markdown_report(read_res, analysis, str(path), args.output)
            print(f"\n[+] Forensic Markdown report successfully written to: {saved_path}")
        except ReportExportError as exc:
            print(f"\n[!] Export failed: {exc}", file=sys.stderr)
            sys.exit(1)

    # Exit code: 0 for successful/clean execution, 1 if failures were detected
    if analysis.has_failures or read_res.error_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
