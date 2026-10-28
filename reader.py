#!/usr/bin/env python3
"""Convenience runner script for Last Signal trace reader and forensic reporter."""

import argparse
import sys
from pathlib import Path

from lastsignal.detector import detect_failures
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
        "--no-color",
        action="store_true",
        help="Disable ANSI styling and color escapes.",
    )

    args = parser.parse_args()
    path = Path(args.trace_file)

    if not path.exists():
        print(f"Error: Trace file not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        read_res = read_trace(path)
    except TraceError as exc:
        print(f"Error parsing trace file: {exc}", file=sys.stderr)
        sys.exit(1)

    analysis = detect_failures(read_res.events)

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
