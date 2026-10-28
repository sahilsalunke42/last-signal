#!/usr/bin/env python3
"""Convenience runner script for Last Signal trace reader."""

import sys
from pathlib import Path
from lastsignal.trace_reader import read_trace


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "example/agentTrace.jsonl"
    path = Path(target)
    if not path.exists():
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading trace file: {path}")
    result = read_trace(path)

    print(f"[+] Parsed {result.valid_count} events from {result.total_lines} lines.")
    if result.errors:
        print(f"[-] Encountered {result.error_count} error(s):")
        for err in result.errors:
            print(f"    Line {err.line_number}: {err.reason}")

    print("\n--- Trace Events ---")
    for event in result.events:
        status_tag = f"[{event.status}]" if event.status else ""
        op_tag = f" tool={event.operation}" if event.operation else ""
        err_tag = f" error={event.error_message!r}" if event.error_message else ""
        print(f"  Line {event.line_number:02d} | {event.event_type:<12} {status_tag}{op_tag}{err_tag}")


if __name__ == "__main__":
    main()
