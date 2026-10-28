"""Unit tests for terminal reporting and Markdown export in Last Signal."""

import os
import stat
from pathlib import Path
import pytest

from lastsignal.detector import detect_failures
from lastsignal.models import (
    AnalysisReport,
    Finding,
    Severity,
    TraceEvent,
    TraceParseError,
    TraceReadResult,
)
from lastsignal.report import (
    ReportExportError,
    determine_outcome,
    export_markdown_report,
    format_terminal_report,
    generate_markdown_report,
    group_findings_by_severity,
    sanitize_markdown,
    sanitize_table_cell,
    sanitize_text,
)


def test_terminal_report_successful_execution():
    """Verify terminal report on a clean successful execution."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="read_file", status="success"),
        TraceEvent(line_number=3, event_type="agent_end", status="success"),
    ]
    read_res = TraceReadResult(events=events, total_lines=3)
    analysis = detect_failures(events)

    report_text = format_terminal_report(read_res, analysis, "test_success.jsonl")
    assert "LAST SIGNAL // FORENSIC INVESTIGATION REPORT" in report_text
    assert "test_success.jsonl" in report_text
    assert "SUCCESSFUL" in report_text
    assert "NO DETECTED FAILURE PATTERNS" in report_text
    assert "Lines Ingested:     3 (3 valid events, 0 malformed lines)" in report_text


def test_terminal_report_failed_execution_with_findings():
    """Verify terminal report formatting with multiple findings and severities."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="run_cmd", status="failed", error_message="Command failed: exit 1"),
        TraceEvent(line_number=3, event_type="tool_call", operation="run_cmd", status="failed", error_message="Command failed: exit 1"),
        TraceEvent(line_number=4, event_type="agent_end", status="failed", error_message="Fatal error"),
    ]
    read_res = TraceReadResult(events=events, total_lines=4)
    analysis = detect_failures(events)

    report_text = format_terminal_report(read_res, analysis, "failed.jsonl")
    assert "FAILED" in report_text
    assert "[CRITICAL] SEVERITY FINDINGS" in report_text
    assert "Repeated Failure in Tool 'run_cmd'" in report_text
    assert "Event Lines:    [2, 3]" in report_text
    assert "Recommendation:" in report_text
    assert "FINAL VERDICT" in report_text


def test_terminal_report_empty_and_incomplete_traces():
    """Verify reporting for empty and incomplete/truncated traces."""
    # 1. Empty trace
    read_res_empty = TraceReadResult(events=[], total_lines=0)
    analysis_empty = detect_failures([])
    report_empty = format_terminal_report(read_res_empty, analysis_empty, "empty.jsonl")
    assert "EMPTY (No events recorded)" in report_empty

    # 2. Incomplete trace (halted after error without agent_end)
    events_incomplete = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="crashed_tool", status="failed", error_message="SIGSEGV"),
    ]
    read_res_inc = TraceReadResult(events=events_incomplete, total_lines=2)
    analysis_inc = detect_failures(events_incomplete)
    report_inc = format_terminal_report(read_res_inc, analysis_inc, "incomplete.jsonl")
    assert "INCOMPLETE (Halted abruptly" in report_inc


def test_terminal_report_with_malformed_lines():
    """Verify that malformed line warnings appear clearly in terminal output."""
    events = [TraceEvent(line_number=1, event_type="agent_start", status="started")]
    errors = [TraceParseError(line_number=2, reason="Malformed JSON: unclosed bracket")]
    read_res = TraceReadResult(events=events, errors=errors, total_lines=2)
    analysis = detect_failures(events)

    report_text = format_terminal_report(read_res, analysis, "broken.jsonl")
    assert "[!] INGESTION WARNINGS (1 Malformed Lines)" in report_text
    assert "Line 2: Malformed JSON: unclosed bracket" in report_text


def test_markdown_report_generation():
    """Verify Markdown generation with table, findings, and timeline."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started", trace_id="tr-test-99"),
        TraceEvent(line_number=2, event_type="tool_call", operation="api_call", status="failed", error_message="HTTP 500"),
        TraceEvent(line_number=3, event_type="agent_end", status="failed"),
    ]
    read_res = TraceReadResult(events=events, total_lines=3)
    analysis = detect_failures(events)

    md = generate_markdown_report(read_res, analysis, "trace.jsonl")
    assert "# LAST SIGNAL // Forensic Investigation Report" in md
    assert "| **Trace File** | `trace.jsonl` |" in md
    assert "| **Trace ID** | `tr-test-99` |" in md
    assert "## Case Overview" in md
    assert "## Detected Failure Patterns" in md
    assert "## Key Event Timeline" in md
    assert "| 2 | `tool_call` | `api_call` | failed | HTTP 500 |" in md


def test_markdown_export_creates_parent_directories(tmp_path):
    """Verify that export creates nested parent directories automatically."""
    events = [TraceEvent(line_number=1, event_type="agent_start", status="started")]
    read_res = TraceReadResult(events=events, total_lines=1)
    analysis = detect_failures(events)

    nested_out = tmp_path / "deeply" / "nested" / "reports" / "autopsy.md"
    saved = export_markdown_report(read_res, analysis, "test.jsonl", nested_out)

    assert saved.exists()
    assert saved.is_file()
    content = saved.read_text(encoding="utf-8")
    assert "LAST SIGNAL" in content


def test_markdown_export_directory_as_target_raises_error(tmp_path):
    """Verify that attempting to write to an existing directory raises ReportExportError."""
    events = [TraceEvent(line_number=1, event_type="agent_start", status="started")]
    read_res = TraceReadResult(events=events, total_lines=1)
    analysis = detect_failures(events)

    with pytest.raises(ReportExportError) as exc_info:
        export_markdown_report(read_res, analysis, "test.jsonl", tmp_path)
    assert "destination is a directory" in str(exc_info.value)


def test_untrusted_text_sanitization():
    """Verify that untrusted input (HTML tags, backticks, table pipes, ANSI codes) is sanitized."""
    # 1. Terminal ANSI escapes
    dirty_ansi = "\x1B[31mRed Text\x1B[0m\x00"
    cleaned = sanitize_text(dirty_ansi)
    assert "\x1B" not in cleaned
    assert "\x00" not in cleaned
    assert "Red Text" in cleaned

    # 2. Script tags and HTML injection
    dirty_html = "<script>alert('pwned')</script> and <style>body{color:red;}</style>"
    cleaned_md = sanitize_markdown(dirty_html)
    assert "<script" not in cleaned_md
    assert "&lt;script" in cleaned_md
    assert "<style" not in cleaned_md

    # 3. Code block fence breakouts
    dirty_backticks = "```bash\nrm -rf /\n```"
    cleaned_fence = sanitize_markdown(dirty_backticks)
    assert "```" not in cleaned_fence
    assert r"\`\`\`" in cleaned_fence

    # 4. Table cell pipes and newlines
    dirty_table = "column | split\nsecond line"
    cleaned_cell = sanitize_table_cell(dirty_table)
    assert r"\|" in cleaned_cell
    assert "<br>" in cleaned_cell
    assert "\n" not in cleaned_cell


def test_markdown_report_with_malicious_trace_content(tmp_path):
    """Verify that a trace with malicious payload fields generates safe Markdown without breaking."""
    malicious_event = TraceEvent(
        line_number=1,
        event_type="tool_call",
        operation="<script>alert('xss')</script>",
        status="failed",
        error_message="Error with | pipe and ``` code fence and \x1B[32mANSI\x1B[0m",
    )
    read_res = TraceReadResult(events=[malicious_event], total_lines=1)
    analysis = detect_failures([malicious_event])

    out_file = tmp_path / "safe_report.md"
    export_markdown_report(read_res, analysis, "malicious.jsonl", out_file)

    content = out_file.read_text(encoding="utf-8")
    assert "<script" not in content
    assert "\x1B" not in content
    assert r"\`\`\`" in content
