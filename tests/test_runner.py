"""Tests for process execution supervisor, trace capture, and 'lastsignal run' CLI command."""

import json
import os
import sys
from pathlib import Path
from typer.testing import CliRunner

import pytest
from lastsignal.cli import app
from lastsignal.runner import (
    CommandExecutionError,
    CommandNotFoundError,
    TraceWriteError,
    parse_stream_line,
    run_and_capture,
)

runner = CliRunner()


def test_parse_stream_line_empty_and_plain_logs():
    """Verify that empty lines or plain unstructured logs return None."""
    assert parse_stream_line("", 1, "tr-1") is None
    assert parse_stream_line("   \n", 2, "tr-1") is None
    assert parse_stream_line("[INFO] Starting worker pool...", 3, "tr-1") is None
    assert parse_stream_line("DEBUG: Processing payload item 4", 4, "tr-1") is None


def test_parse_stream_line_raw_json():
    """Verify parsing of raw JSON lines with event or event_type."""
    raw = json.dumps({"event": "tool_call", "tool": "search_db", "status": "started"})
    ev = parse_stream_line(raw, 5, "tr-test")
    assert ev is not None
    assert ev["event"] == "tool_call"
    assert ev["tool"] == "search_db"
    assert ev["trace_id"] == "tr-test"
    assert "timestamp" in ev

    raw_type = json.dumps({"event_type": "tool_result", "status": "failed", "error": "timeout"})
    ev2 = parse_stream_line(raw_type, 6, "tr-test")
    assert ev2 is not None
    assert ev2["event_type"] == "tool_result"
    assert ev2["status"] == "failed"


def test_parse_stream_line_structured_tags():
    """Verify parsing of structured tags like [tool_call], [tool_result], [retry]."""
    # Simple tool call
    line1 = "[tool_call] tool=query_docs status=started"
    ev1 = parse_stream_line(line1, 10, "tr-tag")
    assert ev1 is not None
    assert ev1["event_type"] == "tool_call"
    assert ev1["operation"] == "query_docs"
    assert ev1["status"] == "started"

    # Quoted error message and attempt number
    line2 = '[tool_result] tool=vector_sync attempt=2 status=failed error="Connection refused at port 8000"'
    ev2 = parse_stream_line(line2, 11, "tr-tag")
    assert ev2 is not None
    assert ev2["event_type"] == "tool_result"
    assert ev2["operation"] == "vector_sync"
    assert ev2["status"] == "failed"
    assert ev2["attempt"] == 2
    assert "Connection refused" in ev2["error_message"]

    # Retry tag
    line3 = "[retry] tool=vector_sync attempt=3 status=pending"
    ev3 = parse_stream_line(line3, 12, "tr-tag")
    assert ev3 is not None
    assert ev3["event_type"] == "retry"
    assert ev3["operation"] == "vector_sync"
    assert ev3["attempt"] == 3


def test_parse_stream_line_python_exceptions():
    """Verify detection of Python tracebacks and exception lines in stderr."""
    line = "RuntimeError: Database connection pool exhausted after 30s"
    ev = parse_stream_line(line, 20, "tr-exc")
    assert ev is not None
    assert ev["event_type"] == "tool_result"
    assert ev["operation"] == "RuntimeError"
    assert ev["status"] == "failed"
    assert "RuntimeError: Database connection pool exhausted" in ev["error_message"]


def test_run_and_capture_empty_command():
    """Verify that invoking run_and_capture with an empty list raises ValueError."""
    with pytest.raises(ValueError, match="No command provided"):
        run_and_capture([])


def test_run_and_capture_successful_execution(tmp_path: Path):
    """Verify execution of a successful command capturing start, end, and output."""
    trace_file = tmp_path / "success_trace.jsonl"
    cmd = [
        sys.executable,
        "-c",
        "print('[tool_call] tool=math_eval status=success')\nprint('Done!')",
    ]
    exit_code, saved_path, events = run_and_capture(
        cmd,
        trace_output_path=trace_file,
        stream_output=False,
    )

    assert exit_code == 0
    assert saved_path == trace_file
    assert trace_file.exists()

    # Verify structured events
    assert len(events) >= 3  # agent_start, tool_call, agent_end
    assert events[0]["event_type"] == "agent_start"
    assert events[0]["status"] == "started"

    assert any(e.get("operation") == "math_eval" and e.get("status") == "success" for e in events)

    assert events[-1]["event_type"] == "agent_end"
    assert events[-1]["status"] == "success"
    assert events[-1]["metadata"]["exit_code"] == 0


def test_run_and_capture_failed_execution(tmp_path: Path):
    """Verify execution of a failing command records error events and preserves exit code."""
    trace_file = tmp_path / "failed_trace.jsonl"
    code = (
        "import sys\n"
        "print('[tool_call] tool=db_fetch status=failed error=\"Lost conn\"')\n"
        "sys.exit(7)\n"
    )
    cmd = [sys.executable, "-c", code]
    exit_code, saved_path, events = run_and_capture(
        cmd,
        trace_output_path=trace_file,
        stream_output=False,
    )

    assert exit_code == 7
    assert saved_path == trace_file
    assert trace_file.exists()

    # Verify error captured
    assert events[-1]["event_type"] == "agent_end"
    assert events[-1]["status"] == "failed"
    assert events[-1]["metadata"]["exit_code"] == 7


def test_run_and_capture_command_not_found(tmp_path: Path):
    """Verify that an invalid/nonexistent executable raises CommandNotFoundError."""
    with pytest.raises(CommandNotFoundError) as exc_info:
        run_and_capture(["nonexistent_binary_xyz_98765"], stream_output=False)
    assert "Verify the binary name and PATH" in str(exc_info.value)


def test_run_and_capture_trace_target_is_directory(tmp_path: Path):
    """Verify that specifying a directory as trace_output_path raises TraceWriteError."""
    target_dir = tmp_path / "already_a_dir"
    target_dir.mkdir()

    with pytest.raises(TraceWriteError) as exc_info:
        run_and_capture([sys.executable, "-c", "print('ok')"], trace_output_path=target_dir, stream_output=False)
    assert "existing directory" in str(exc_info.value)


def test_cli_run_no_command():
    """Verify that 'lastsignal run' without arguments shows usage error and exits code 2."""
    result = runner.invoke(app, ["run"])
    assert result.exit_code == 2
    assert "No command provided to run" in result.output
    assert "lastsignal run [OPTIONS] -- <COMMAND>" in result.output


def test_cli_run_missing_executable():
    """Verify that 'lastsignal run -- invalid_cmd' exits code 127."""
    result = runner.invoke(app, ["run", "--", "definitely_not_a_valid_command_12345"])
    assert result.exit_code == 127
    assert "Execution Error" in result.output
    assert "Verify the binary name and PATH" in result.output


def test_cli_run_successful_command(tmp_path: Path):
    """Verify that 'lastsignal run' on a successful command exits code 0 and reports trace location."""
    trace_path = tmp_path / "custom_run.jsonl"
    result = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(trace_path),
            "--",
            sys.executable,
            "-c",
            "print('Agent step completed.')",
        ],
    )
    assert result.exit_code == 0
    assert "Process completed successfully (exit code 0)" in result.output
    assert "Execution trace saved to:" in result.output
    assert trace_path.exists()


def test_cli_run_failure_launches_autopsy(tmp_path: Path):
    """Verify that 'lastsignal run' on a failing agent launches forensic autopsy and preserves exit code."""
    trace_path = tmp_path / "auto_fail.jsonl"
    report_path = tmp_path / "auto_report.md"

    # Command that emits repeated failure tags and exits code 3
    code = (
        "import sys\n"
        "for i in range(1, 4):\n"
        "    print(f'[tool_call] tool=remote_api attempt={i} status=started')\n"
        "    print(f'[tool_result] tool=remote_api attempt={i} status=failed error=\"HTTP 500 Server Error\"')\n"
        "    if i < 3: print(f'[retry] tool=remote_api attempt={i+1} status=pending')\n"
        "print('RuntimeError: Fatal API unreachable', file=sys.stderr)\n"
        "sys.exit(3)\n"
    )

    result = runner.invoke(
        app,
        [
            "run",
            "--no-ai",
            "--trace-out",
            str(trace_path),
            "--output",
            str(report_path),
            "--",
            sys.executable,
            "-c",
            code,
        ],
    )

    # Must preserve child exit code
    assert result.exit_code == 3
    assert "Process failed with exit code 3. Launching forensic autopsy..." in result.output
    assert "LAST SIGNAL // FORENSIC INVESTIGATION REPORT" in result.output
    assert "Repeated Failure in Tool 'remote_api'" in result.output
    assert "Markdown report exported to:" in result.output
    assert trace_path.exists()
    assert report_path.exists()

    # Check report content
    report_content = report_path.read_text(encoding="utf-8")
    assert "Forensic Investigation Report" in report_content
    assert "remote_api" in report_content


def test_cli_run_demo_agent_e2e(tmp_path: Path):
    """Verify end-to-end integration running examples/demo_agent.py."""
    demo_script = Path("examples/demo_agent.py").resolve()
    assert demo_script.exists()

    # 1. Successful run
    res_succ = runner.invoke(
        app,
        [
            "run",
            "--no-ai",
            "-t",
            str(tmp_path / "demo_succ.jsonl"),
            "--",
            sys.executable,
            str(demo_script),
            "--succeed",
        ],
    )
    assert res_succ.exit_code == 0
    assert "Process completed successfully" in res_succ.output

    # 2. Failing run
    fail_trace = tmp_path / "demo_fail.jsonl"
    fail_report = tmp_path / "demo_fail_report.md"
    res_fail = runner.invoke(
        app,
        [
            "run",
            "--no-ai",
            "-t",
            str(fail_trace),
            "-o",
            str(fail_report),
            "--",
            sys.executable,
            str(demo_script),
        ],
    )
    assert res_fail.exit_code == 1
    assert "Process failed with exit code 1. Launching forensic autopsy..." in res_fail.output
    assert "Repeated Failure in Tool 'vector_sync'" in res_fail.output
    assert "Unproductive Retry Loop for 'vector_sync'" in res_fail.output
    assert fail_trace.exists()
    assert fail_report.exists()
