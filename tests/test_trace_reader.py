"""Tests for Last Signal trace ingestion and schema validation."""

import json
from pathlib import Path
import pytest

from lastsignal.models import (
    TraceEvent,
    TraceFileNotFoundError,
    TraceParseError,
    TraceReadResult,
)
from lastsignal.trace_reader import iter_trace_events, read_trace


def test_read_valid_trace_file():
    """Verify that a valid JSONL trace is parsed into typed TraceEvent objects."""
    trace_path = Path("examples/successful_execution.jsonl")
    result = read_trace(trace_path)

    assert result.is_valid is True
    assert result.error_count == 0
    assert result.valid_count == 6
    assert result.total_lines == 6

    # Verify first event
    first = result.events[0]
    assert first.line_number == 1
    assert first.event_type == "agent_start"
    assert first.status == "started"
    assert first.trace_id == "tr-ghost-1001"
    assert first.timestamp == "2026-10-29T00:05:00Z"
    assert first.metadata.get("goal") == "Lint and format python files"

    # Verify tool call & alias resolution
    tool_call = result.events[1]
    assert tool_call.line_number == 2
    assert tool_call.event_type == "tool_call"
    assert tool_call.operation == "read_file"
    assert tool_call.tool == "read_file"
    assert tool_call.attempt == 1


def test_read_repeated_failure_trace():
    """Verify reading a trace with tool failures and retries."""
    trace_path = Path("examples/repeated_tool_failure.jsonl")
    result = read_trace(trace_path)

    assert result.is_valid is True
    assert result.valid_count == 11
    assert result.error_count == 0

    failures = [e for e in result.events if e.is_failure]
    assert len(failures) == 4  # 3 tool_results failed + 1 agent_end failed

    third_fail = failures[2]
    assert third_fail.line_number == 10
    assert third_fail.operation == "run_migration"
    assert "Connection refused" in third_fail.error_message
    assert third_fail.error == third_fail.error_message


def test_legacy_format_and_empty_lines(tmp_path):
    """Verify aliases ('tool', 'error', 'event') and skipping blank lines."""
    content = (
        "\n"
        '{"event": "tool_call", "tool": "read_file", "status": "success"}\n'
        "\n"
        '{"event": "tool_call", "tool": "execute_test", "status": "failed", "error": "pytest failed"}\n'
        '{"event": "agent_end", "status": "failed"}\n'
    )
    test_file = tmp_path / "legacy.jsonl"
    test_file.write_text(content)

    result = read_trace(test_file)
    assert result.valid_count == 3
    assert result.error_count == 0

    # Line numbers must reflect actual lines in file
    assert result.events[0].line_number == 2
    assert result.events[0].event_type == "tool_call"
    assert result.events[0].operation == "read_file"

    assert result.events[1].line_number == 4
    assert result.events[1].operation == "execute_test"
    assert result.events[1].error_message == "pytest failed"

    assert result.events[2].line_number == 5
    assert result.events[2].event_type == "agent_end"


def test_malformed_json_handling(tmp_path):
    """Verify that invalid JSON lines produce informative errors with line numbers."""
    content = (
        '{"event_type": "agent_start", "status": "started"}\n'
        '{"event_type": "tool_call", "unclosed_json: true\n'
        '{"event_type": "agent_end", "status": "success"}\n'
    )
    test_file = tmp_path / "broken.jsonl"
    test_file.write_text(content)

    # Permissive mode: collect errors
    result = read_trace(test_file, raise_on_error=False)
    assert result.valid_count == 2
    assert result.error_count == 1
    assert result.is_valid is False

    err = result.errors[0]
    assert err.line_number == 2
    assert "Malformed JSON" in err.reason

    # Strict mode: raise error immediately
    with pytest.raises(TraceParseError) as exc_info:
        read_trace(test_file, raise_on_error=True)
    assert exc_info.value.line_number == 2
    assert "Malformed JSON" in str(exc_info.value)


def test_missing_required_event_type(tmp_path):
    """Verify that a line missing event_type is rejected."""
    content = '{"status": "success", "operation": "run"}\n'
    test_file = tmp_path / "missing_type.jsonl"
    test_file.write_text(content)

    result = read_trace(test_file)
    assert result.error_count == 1
    assert result.valid_count == 0
    assert "Missing required field" in result.errors[0].reason
    assert result.errors[0].line_number == 1


def test_invalid_event_type_datatype(tmp_path):
    """Verify that non-string event_type is rejected."""
    content = '{"event_type": 12345, "status": "success"}\n'
    test_file = tmp_path / "bad_type.jsonl"
    test_file.write_text(content)

    result = read_trace(test_file)
    assert result.error_count == 1
    assert "'event_type' must be a string" in result.errors[0].reason


def test_empty_string_event_type(tmp_path):
    """Verify that an empty string event_type is rejected."""
    content = '{"event_type": "   ", "status": "success"}\n'
    test_file = tmp_path / "empty_type.jsonl"
    test_file.write_text(content)

    result = read_trace(test_file)
    assert result.error_count == 1
    assert "cannot be an empty string" in result.errors[0].reason


def test_non_dict_json_line(tmp_path):
    """Verify that a valid JSON scalar or array line is rejected."""
    content = '["event_start", "event_end"]\n'
    test_file = tmp_path / "array.jsonl"
    test_file.write_text(content)

    result = read_trace(test_file)
    assert result.error_count == 1
    assert "Expected JSON object" in result.errors[0].reason


def test_file_not_found():
    """Verify that non-existent trace file raises TraceFileNotFoundError."""
    with pytest.raises(TraceFileNotFoundError) as exc_info:
        read_trace("non_existent_trace_file.jsonl")
    assert "not found" in str(exc_info.value).lower()


def test_streaming_iterator(tmp_path):
    """Verify streaming line-by-line via iter_trace_events."""
    content = (
        '{"event_type": "agent_start"}\n'
        '{"invalid json line\n'
        '{"event_type": "agent_end"}\n'
    )
    test_file = tmp_path / "stream.jsonl"
    test_file.write_text(content)

    items = list(iter_trace_events(test_file))
    assert len(items) == 3

    # Line 1: valid
    line1, event1, err1 = items[0]
    assert line1 == 1
    assert event1 is not None and event1.event_type == "agent_start"
    assert err1 is None

    # Line 2: error
    line2, event2, err2 = items[1]
    assert line2 == 2
    assert event2 is None
    assert err2 is not None and "Malformed JSON" in err2.reason

    # Line 3: valid
    line3, event3, err3 = items[2]
    assert line3 == 3
    assert event3 is not None and event3.event_type == "agent_end"
    assert err3 is None


def test_trace_event_to_dict():
    """Verify TraceEvent serialization to clean dictionary."""
    ev = TraceEvent(
        line_number=5,
        event_type="tool_call",
        operation="search",
        status="success",
        metadata={"extra_field": "val"},
    )
    data = ev.to_dict()
    assert data["line_number"] == 5
    assert data["event_type"] == "tool_call"
    assert data["operation"] == "search"
    assert data["metadata"] == {"extra_field": "val"}
