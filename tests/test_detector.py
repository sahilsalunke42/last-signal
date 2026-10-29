"""Unit tests for deterministic failure detection engine."""

import pytest
from lastsignal.detector import FailureDetector, detect_failures
from lastsignal.models import AnalysisReport, EventType, Finding, Severity, TraceEvent


def test_repeated_tool_failures_detection():
    """Verify that 2+ failures for the same tool are flagged with exact lines and evidence."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(
            line_number=2,
            event_type="tool_call",
            operation="database_query",
            status="failed",
            error_message="Timeout connecting to DB",
        ),
        TraceEvent(
            line_number=3,
            event_type="tool_call",
            operation="database_query",
            status="failed",
            error_message="Timeout connecting to DB",
        ),
        TraceEvent(line_number=4, event_type="agent_end", status="failed"),
    ]

    report = detect_failures(events)
    assert report.has_failures is True

    rule1 = [f for f in report.findings if f.id == "RULE-REPEATED-TOOL-FAILURE"]
    assert len(rule1) == 1
    finding = rule1[0]
    assert finding.severity == Severity.CRITICAL
    assert finding.line_numbers == [2, 3]
    assert "database_query" in finding.title
    assert finding.inferred is False  # Explicitly logged errors
    assert any("Line 2" in ev for ev in finding.evidence)
    assert any("Line 3" in ev for ev in finding.evidence)
    assert "Timeout connecting to DB" in str(finding.evidence)


def test_unproductive_retry_loop():
    """Verify detection of retry attempts without intervening success."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="api_fetch", attempt=1, status="failed", error_message="503 Service Unavailable"),
        TraceEvent(line_number=3, event_type="retry", operation="api_fetch", attempt=2, status="pending"),
        TraceEvent(line_number=4, event_type="tool_call", operation="api_fetch", attempt=2, status="failed", error_message="503 Service Unavailable"),
        TraceEvent(line_number=5, event_type="agent_end", status="failed"),
    ]

    report = detect_failures(events)
    retry_findings = [f for f in report.findings if f.id == "RULE-UNPRODUCTIVE-RETRY-LOOP"]
    assert len(retry_findings) == 1
    rf = retry_findings[0]
    assert rf.severity == Severity.HIGH
    assert rf.inferred is True
    assert 3 in rf.line_numbers  # Retry event line
    assert "api_fetch" in rf.title


def test_terminal_tool_failure_preceding_abort():
    """Verify detection of the proximate tool failure preceding agent termination."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="search", status="success"),
        TraceEvent(line_number=3, event_type="tool_call", operation="write_file", status="failed", error_message="Disk full"),
        TraceEvent(line_number=4, event_type="agent_end", status="failed", error_message="Cannot continue: disk full"),
    ]

    report = detect_failures(events)
    term_findings = [f for f in report.findings if f.id == "RULE-TERMINAL-TOOL-FAILURE"]
    assert len(term_findings) == 1
    tf = term_findings[0]
    assert tf.severity == Severity.CRITICAL
    assert tf.line_numbers == [3, 4]
    assert "write_file" in tf.title
    assert tf.inferred is True  # Temporal correlation


def test_unrecovered_execution_failure():
    """Verify detection of a session ending in failure without recovery."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="fetch", status="failed", error_message="Auth failed"),
        TraceEvent(line_number=3, event_type="agent_end", status="failed"),
    ]

    report = detect_failures(events)
    unrec = [f for f in report.findings if f.id == "RULE-UNRECOVERED-EXECUTION-FAILURE"]
    assert len(unrec) == 1
    assert unrec[0].severity == Severity.HIGH
    assert 2 in unrec[0].line_numbers
    assert 3 in unrec[0].line_numbers


def test_successful_execution_no_false_positives():
    """Verify that a successful trace generates zero failure findings."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="read_file", status="started"),
        TraceEvent(line_number=3, event_type="tool_result", operation="read_file", status="success"),
        TraceEvent(line_number=4, event_type="tool_call", operation="execute_test", status="started"),
        TraceEvent(line_number=5, event_type="tool_result", operation="execute_test", status="success"),
        TraceEvent(line_number=6, event_type="agent_end", status="success"),
    ]

    report = detect_failures(events)
    assert report.has_failures is False
    assert len(report.findings) == 0
    assert report.critical_count == 0
    assert report.high_count == 0
    assert "successfully" in report.summary.lower()


def test_recovered_failure_not_flagged_as_unrecovered():
    """Verify that a tool failing once and then succeeding on retry is NOT flagged as unrecovered or unproductive."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="api_call", attempt=1, status="failed", error_message="Transient network glitch"),
        TraceEvent(line_number=3, event_type="retry", operation="api_call", attempt=2, status="pending"),
        TraceEvent(line_number=4, event_type="tool_call", operation="api_call", attempt=2, status="success"),
        TraceEvent(line_number=5, event_type="agent_end", status="success"),
    ]

    report = detect_failures(events)
    # Failure occurred once -> not repeated
    assert len([f for f in report.findings if f.id == "RULE-REPEATED-TOOL-FAILURE"]) == 0
    # Retry succeeded -> not unproductive
    assert len([f for f in report.findings if f.id == "RULE-UNPRODUCTIVE-RETRY-LOOP"]) == 0
    # Terminal event succeeded -> no terminal failure
    assert len([f for f in report.findings if f.id == "RULE-TERMINAL-TOOL-FAILURE"]) == 0
    # Subsequent success occurred -> not unrecovered
    assert len([f for f in report.findings if f.id == "RULE-UNRECOVERED-EXECUTION-FAILURE"]) == 0
    assert len(report.findings) == 0


def test_tool_started_status_not_treated_as_failure():
    """Verify that tool calls with status 'started' without errors are not treated as failures."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="run_job", status="started"),
        TraceEvent(line_number=3, event_type="tool_result", operation="run_job", status="success"),
        TraceEvent(line_number=4, event_type="agent_end", status="completed"),
    ]

    report = detect_failures(events)
    assert len(report.findings) == 0
    assert report.has_failures is False


def test_abrupt_termination_without_agent_end():
    """Verify that a trace cutting off after a failure is flagged as unrecovered."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="segfault_tool", status="failed", error_message="Process killed by SIGSEGV"),
    ]

    report = detect_failures(events)
    assert report.agent_status == "terminated_abruptly"
    unrec = [f for f in report.findings if f.id == "RULE-UNRECOVERED-EXECUTION-FAILURE"]
    assert len(unrec) == 1
    assert unrec[0].inferred is True  # Inferred from abrupt cessation


def test_different_tools_single_failure_not_repeated():
    """Verify that multiple different tools failing once each do not trigger repeated failure."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="tool_a", status="failed", error_message="Error A"),
        TraceEvent(line_number=3, event_type="tool_call", operation="tool_b", status="failed", error_message="Error B"),
        TraceEvent(line_number=4, event_type="agent_end", status="failed"),
    ]

    report = detect_failures(events)
    repeated = [f for f in report.findings if f.id == "RULE-REPEATED-TOOL-FAILURE"]
    assert len(repeated) == 0  # Neither tool failed >= 2 times


def test_empty_events_list():
    """Verify detector handles empty trace events safely."""
    report = detect_failures([])
    assert report.total_events == 0
    assert len(report.findings) == 0
    assert report.has_failures is False
    assert report.agent_status == "empty"


def test_missing_optional_fields_safe_handling():
    """Verify that events with None operations or error messages do not crash."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start"),
        TraceEvent(line_number=2, event_type="tool_call", status="failed"),
        TraceEvent(line_number=3, event_type="tool_call", status="failed"),
        TraceEvent(line_number=4, event_type="agent_end", status="failed"),
    ]

    report = detect_failures(events)
    assert report.has_failures is True
    assert len(report.findings) > 0


def test_analysis_report_and_finding_serialization():
    """Verify to_dict conversion for findings and reports."""
    finding = Finding(
        id="RULE-TEST",
        title="Test Title",
        severity=Severity.HIGH,
        explanation="Test explanation",
        line_numbers=[1, 2],
        evidence=["Evidence item"],
        recommendation="Test recommendation",
        inferred=True,
    )
    data = finding.to_dict()
    assert data["id"] == "RULE-TEST"
    assert data["severity"] == "HIGH"
    assert data["inferred"] is True
    assert data["line_numbers"] == [1, 2]

    report = AnalysisReport(
        trace_id="tr-test-1",
        total_events=5,
        findings=[finding],
        has_failures=True,
        agent_status="failed",
        summary="Summary test",
    )
    report_dict = report.to_dict()
    assert report_dict["trace_id"] == "tr-test-1"
    assert report_dict["finding_count"] == 1
    assert report_dict["high_count"] == 1
    assert report_dict["critical_count"] == 0


def test_successful_setup_with_repeated_failures_not_counted_as_error():
    """Verify that a successful setup event is preserved as evidence and not counted as a failure."""
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(line_number=2, event_type="tool_call", operation="load_configuration", status="success"),
        TraceEvent(line_number=3, event_type="tool_call", operation="vector_sync", attempt=1, status="started"),
        TraceEvent(line_number=4, event_type="tool_result", operation="vector_sync", attempt=1, status="failed", error_message="Connection timeout"),
        TraceEvent(line_number=5, event_type="retry", operation="vector_sync", attempt=2, status="pending"),
        TraceEvent(line_number=6, event_type="tool_call", operation="vector_sync", attempt=2, status="started"),
        TraceEvent(line_number=7, event_type="tool_result", operation="vector_sync", attempt=2, status="failed", error_message="Connection timeout"),
        TraceEvent(line_number=8, event_type="retry", operation="vector_sync", attempt=3, status="pending"),
        TraceEvent(line_number=9, event_type="tool_call", operation="vector_sync", attempt=3, status="started"),
        TraceEvent(line_number=10, event_type="tool_result", operation="vector_sync", attempt=3, status="failed", error_message="Connection timeout"),
        TraceEvent(line_number=11, event_type="agent_end", status="failed", error_message="Fatal abort"),
    ]

    report = detect_failures(events)

    # 1. Unrecovered execution finding exists
    unrec_findings = [f for f in report.findings if f.id == "RULE-UNRECOVERED-EXECUTION-FAILURE"]
    assert len(unrec_findings) == 1
    unrec = unrec_findings[0]

    # 2. Line 2 (load_configuration, success) MUST NOT be in failure line numbers
    assert 2 not in unrec.line_numbers

    # 3. Only genuine failure lines [4, 7, 10] plus terminal event [11] should be in line_numbers
    assert unrec.line_numbers == [4, 7, 10, 11]

    # 4. Error event count in evidence must only count genuine failure events (3), not setup (line 2)
    evidence_text = "\n".join(unrec.evidence)
    assert "Encountered 3 error event(s) across line(s): [4, 7, 10]" in evidence_text
    assert "Prior setup operation 'load_configuration' succeeded on Line 2" in evidence_text

    # 5. Terminal event is properly interpreted
    assert "Session ended in status 'failed'" in evidence_text
    assert "No successful tool or model operation was recorded following the error on Line 10" in evidence_text
