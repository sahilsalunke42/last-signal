"""Deterministic failure pattern detector for Last Signal.

Analyzes parsed trace events to identify repeated tool failures, unbroken retry loops,
terminal tool crashes, and unrecovered execution states using deterministic heuristics.
"""

from typing import Dict, List, Optional, Set
from lastsignal.models import (
    AnalysisReport,
    Finding,
    Severity,
    TraceEvent,
)


class FailureDetector:
    """Deterministic rule-based failure pattern detector."""

    def __init__(
        self,
        repeated_failure_threshold: int = 2,
    ):
        """Initialize detector with configurable thresholds.

        Args:
            repeated_failure_threshold: Minimum failure count to trigger repeated failure rule.
        """
        self.repeated_failure_threshold = repeated_failure_threshold

    def analyze(self, events: List[TraceEvent], trace_id: Optional[str] = None) -> AnalysisReport:
        """Run all deterministic failure detection rules against a trace event sequence.

        Args:
            events: List of validated TraceEvent objects.
            trace_id: Optional override for the trace identifier.

        Returns:
            AnalysisReport containing detected findings and execution summary.
        """
        if not events:
            return AnalysisReport(
                trace_id=trace_id,
                total_events=0,
                findings=[],
                has_failures=False,
                agent_status="empty",
                summary="Empty trace: no events recorded.",
            )

        resolved_trace_id = trace_id or self._extract_trace_id(events)
        agent_end_event = self._find_agent_end(events)
        agent_status = self._determine_agent_status(events, agent_end_event)

        findings: List[Finding] = []

        # Rule 1: Repeated failures from the same tool
        findings.extend(self._check_repeated_tool_failures(events, agent_end_event))

        # Rule 2: Repeated retries without a successful result
        findings.extend(self._check_unproductive_retries(events))

        # Rule 3: Tool calls that fail immediately before agent terminates unsuccessfully
        terminal_finding = self._check_terminal_tool_failure(events, agent_end_event)
        if terminal_finding:
            findings.append(terminal_finding)

        # Rule 4: Failed executions with no clear recovery event
        unrecovered_finding = self._check_unrecovered_execution(events, agent_end_event, agent_status)
        if unrecovered_finding:
            findings.append(unrecovered_finding)

        has_failures = bool(findings) or any(e.is_failure for e in events)

        # Build concise executive summary
        summary = self._build_summary(events, findings, agent_status)

        return AnalysisReport(
            trace_id=resolved_trace_id,
            total_events=len(events),
            findings=findings,
            has_failures=has_failures,
            agent_status=agent_status,
            summary=summary,
        )

    # -------------------------------------------------------------------------
    # Helper extractors
    # -------------------------------------------------------------------------

    def _extract_trace_id(self, events: List[TraceEvent]) -> Optional[str]:
        for e in events:
            if e.trace_id:
                return e.trace_id
        return None

    def _find_agent_end(self, events: List[TraceEvent]) -> Optional[TraceEvent]:
        for e in reversed(events):
            if e.event_type == "agent_end":
                return e
        return None

    def _determine_agent_status(
        self, events: List[TraceEvent], agent_end_event: Optional[TraceEvent]
    ) -> str:
        if agent_end_event:
            return agent_end_event.status or ("failed" if agent_end_event.is_failure else "completed")
        if any(e.is_failure for e in events):
            return "terminated_abruptly"
        return "incomplete"

    # -------------------------------------------------------------------------
    # Rule 1: Repeated Failures from the Same Tool
    # -------------------------------------------------------------------------

    def _check_repeated_tool_failures(
        self, events: List[TraceEvent], agent_end_event: Optional[TraceEvent]
    ) -> List[Finding]:
        """Detect tools that fail repeatedly across the execution."""
        findings: List[Finding] = []

        # Group failed tool events by operation name
        # Filter out session lifecycle events (agent_start, agent_end)
        tool_failures: Dict[str, List[TraceEvent]] = {}

        # Track (operation, attempt) to avoid double counting tool_call + tool_result for same attempt
        seen_attempts: Set[tuple] = set()

        for e in events:
            if e.event_type in {"agent_start", "agent_end"}:
                continue
            if not e.is_failure:
                continue

            op = e.operation or "unspecified_tool"
            attempt_key = (op, e.attempt) if e.attempt is not None else (op, f"line_{e.line_number}")

            if attempt_key in seen_attempts:
                # Merge line number into existing failure record if consecutive
                if tool_failures.get(op):
                    existing = tool_failures[op][-1]
                    if e.line_number not in (existing.line_number,):
                        # Still record the line in metadata
                        pass
                continue

            seen_attempts.add(attempt_key)
            tool_failures.setdefault(op, []).append(e)

        for op, fails in tool_failures.items():
            if len(fails) >= self.repeated_failure_threshold:
                line_nums = [f.line_number for f in fails]
                fail_count = len(fails)

                # Severity is CRITICAL if it ended the agent or failed 3+ times
                is_fatal = (
                    agent_end_event is not None
                    and agent_end_event.is_failure
                    and any(f.line_number == fails[-1].line_number for f in fails)
                )
                severity = Severity.CRITICAL if (fail_count >= 3 or is_fatal) else Severity.HIGH

                evidence = [
                    f"Tool '{op}' recorded {fail_count} failure events on line(s): {line_nums}."
                ]
                for f in fails:
                    err_text = f.error_message or f.status or "unspecified error"
                    attempt_str = f" (attempt {f.attempt})" if f.attempt else ""
                    evidence.append(f"Line {f.line_number}{attempt_str}: {err_text}")

                findings.append(
                    Finding(
                        id="RULE-REPEATED-TOOL-FAILURE",
                        title=f"Repeated Failure in Tool '{op}'",
                        severity=severity,
                        explanation=(
                            f"Tool '{op}' failed {fail_count} times during execution. "
                            f"Persistent failure indicates an unhandled error condition, environmental "
                            f"misconfiguration, or invalid input parameters."
                        ),
                        line_numbers=line_nums,
                        evidence=evidence,
                        recommendation=(
                            f"Check external service dependencies, environment credentials, and arguments "
                            f"passed to '{op}'. Consider adding a fallback alternative tool if this service is unstable."
                        ),
                        inferred=False,  # Explicitly logged failure statuses
                        metadata={"operation": op, "failure_count": fail_count},
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Rule 2: Repeated Retries Without a Successful Result
    # -------------------------------------------------------------------------

    def _check_unproductive_retries(self, events: List[TraceEvent]) -> List[Finding]:
        """Detect retry sequences that fail to yield a successful result."""
        findings: List[Finding] = []

        # Track operations that had retries or multiple attempts
        operations: Dict[str, List[TraceEvent]] = {}
        for e in events:
            if e.event_type in {"agent_start", "agent_end"}:
                continue
            if e.operation:
                operations.setdefault(e.operation, []).append(e)

        for op, op_events in operations.items():
            # Look for retry indicators:
            # - events with event_type == "retry"
            # - attempts > 1
            # - repeated invocations with failures
            retry_events = [e for e in op_events if e.event_type == "retry"]
            max_attempt = max((e.attempt for e in op_events if e.attempt is not None), default=1)
            failure_events = [e for e in op_events if e.is_failure]

            has_retries = bool(retry_events) or (max_attempt > 1) or (len(failure_events) >= 2)
            if not has_retries:
                continue

            # Check if any event for this operation succeeded AFTER the first failure or retry
            first_fail_idx = None
            for idx, e in enumerate(op_events):
                if e.is_failure or e.event_type == "retry":
                    first_fail_idx = idx
                    break

            if first_fail_idx is None:
                continue

            subsequent_success = any(
                (e.status and e.status.lower() == "success" and not e.is_failure)
                for e in op_events[first_fail_idx + 1 :]
            )

            if not subsequent_success:
                relevant_lines = sorted(
                    list({e.line_number for e in op_events if e.is_failure or e.event_type == "retry"})
                )
                evidence = [
                    f"Operation '{op}' made {max(max_attempt, len(failure_events))} recorded attempt(s) without subsequent success."
                ]
                for r in retry_events:
                    evidence.append(
                        f"Line {r.line_number}: retry attempt={r.attempt or 'unknown'} status={r.status or 'pending'}"
                    )
                for f in failure_events:
                    evidence.append(
                        f"Line {f.line_number}: failed attempt={f.attempt or 'unknown'} error={f.error_message or f.status}"
                    )

                findings.append(
                    Finding(
                        id="RULE-UNPRODUCTIVE-RETRY-LOOP",
                        title=f"Unproductive Retry Loop for '{op}'",
                        severity=Severity.HIGH,
                        explanation=(
                            f"Operation '{op}' entered a retry cycle but never recovered. "
                            f"All recorded retry attempts continued to fail without an intervening success."
                        ),
                        line_numbers=relevant_lines,
                        evidence=evidence,
                        recommendation=(
                            f"Implement exponential backoff, circuit breaking, or classify '{op}' errors "
                            f"as non-retryable to avoid exhausting execution budget on permanent failures."
                        ),
                        inferred=True,  # Inferred from chronological progression without recovery
                        metadata={"operation": op, "attempt_count": max(max_attempt, len(failure_events))},
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Rule 3: Tool Call Failing Immediately Before Unsuccessful Agent Termination
    # -------------------------------------------------------------------------

    def _check_terminal_tool_failure(
        self, events: List[TraceEvent], agent_end_event: Optional[TraceEvent]
    ) -> Optional[Finding]:
        """Detect if the last executed tool call failed directly before session termination."""
        # Condition: agent ended in failure or ended abruptly
        is_terminal_failure = False
        terminal_event = agent_end_event or (events[-1] if events else None)

        if agent_end_event:
            is_terminal_failure = agent_end_event.is_failure
        elif events and events[-1].is_failure:
            is_terminal_failure = True

        if not is_terminal_failure or not terminal_event:
            return None

        # Look backward from terminal event for the last tool/model event
        last_tool_event: Optional[TraceEvent] = None
        for e in reversed(events):
            if e.line_number == terminal_event.line_number:
                continue
            if e.event_type in {"tool_call", "tool_result", "model_call"}:
                last_tool_event = e
                break

        if not last_tool_event or not last_tool_event.is_failure:
            return None

        op = last_tool_event.operation or "unspecified_tool"
        line_nums = sorted(list({last_tool_event.line_number, terminal_event.line_number}))

        evidence = [
            f"Line {last_tool_event.line_number}: Tool '{op}' failed with error: {last_tool_event.error_message or last_tool_event.status}",
            f"Line {terminal_event.line_number}: Agent terminated with status '{terminal_event.status or 'failed'}'"
            + (f" error: {terminal_event.error_message}" if terminal_event.error_message else ""),
        ]

        return Finding(
            id="RULE-TERMINAL-TOOL-FAILURE",
            title=f"Terminal Tool Failure in '{op}' Preceding Agent Abort",
            severity=Severity.CRITICAL,
            explanation=(
                f"Tool '{op}' failed immediately before the agent terminated unsuccessfully. "
                f"The failure of this tool is the proximate event preceding session failure."
            ),
            line_numbers=line_nums,
            evidence=evidence,
            recommendation=(
                f"Wrap calls to '{op}' in comprehensive exception handling or fallback logic. "
                f"Ensure the agent can handle tool failures gracefully without crashing the overall session."
            ),
            inferred=True,  # Inferred causal relationship based on temporal proximity
            metadata={"terminal_operation": op, "proximate_line": last_tool_event.line_number},
        )

    # -------------------------------------------------------------------------
    # Rule 4: Failed Executions with No Clear Recovery Event
    # -------------------------------------------------------------------------

    def _check_unrecovered_execution(
        self,
        events: List[TraceEvent],
        agent_end_event: Optional[TraceEvent],
        agent_status: str,
    ) -> Optional[Finding]:
        """Detect sessions that encountered errors and terminated without recovery."""
        # Find genuine operational failures (exclude lifecycle events like agent_start and agent_end)
        op_failures = [
            e for e in events
            if e.is_failure and e.event_type not in {"agent_start", "agent_end"}
        ]

        has_terminal_failure = (
            agent_status in {"failed", "fatal", "error", "terminated_abruptly"}
            or (agent_end_event is not None and agent_end_event.is_failure)
        )

        if not op_failures and not has_terminal_failure:
            return None

        # Check if any tool/model succeeded AFTER the last operational failure
        if op_failures:
            last_op_failure = op_failures[-1]
            subsequent_successes = [
                e
                for e in events
                if e.line_number > last_op_failure.line_number
                and e.event_type in {"tool_call", "tool_result", "model_call"}
                and (e.status and e.status.lower() in {"success", "completed", "ok"})
                and not e.is_failure
            ]
            # If a subsequent operation succeeded, the agent recovered!
            if subsequent_successes:
                return None

        # Check if the execution ended in an unrecovered state
        is_unrecovered = (
            has_terminal_failure
            or (agent_end_event is None)  # ended abruptly
        )

        if not is_unrecovered:
            return None

        # Determine genuine error events and lines
        if op_failures:
            error_event_lines = [f.line_number for f in op_failures]
            error_count = len(op_failures)
            last_failure_line = op_failures[-1].line_number
        elif agent_end_event:
            error_event_lines = [agent_end_event.line_number]
            error_count = 1
            last_failure_line = agent_end_event.line_number
        else:
            error_event_lines = [events[-1].line_number] if events else []
            error_count = len(error_event_lines)
            last_failure_line = error_event_lines[-1] if error_event_lines else 1

        # Finding line numbers: genuine failure lines plus the final agent_end resolution line
        failed_lines = list(error_event_lines)
        if agent_end_event and agent_end_event.line_number not in failed_lines:
            failed_lines.append(agent_end_event.line_number)
        failed_lines = sorted(list(set(failed_lines)))

        # Build evidence
        evidence = [
            f"Session ended in status '{agent_status}'.",
        ]

        # Preserve successful setup operations as evidence without classifying them as failures
        first_fail_line = (
            op_failures[0].line_number
            if op_failures
            else (agent_end_event.line_number if agent_end_event else float("inf"))
        )
        setup_successes = [
            e
            for e in events
            if e.event_type in {"tool_call", "tool_result", "model_call"}
            and (e.status and e.status.lower() in {"success", "completed", "ok"})
            and e.line_number < first_fail_line
            and not e.is_failure
        ]
        for s in setup_successes:
            op_name = s.operation or "setup_operation"
            evidence.append(
                f"Prior setup operation '{op_name}' succeeded on Line {s.line_number}."
            )

        evidence.append(
            f"Encountered {error_count} error event(s) across line(s): {error_event_lines}."
        )
        evidence.append(
            f"No successful tool or model operation was recorded following the error on Line {last_failure_line}."
        )

        explanation = (
            "The execution encountered errors and terminated without any subsequent successful recovery "
            "operations. The agent failed to self-correct or transition to an alternate execution path."
        )

        recommendation = (
            "Implement global self-correction prompts, retry budgets, or secondary fallback tools "
            "so the agent does not terminate ungracefully upon encountering unhandled tool errors."
        )

        return Finding(
            id="RULE-UNRECOVERED-EXECUTION-FAILURE",
            title="Unrecovered Execution Failure",
            severity=Severity.HIGH,
            explanation=explanation,
            line_numbers=failed_lines,
            evidence=evidence,
            recommendation=recommendation,
            inferred=(agent_end_event is None),  # Inferred if session halted abruptly without agent_end
            metadata={"status": agent_status, "total_failures": error_count},
        )

    # -------------------------------------------------------------------------
    # Summary builder
    # -------------------------------------------------------------------------

    def _build_summary(
        self,
        events: List[TraceEvent],
        findings: List[Finding],
        agent_status: str,
    ) -> str:
        if not findings:
            if agent_status in {"success", "completed"}:
                return "Execution completed successfully with no detected failure patterns."
            return f"Trace analyzed ({len(events)} events): no deterministic failure patterns detected."

        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

        return (
            f"Detected {len(findings)} failure pattern(s) across {len(events)} events: "
            f"{critical_count} critical, {high_count} high severity. Session status: '{agent_status}'."
        )


def detect_failures(
    events: List[TraceEvent],
    trace_id: Optional[str] = None,
    repeated_failure_threshold: int = 2,
) -> AnalysisReport:
    """Convenience function to run deterministic failure detection.

    Args:
        events: List of validated TraceEvent objects.
        trace_id: Optional trace ID override.
        repeated_failure_threshold: Threshold for repeated failure rule.

    Returns:
        AnalysisReport containing all findings.
    """
    detector = FailureDetector(repeated_failure_threshold=repeated_failure_threshold)
    return detector.analyze(events, trace_id=trace_id)
