"""Data models and schema definitions for Last Signal trace events."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class EventType(str, Enum):
    """Standard lifecycle and execution event types."""
    AGENT_START = "agent_start"
    MODEL_CALL = "model_call"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    RETRY = "retry"
    AGENT_END = "agent_end"


STANDARD_EVENT_TYPES = {e.value for e in EventType}


class TraceError(Exception):
    """Base exception for trace parsing and validation errors."""
    pass


class TraceFileNotFoundError(TraceError):
    """Raised when the requested trace file does not exist."""
    pass


class TraceParseError(TraceError):
    """Raised when a trace line cannot be parsed or fails schema validation."""

    def __init__(self, line_number: int, reason: str, line_text: Optional[str] = None):
        self.line_number = line_number
        self.reason = reason
        self.line_text = line_text
        preview = f" (content: {line_text.strip()!r})" if line_text else ""
        super().__init__(f"Line {line_number}: {reason}{preview}")


@dataclass
class TraceEvent:
    """Represents a single verified trace event from a JSONL log.

    Attributes:
        line_number: 1-based line number in the source file.
        event_type: Identifier of the event (e.g., tool_call, agent_end).
        timestamp: Optional ISO 8601 timestamp string.
        trace_id: Optional correlation ID for the execution session.
        operation: Name of tool, model, or step executed (aliased to tool).
        status: Outcome status (e.g., success, failed, error, started).
        error_message: Descriptive error text if an error occurred.
        attempt: Attempt sequence count (1-based integer).
        metadata: Extra arbitrary fields provided in the event.
        raw: Full unprocessed dictionary as read from the source.
    """
    line_number: int
    event_type: str
    timestamp: Optional[str] = None
    trace_id: Optional[str] = None
    operation: Optional[str] = None
    status: Optional[str] = None
    error_message: Optional[str] = None
    attempt: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def tool(self) -> Optional[str]:
        """Convenience alias for operation."""
        return self.operation

    @property
    def error(self) -> Optional[str]:
        """Convenience alias for error_message."""
        return self.error_message

    @property
    def is_failure(self) -> bool:
        """Indicates whether this event represents a failure or error."""
        if self.status and self.status.lower() in {
            "success", "completed", "ok", "started", "pending", "running"
        }:
            return False
        if self.status and self.status.lower() in {"failed", "error", "fatal", "timed_out"}:
            return True
        return bool(self.error_message)

    def to_dict(self) -> Dict[str, Any]:
        """Return a clean dictionary representation of this event."""
        return {
            "line_number": self.line_number,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "trace_id": self.trace_id,
            "operation": self.operation,
            "status": self.status,
            "error_message": self.error_message,
            "attempt": self.attempt,
            "metadata": self.metadata,
        }


@dataclass
class TraceReadResult:
    """Result container for reading a JSONL trace file."""
    events: List[TraceEvent] = field(default_factory=list)
    errors: List[TraceParseError] = field(default_factory=list)
    total_lines: int = 0

    @property
    def valid_count(self) -> int:
        return len(self.events)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def is_valid(self) -> bool:
        return self.error_count == 0 and self.valid_count > 0


class Severity(str, Enum):
    """Severity levels for failure findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A deterministic observation or inferred pattern from trace analysis.

    Attributes:
        id: Unique rule identifier (e.g., RULE-REPEATED-TOOL-FAILURE).
        title: Short descriptive heading.
        severity: Severity level justified by trace evidence.
        explanation: Clear narrative explanation of the failure.
        line_numbers: Relevant trace line numbers.
        evidence: Concrete evidence strings (errors, attempts, statuses).
        recommendation: Practical, actionable debugging guidance.
        inferred: True if inferred from temporal/sequence correlation,
                  False if backed by explicit logged errors.
        metadata: Additional diagnostic context.
    """
    id: str
    title: str
    severity: Severity
    explanation: str
    line_numbers: List[int]
    evidence: List[str]
    recommendation: str
    inferred: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "line_numbers": self.line_numbers,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "inferred": self.inferred,
            "metadata": self.metadata,
        }


@dataclass
class AIDiagnosis:
    """Interpretation generated by a local open-weight model via Ollama.

    Attributes:
        available: True if local model was reachable and generated an interpretation.
        model_name: Name of the local model used (e.g. 'llama3.2:latest').
        summary: High-level incident diagnosis narrative.
        hypotheses: Grounded explanations of potential failure causes.
        evidence_citations: Explicit references to trace line numbers and events.
        recommendations: Suggested debugging and remediation steps.
        raw_response: Full text returned by the model.
        error: Descriptive error message if Ollama was unreachable or failed.
        uncertainty_note: Explicit statement of evidence limits or model uncertainty.
    """
    available: bool = False
    model_name: Optional[str] = None
    summary: Optional[str] = None
    hypotheses: List[str] = field(default_factory=list)
    evidence_citations: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    raw_response: Optional[str] = None
    error: Optional[str] = None
    uncertainty_note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert diagnosis to dictionary representation."""
        return {
            "available": self.available,
            "model_name": self.model_name,
            "summary": self.summary,
            "hypotheses": self.hypotheses,
            "evidence_citations": self.evidence_citations,
            "recommendations": self.recommendations,
            "error": self.error,
            "uncertainty_note": self.uncertainty_note,
        }


@dataclass
class AnalysisReport:
    """Overall report summarizing deterministic failure detection findings."""
    trace_id: Optional[str] = None
    total_events: int = 0
    findings: List[Finding] = field(default_factory=list)
    has_failures: bool = False
    agent_status: Optional[str] = None
    summary: str = ""
    ai_diagnosis: Optional[AIDiagnosis] = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary representation."""
        return {
            "trace_id": self.trace_id,
            "total_events": self.total_events,
            "has_failures": self.has_failures,
            "agent_status": self.agent_status,
            "summary": self.summary,
            "finding_count": self.finding_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "findings": [f.to_dict() for f in self.findings],
            "ai_diagnosis": self.ai_diagnosis.to_dict() if self.ai_diagnosis else None,
        }


