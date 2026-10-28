"""Trace ingestion and validation module for Last Signal.

Reads JSONL trace logs line-by-line, validates events against the schema,
and flags malformed JSON or missing fields with precise line references.
"""

import json
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple, Union

from lastsignal.models import (
    TraceError,
    TraceEvent,
    TraceFileNotFoundError,
    TraceParseError,
    TraceReadResult,
)


def _parse_event_dict(raw: Dict[str, Any], line_number: int, line_text: str) -> TraceEvent:
    """Validate a parsed JSON dictionary and build a TraceEvent.

    Raises:
        TraceParseError: If required fields are missing or invalid.
    """
    if not isinstance(raw, dict):
        raise TraceParseError(
            line_number=line_number,
            reason=f"Expected JSON object, got {type(raw).__name__}",
            line_text=line_text,
        )

    # 1. Resolve event_type (required)
    event_type = raw.get("event_type") or raw.get("event") or raw.get("type")
    if not event_type:
        raise TraceParseError(
            line_number=line_number,
            reason="Missing required field: 'event_type' (or 'event')",
            line_text=line_text,
        )
    if not isinstance(event_type, str):
        raise TraceParseError(
            line_number=line_number,
            reason=f"'event_type' must be a string, got {type(event_type).__name__}",
            line_text=line_text,
        )
    event_type = event_type.strip()
    if not event_type:
        raise TraceParseError(
            line_number=line_number,
            reason="'event_type' cannot be an empty string",
            line_text=line_text,
        )

    # 2. Resolve optional fields with aliases
    timestamp = raw.get("timestamp") or raw.get("time") or raw.get("ts")
    if timestamp is not None and not isinstance(timestamp, str):
        timestamp = str(timestamp)

    trace_id = raw.get("trace_id") or raw.get("session_id")
    if trace_id is not None and not isinstance(trace_id, str):
        trace_id = str(trace_id)

    operation = (
        raw.get("operation")
        or raw.get("tool")
        or raw.get("tool_name")
        or raw.get("action")
    )
    if operation is not None and not isinstance(operation, str):
        operation = str(operation)

    status = raw.get("status") or raw.get("state") or raw.get("outcome")
    if status is not None and not isinstance(status, str):
        status = str(status)

    error_message = (
        raw.get("error_message")
        or raw.get("error")
        or raw.get("err")
        or raw.get("exception")
    )
    if error_message is not None and not isinstance(error_message, str):
        error_message = str(error_message)

    # Attempt sequence count
    attempt_val = raw.get("attempt") or raw.get("attempt_number") or raw.get("try_count")
    attempt: Optional[int] = None
    if attempt_val is not None:
        try:
            attempt = int(attempt_val)
        except (ValueError, TypeError):
            attempt = None

    # Metadata & unmapped extra fields
    metadata = {}
    if isinstance(raw.get("metadata"), dict):
        metadata.update(raw["metadata"])

    mapped_keys = {
        "event_type", "event", "type",
        "timestamp", "time", "ts",
        "trace_id", "session_id", "id",
        "operation", "tool", "tool_name", "action",
        "status", "state", "outcome",
        "error_message", "error", "err", "exception",
        "attempt", "attempt_number", "try_count",
        "metadata",
    }
    for k, v in raw.items():
        if k not in mapped_keys and k not in metadata:
            metadata[k] = v

    return TraceEvent(
        line_number=line_number,
        event_type=event_type,
        timestamp=timestamp,
        trace_id=trace_id,
        operation=operation,
        status=status,
        error_message=error_message,
        attempt=attempt,
        metadata=metadata,
        raw=raw,
    )


def iter_trace_events(
    path: Union[str, Path],
    ignore_empty_lines: bool = True,
) -> Iterator[Tuple[int, Optional[TraceEvent], Optional[TraceParseError]]]:
    """Stream events from a JSONL trace file line-by-line.

    Yields:
        Tuple of (line_number, event_or_none, error_or_none)
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise TraceFileNotFoundError(f"Trace file not found: {file_path}")

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_number, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                if ignore_empty_lines:
                    continue
                yield (line_number, None, TraceParseError(line_number, "Empty line encountered", line))
                continue

            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                err = TraceParseError(
                    line_number=line_number,
                    reason=f"Malformed JSON: {exc.msg} at column {exc.colno}",
                    line_text=stripped,
                )
                yield (line_number, None, err)
                continue

            try:
                event = _parse_event_dict(data, line_number=line_number, line_text=stripped)
                yield (line_number, event, None)
            except TraceParseError as err:
                yield (line_number, None, err)


def read_trace(
    path: Union[str, Path],
    raise_on_error: bool = False,
    ignore_empty_lines: bool = True,
) -> TraceReadResult:
    """Read and validate a complete JSONL trace file.

    Args:
        path: Path to the JSONL trace file.
        raise_on_error: If True, immediately raise the first TraceParseError encountered.
        ignore_empty_lines: If True, blank lines are ignored without generating errors.

    Returns:
        TraceReadResult containing parsed events and any validation errors.

    Raises:
        TraceFileNotFoundError: If the file does not exist.
        TraceParseError: If raise_on_error is True and any line fails validation.
    """
    result = TraceReadResult()

    for line_number, event, error in iter_trace_events(path, ignore_empty_lines=ignore_empty_lines):
        result.total_lines = line_number
        if error:
            if raise_on_error:
                raise error
            result.errors.append(error)
        elif event:
            result.events.append(event)

    return result
