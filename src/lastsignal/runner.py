"""Process execution supervisor and automatic trace capture engine for Last Signal.

Executes user-provided commands safely without shell invocation, streams and captures
stdout/stderr, writes validated JSONL trace events, and automatically triggers
deterministic failure analysis and local AI diagnosis upon process failure.
"""

import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lastsignal.models import TraceError

# Regular expressions for detecting structured agent tool execution tags in stream lines
_TAG_REGEX = re.compile(
    r"\[(?P<type>tool_call|tool_result|model_call|retry|agent_start|agent_end)\]\s*(?P<rest>.*)",
    re.IGNORECASE,
)
_KV_REGEX = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

# Common exception pattern in stderr (e.g., "OperationalError: ...", "TimeoutError: ...")
_EXCEPTION_REGEX = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?P<exc>[A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Timeout|Fault|Failure)):\s*(?P<msg>.*)"
)


class RunnerError(TraceError):
    """Base exception for process execution and trace capture errors."""
    pass


class CommandNotFoundError(RunnerError):
    """Raised when the specified executable cannot be found in PATH."""
    pass


class CommandExecutionError(RunnerError):
    """Raised when an error occurs while launching or supervising the command."""
    pass


class TraceWriteError(RunnerError):
    """Raised when the captured trace file cannot be written to disk."""
    pass


def _iso_now() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stream_line(
    line: str,
    line_number: int,
    trace_id: str,
    timestamp: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Inspect an output line for structured agent events.

    Detects:
      1. Raw JSON objects with 'event' or 'event_type'.
      2. Structured log tags like '[tool_call] tool=db_query status=started'.
      3. Python/system exception signatures in stderr.
    """
    stripped = line.strip()
    if not stripped:
        return None

    ts = timestamp or _iso_now()

    # 1. Attempt raw JSON parse
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                ev_type = data.get("event_type") or data.get("event") or data.get("type")
                if ev_type:
                    data.setdefault("trace_id", trace_id)
                    data.setdefault("timestamp", ts)
                    return data
        except json.JSONDecodeError:
            pass

    # 2. Check for structured bracket tags [tool_call], [tool_result], [retry], etc.
    tag_match = _TAG_REGEX.search(stripped)
    if tag_match:
        ev_type = tag_match.group("type").lower()
        rest = tag_match.group("rest")
        kvs: Dict[str, Any] = {}
        for key, val_quoted, val_unquoted in _KV_REGEX.findall(rest):
            val = val_quoted if val_quoted != "" else val_unquoted
            if key in ("attempt", "attempt_number", "try_count"):
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    pass
            kvs[key] = val

        event_dict: Dict[str, Any] = {
            "timestamp": ts,
            "trace_id": trace_id,
            "event_type": ev_type,
        }
        if "tool" in kvs:
            event_dict["operation"] = kvs["tool"]
        elif "operation" in kvs:
            event_dict["operation"] = kvs["operation"]

        if "status" in kvs:
            event_dict["status"] = kvs["status"]
        if "error" in kvs:
            event_dict["error_message"] = kvs["error"]
        elif "error_message" in kvs:
            event_dict["error_message"] = kvs["error_message"]
        if "attempt" in kvs:
            event_dict["attempt"] = kvs["attempt"]

        # Collect extra metadata
        known = {"tool", "operation", "status", "error", "error_message", "attempt"}
        extra = {k: v for k, v in kvs.items() if k not in known}
        if extra:
            event_dict["metadata"] = extra

        return event_dict

    # 3. Detect standard Python/system fatal exception lines (process-level errors)
    exc_match = _EXCEPTION_REGEX.search(stripped)
    if exc_match:
        exc_type = exc_match.group("exc")
        exc_msg = exc_match.group("msg").strip()
        return {
            "timestamp": ts,
            "trace_id": trace_id,
            "event_type": "process_error",
            "status": "fatal",
            "error_message": f"{exc_type}: {exc_msg}" if exc_msg else exc_type,
            "metadata": {
                "exception_type": exc_type,
            },
        }

    return None


def run_and_capture(
    command: List[str],
    trace_output_path: Optional[Path] = None,
    stream_output: bool = True,
) -> Tuple[int, Path, List[Dict[str, Any]]]:
    """Execute a command safely, stream its output, and write a JSONL trace file.

    Args:
        command: Command and argument list to execute (never invoked through a shell).
        trace_output_path: Destination path for the captured JSONL trace file.
        stream_output: If True, streams stdout and stderr in real time to the terminal.

    Returns:
        Tuple of (exit_code, trace_file_path, list_of_captured_events).

    Raises:
        CommandNotFoundError: If the target executable is not found.
        CommandExecutionError: If launching the process fails.
        TraceWriteError: If writing the trace file fails.
    """
    if not command:
        raise ValueError("No command provided to execute.")

    trace_id = f"tr-auto-{uuid.uuid4().hex[:8]}"
    start_ts = _iso_now()
    start_perf = time.perf_counter()

    # Determine default trace path if not provided: .lastsignal/traces/trace_<timestamp>_<id>.jsonl
    if trace_output_path is None:
        safe_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        trace_dir = Path(".lastsignal") / "traces"
        trace_file = trace_dir / f"trace_{safe_ts}_{trace_id}.jsonl"
    else:
        trace_file = Path(trace_output_path).resolve()

    if trace_file.is_dir():
        raise TraceWriteError(
            f"Cannot write trace to '{trace_file}': target path is an existing directory."
        )

    # 1. Initialize event sequence with agent_start
    events: List[Dict[str, Any]] = [
        {
            "timestamp": start_ts,
            "trace_id": trace_id,
            "event_type": "agent_start",
            "status": "started",
            "metadata": {
                "command": " ".join(command),
                "executable": command[0],
            },
        }
    ]

    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    unified_lines: List[str] = []
    lines_lock = threading.Lock()

    def _reader(pipe, sink: List[str], out_stream):
        try:
            for line in iter(pipe.readline, ""):
                with lines_lock:
                    sink.append(line)
                    unified_lines.append(line)
                if stream_output and out_stream:
                    out_stream.write(line)
                    out_stream.flush()
        finally:
            pipe.close()

    # 2. Execute process securely (shell=False strictly enforced)
    run_env = dict(os.environ)
    run_env["PYTHONUNBUFFERED"] = "1"
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            shell=False,
            env=run_env,
        )
    except FileNotFoundError as exc:
        raise CommandNotFoundError(
            f"Command executable not found: '{command[0]}'. Verify the binary name and PATH."
        ) from exc
    except PermissionError as exc:
        raise CommandExecutionError(
            f"Permission denied executing '{command[0]}'."
        ) from exc
    except Exception as exc:
        raise CommandExecutionError(f"Failed to execute command '{command[0]}': {exc}") from exc

    # 3. Read streams with background threads to avoid pipe deadlocks
    t_out = threading.Thread(
        target=_reader,
        args=(proc.stdout, stdout_lines, sys.stdout),
        daemon=True,
    )
    t_err = threading.Thread(
        target=_reader,
        args=(proc.stderr, stderr_lines, sys.stderr),
        daemon=True,
    )
    t_out.start()
    t_err.start()

    exit_code = 0
    try:
        exit_code = proc.wait()
    except KeyboardInterrupt:
        # Gracefully terminate child process if user interrupts
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        exit_code = 130  # Standard exit code for SIGINT (128 + 2)
    finally:
        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)

    end_ts = _iso_now()
    duration = time.perf_counter() - start_perf

    # 4. Extract structured events from captured output streams
    all_captured_lines = unified_lines
    for idx, raw_line in enumerate(all_captured_lines, start=2):
        parsed = parse_stream_line(raw_line, line_number=idx, trace_id=trace_id)
        if parsed:
            events.append(parsed)

    # If the process exited with an error and no failures were detected in stream lines,
    # capture the final stderr error or nonzero exit as a process-level error event
    has_recorded_failures = any(
        e.get("status") in ("failed", "error", "fatal") or bool(e.get("error_message"))
        for e in events[1:]
    )
    if exit_code != 0 and not has_recorded_failures:
        clean_err = "".join(stderr_lines).strip()
        summary_err = clean_err.splitlines()[-1] if clean_err else f"Process exited with nonzero status {exit_code}"
        events.append(
            {
                "timestamp": end_ts,
                "trace_id": trace_id,
                "event_type": "process_error",
                "status": "fatal",
                "error_message": summary_err,
            }
        )

    # 5. Append terminal agent_end event
    terminal_status = "success" if exit_code == 0 else "failed"
    end_event: Dict[str, Any] = {
        "timestamp": end_ts,
        "trace_id": trace_id,
        "event_type": "agent_end",
        "status": terminal_status,
        "metadata": {
            "exit_code": exit_code,
            "duration_seconds": round(duration, 3),
        },
    }
    if exit_code != 0:
        clean_err = "".join(stderr_lines).strip()
        end_event["error_message"] = (
            clean_err.splitlines()[-1] if clean_err else f"Process failed with exit code {exit_code}"
        )

    events.append(end_event)

    # 6. Write JSONL trace file to disk
    try:
        trace_file.parent.mkdir(parents=True, exist_ok=True)
        with trace_file.open("w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")
    except (PermissionError, OSError) as exc:
        raise TraceWriteError(f"Failed to write trace to '{trace_file}': {exc}") from exc

    return exit_code, trace_file, events
