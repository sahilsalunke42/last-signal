"""Unit tests for local Ollama integration and AI diagnosis."""

import io
import json
import socket
import urllib.error
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from lastsignal.cli import app
from lastsignal.detector import detect_failures
from lastsignal.llm import (
    OllamaClient,
    diagnose_with_local_ai,
)
from lastsignal.models import (
    AIDiagnosis,
    AnalysisReport,
    Finding,
    Severity,
    TraceEvent,
)


class MockHTTPResponse:
    """Helper to mock urllib.request response objects."""

    def __init__(self, data: dict, status: int = 200):
        self.raw_bytes = json.dumps(data).encode("utf-8")
        self.status = status

    def read(self):
        return self.raw_bytes

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@pytest.fixture
def sample_report():
    events = [
        TraceEvent(line_number=1, event_type="agent_start", status="started"),
        TraceEvent(
            line_number=2,
            event_type="tool_call",
            operation="run_migration",
            status="failed",
            error_message="Connection refused: 5432",
        ),
        TraceEvent(
            line_number=3,
            event_type="tool_call",
            operation="run_migration",
            status="failed",
            error_message="Connection refused: 5432",
        ),
        TraceEvent(line_number=4, event_type="agent_end", status="failed"),
    ]
    report = detect_failures(events)
    return report, events


def test_ollama_successful_json_response(sample_report):
    """Verify parsing a structured JSON response from local Ollama."""
    report, events = sample_report

    mock_llm_json = {
        "summary": "Agent aborted after PostgreSQL database connection refused on port 5432.",
        "hypotheses": [
            "PostgreSQL staging instance was offline during the migration attempt.",
            "Network firewall or container port mapping misconfigured."
        ],
        "evidence_citations": [
            "Line 2: run_migration connection refused",
            "Line 3: run_migration connection refused"
        ],
        "recommendations": [
            "Verify PostgreSQL is running on port 5432.",
            "Check database credentials and network reachability before invoking migration tool."
        ],
        "uncertainty_note": "Trace does not include container logs or database server status."
    }

    client = OllamaClient(model="llama3.2:latest")

    with patch.object(client, "check_connectivity", return_value=(True, "0.1.32")):
        with patch.object(client, "is_model_available", return_value=(True, ["llama3.2:latest"])):
            with patch.object(client, "_http_request", return_value={"response": json.dumps(mock_llm_json)}):
                diag = client.generate_diagnosis(report, events)

    assert diag.available is True
    assert diag.model_name == "llama3.2:latest"
    assert "PostgreSQL" in diag.summary
    assert len(diag.hypotheses) == 2
    assert len(diag.evidence_citations) == 2
    assert len(diag.recommendations) == 2
    assert "container logs" in diag.uncertainty_note


def test_ollama_unavailable_server(sample_report):
    """Verify graceful fallback when Ollama daemon is offline."""
    report, events = sample_report
    client = OllamaClient(base_url="http://localhost:11434")

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        diag = client.generate_diagnosis(report, events)

    assert diag.available is False
    assert "unreachable" in diag.error.lower()
    assert "deterministic analysis" in diag.error.lower()


def test_ollama_missing_model(sample_report):
    """Verify graceful notice when target model is not installed locally."""
    report, events = sample_report
    client = OllamaClient(model="nonexistent-model:latest")

    with patch.object(client, "check_connectivity", return_value=(True, "0.1.32")):
        with patch.object(client, "list_models", return_value=["llama3.2:latest", "mistral:latest"]):
            diag = client.generate_diagnosis(report, events)

    assert diag.available is False
    assert "not installed in local ollama" in diag.error.lower()
    assert "ollama pull nonexistent-model:latest" in diag.error


def test_ollama_connection_timeout(sample_report):
    """Verify timeout handling during connectivity check or generation."""
    report, events = sample_report
    client = OllamaClient()

    with patch.object(client, "check_connectivity", return_value=(True, "0.1.32")):
        with patch.object(client, "is_model_available", return_value=(True, ["llama3.2:latest"])):
            with patch.object(client, "_http_request", side_effect=TimeoutError("Timed out")):
                diag = client.generate_diagnosis(report, events)

    assert diag.available is False
    assert "timed out" in diag.error.lower()


def test_ollama_empty_response(sample_report):
    """Verify handling when model returns blank text."""
    report, events = sample_report
    client = OllamaClient()

    with patch.object(client, "check_connectivity", return_value=(True, "0.1.32")):
        with patch.object(client, "is_model_available", return_value=(True, ["llama3.2:latest"])):
            with patch.object(client, "_http_request", return_value={"response": "   "}):
                diag = client.generate_diagnosis(report, events)

    assert diag.available is False
    assert "empty response" in diag.error.lower()


def test_ollama_plain_text_fallback(sample_report):
    """Verify fallback when model responds with plain text instead of JSON."""
    report, events = sample_report
    client = OllamaClient()

    raw_text = (
        "The migration failed due to a missing local database server.\n"
        "- The service was unreachable on port 5432\n"
        "- Ensure PostgreSQL daemon is running\n"
    )

    with patch.object(client, "check_connectivity", return_value=(True, "0.1.32")):
        with patch.object(client, "is_model_available", return_value=(True, ["llama3.2:latest"])):
            with patch.object(client, "_http_request", return_value={"response": raw_text}):
                diag = client.generate_diagnosis(report, events)

    assert diag.available is True
    assert "migration failed" in diag.summary
    assert len(diag.hypotheses) >= 1


def test_no_ai_flag_skips_all_network_calls(sample_report):
    """Verify that --no-ai does not make any network requests."""
    report, events = sample_report

    with patch("urllib.request.urlopen") as mock_url:
        diag = diagnose_with_local_ai(report, events, disabled=True)
        assert mock_url.called is False

    assert diag.available is False
    assert "--no-ai" in diag.error


def test_prompt_includes_ground_truth_findings(sample_report):
    """Verify that prompt builder injects deterministic findings as ground truth."""
    report, events = sample_report
    client = OllamaClient()
    prompt = client.build_prompt(report, events)

    assert "DETERMINISTIC FINDINGS (CONFIRMED GROUND TRUTH):" in prompt
    assert "RULE-REPEATED-TOOL-FAILURE" in prompt or "Repeated Failure in Tool" in prompt
    assert "Never invent events" in prompt


def test_cli_doctor_command_offline():
    """Verify lastsignal doctor output when Ollama is offline."""
    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "=== LAST SIGNAL SYSTEM DIAGNOSTICS ===" in result.output
    assert "Core Engine:" in result.output
    assert "Report Exporter:" in result.output
    assert "Local Ollama:" in result.output


def test_cli_doctor_command_online_mocked():
    """Verify lastsignal doctor output when Ollama is simulated online with models."""
    runner = CliRunner()
    with patch("lastsignal.llm.OllamaClient.check_connectivity", return_value=(True, "0.1.44")):
        with patch("lastsignal.llm.OllamaClient.list_models", return_value=["llama3.2:latest"]):
            with patch("lastsignal.llm.OllamaClient.is_model_available", return_value=(True, ["llama3.2:latest"])):
                result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "ONLINE (Daemon v0.1.44" in result.output
    assert "Target Model:        READY" in result.output
