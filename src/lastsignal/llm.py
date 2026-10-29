"""Local Ollama integration module for Last Signal.

Connects strictly to local Ollama HTTP endpoints to produce evidence-grounded
hypotheses and remediation recommendations from deterministic trace findings.
Zero remote cloud calls, zero telemetry, zero automatic model downloads.
"""

import json
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from lastsignal.models import (
    AIDiagnosis,
    AnalysisReport,
    TraceEvent,
)

DEFAULT_OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:latest")
DEFAULT_CONNECT_TIMEOUT = 3.0
DEFAULT_REQUEST_TIMEOUT = 60.0


class OllamaClient:
    """HTTP client for communicating strictly with a local Ollama daemon."""

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_OLLAMA_MODEL,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    ):
        """Initialize Ollama client.

        Args:
            base_url: Base URL of local Ollama instance (default: http://localhost:11434).
            model: Name of the local model to use (default: llama3.2:latest).
            timeout: Request response timeout in seconds.
            connect_timeout: Connection attempt timeout in seconds.
        """
        # Clean URL and ensure scheme
        url = base_url.strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        self.base_url = url
        self.model = model
        self.timeout = timeout
        self.connect_timeout = connect_timeout

    def _http_request(
        self,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Send an HTTP request to the local Ollama instance.

        Raises:
            urllib.error.URLError: On network or connection failures.
            urllib.error.HTTPError: On non-200 HTTP response codes.
            TimeoutError: When requests exceed timeout duration.
        """
        url = f"{self.base_url}{path}"
        req_timeout = timeout or self.timeout

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "LastSignal-ForensicClient/0.1.0",
        }

        body = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method="POST" if data is not None else "GET",
        )

        with urllib.request.urlopen(req, timeout=req_timeout) as resp:
            content = resp.read().decode("utf-8")
            return json.loads(content) if content else {}

    def check_connectivity(self) -> Tuple[bool, Optional[str]]:
        """Verify connectivity to local Ollama server.

        Returns:
            Tuple of (is_connected, version_or_error_string).
        """
        try:
            res = self._http_request("/api/version", timeout=self.connect_timeout)
            version = res.get("version", "unknown")
            return True, str(version)
        except (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionRefusedError) as exc:
            reason = getattr(exc, "reason", str(exc))
            return False, f"Cannot connect to local Ollama at {self.base_url}: {reason}"
        except Exception as exc:
            return False, f"Unexpected error connecting to Ollama: {exc}"

    def list_models(self) -> List[str]:
        """Fetch list of models locally installed in Ollama.

        Returns:
            List of model names (e.g. ['llama3.2:latest', 'qwen2.5:latest']).
        """
        try:
            res = self._http_request("/api/tags", timeout=self.connect_timeout)
            models_info = res.get("models", [])
            names: List[str] = []
            for m in models_info:
                name = m.get("name") or m.get("model")
                if name:
                    names.append(name)
            return names
        except Exception:
            return []

    def is_model_available(self, target_model: Optional[str] = None) -> Tuple[bool, List[str]]:
        """Check if target model is installed locally in Ollama.

        Returns:
            Tuple of (is_available, list_of_all_available_models).
        """
        model_name = target_model or self.model
        available = self.list_models()

        # Check exact match or match without tag suffix (e.g. 'llama3.2' vs 'llama3.2:latest')
        target_base = model_name.split(":")[0]
        for item in available:
            if item == model_name or item.split(":")[0] == target_base:
                return True, available

        return False, available

    def build_prompt(self, report: AnalysisReport, events: List[TraceEvent]) -> str:
        """Construct a compact, evidence-bounded prompt for local LLM inference."""
        findings_summary = []
        for f in report.findings:
            findings_summary.append(
                f"- [{f.severity.value}] {f.title} (Lines {f.line_numbers}): {f.explanation}"
            )
            for ev in f.evidence[:3]:
                findings_summary.append(f"    * {ev}")

        # Compact timeline of relevant failure / error events
        key_events = []
        for e in events:
            if e.is_failure or e.event_type in {"agent_start", "agent_end", "retry"}:
                status_str = f"status={e.status}" if e.status else ""
                err_str = f"error={e.error_message}" if e.error_message else ""
                op_str = f"op={e.operation}" if e.operation else ""
                key_events.append(f"Line {e.line_number}: {e.event_type} {op_str} {status_str} {err_str}".strip())

        prompt_lines = [
            "You are the Last Signal forensic analysis assistant. You are investigating a failed AI-agent execution.",
            "You must use the deterministic findings provided below as the immutable ground truth.",
            "Never invent events, line numbers, or tool outputs not present in the trace.",
            "",
            f"Trace ID: {report.trace_id or 'Unknown'}",
            f"Session Outcome: {report.agent_status or 'Unknown'}",
            f"Total Trace Events: {report.total_events}",
            "",
            "DETERMINISTIC FINDINGS (CONFIRMED GROUND TRUTH):",
            "\n".join(findings_summary) if findings_summary else "No recurring deterministic findings.",
            "",
            "KEY EVENT SEQUENCE:",
            "\n".join(key_events) if key_events else "No failure events.",
            "",
            "INSTRUCTIONS:",
            "1. Explain what likely caused the execution failure based strictly on the provided findings.",
            "2. Distinguish confirmed facts (backed by explicit errors) from hypotheses (inferred sequence patterns).",
            "3. Cite relevant event line numbers.",
            "4. Recommend practical, actionable debugging steps.",
            "5. Explicitly note any uncertainty where evidence is insufficient.",
            "6. Output ONLY a valid JSON object with the following schema:",
            "{",
            '  "summary": "Concise 1-2 sentence incident diagnosis",',
            '  "hypotheses": ["Hypothesis 1 citing specific lines", "Hypothesis 2..."],',
            '  "evidence_citations": ["Line X: ...", "Line Y: ..."],',
            '  "recommendations": ["Actionable remediation step 1", "Step 2..."],',
            '  "uncertainty_note": "Limits of the trace evidence"',
            "}",
        ]
        return "\n".join(prompt_lines)

    def generate_diagnosis(
        self,
        report: AnalysisReport,
        events: List[TraceEvent],
    ) -> AIDiagnosis:
        """Run evidence-grounded local AI diagnosis against deterministic report.

        Falls back gracefully if Ollama is unreachable, model is missing, or
        request times out.
        """
        # 1. Verify connectivity
        connected, version_or_err = self.check_connectivity()
        if not connected:
            return AIDiagnosis(
                available=False,
                model_name=self.model,
                error=(
                    f"Local Ollama daemon is unreachable ({version_or_err}). "
                    "Skipping AI diagnosis and continuing with deterministic analysis."
                ),
            )

        # 2. Verify model presence
        available, installed_models = self.is_model_available()
        if not available:
            models_str = ", ".join(f"'{m}'" for m in installed_models) if installed_models else "none"
            return AIDiagnosis(
                available=False,
                model_name=self.model,
                error=(
                    f"Configured model '{self.model}' is not installed in local Ollama (Installed: {models_str}). "
                    f"To install locally, run: ollama pull {self.model}. Skipping AI diagnosis."
                ),
            )

        # 3. Construct bounded prompt
        prompt = self.build_prompt(report, events)

        # 4. Invoke Ollama HTTP API
        try:
            req_data = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.9,
                },
            }
            res = self._http_request("/api/generate", data=req_data, timeout=self.timeout)
            raw_text = res.get("response", "").strip()

            if not raw_text:
                return AIDiagnosis(
                    available=False,
                    model_name=self.model,
                    error="Local Ollama model returned an empty response.",
                )

            return self._parse_model_response(raw_text)

        except (TimeoutError, socket.timeout):
            return AIDiagnosis(
                available=False,
                model_name=self.model,
                error=f"Local Ollama inference timed out after {self.timeout}s.",
            )
        except urllib.error.HTTPError as exc:
            return AIDiagnosis(
                available=False,
                model_name=self.model,
                error=f"Local Ollama HTTP error {exc.code}: {exc.reason}",
            )
        except Exception as exc:
            return AIDiagnosis(
                available=False,
                model_name=self.model,
                error=f"Unexpected error during Ollama inference: {exc}",
            )

    def _parse_model_response(self, raw_text: str) -> AIDiagnosis:
        """Parse and validate JSON response from model, with text fallback."""
        def _ensure_list(val: Any) -> List[str]:
            if isinstance(val, list):
                return [str(x).strip() for x in val if str(x).strip()]
            if isinstance(val, str) and val.strip():
                return [val.strip()]
            return []

        # Attempt to locate and extract JSON object
        json_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(0))
                if isinstance(data, dict):
                    return AIDiagnosis(
                        available=True,
                        model_name=self.model,
                        summary=str(data.get("summary", "")).strip() or None,
                        hypotheses=_ensure_list(data.get("hypotheses")),
                        evidence_citations=_ensure_list(data.get("evidence_citations")),
                        recommendations=_ensure_list(data.get("recommendations")),
                        uncertainty_note=str(data.get("uncertainty_note", "")).strip() or None,
                        raw_response=raw_text,
                    )
            except json.JSONDecodeError:
                pass

        # Plain text fallback if JSON parsing failed
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
        summary = lines[0] if lines else "AI analysis completed."
        bullets = [line.lstrip("*- ").strip() for line in lines[1:] if line.startswith(("*", "-", "1.", "2."))]

        return AIDiagnosis(
            available=True,
            model_name=self.model,
            summary=summary,
            hypotheses=bullets[:3],
            recommendations=bullets[3:6] if len(bullets) > 3 else [],
            raw_response=raw_text,
            uncertainty_note="Model output was plain text rather than structured JSON.",
        )


def diagnose_with_local_ai(
    report: AnalysisReport,
    events: List[TraceEvent],
    base_url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_OLLAMA_MODEL,
    timeout: float = DEFAULT_REQUEST_TIMEOUT,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    disabled: bool = False,
) -> AIDiagnosis:
    """Run local AI diagnosis against trace report.

    Args:
        report: AnalysisReport containing deterministic findings.
        events: Parsed TraceEvent list.
        base_url: Ollama daemon URL.
        model: Model identifier.
        timeout: Request timeout seconds.
        connect_timeout: Connection check timeout seconds.
        disabled: If True (--no-ai), skips all Ollama network calls.

    Returns:
        AIDiagnosis object.
    """
    if disabled:
        return AIDiagnosis(
            available=False,
            model_name=model,
            error="Local AI diagnosis was skipped (--no-ai flag specified).",
        )

    client = OllamaClient(
        base_url=base_url,
        model=model,
        timeout=timeout,
        connect_timeout=connect_timeout,
    )
    return client.generate_diagnosis(report, events)
