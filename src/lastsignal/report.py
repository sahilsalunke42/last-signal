"""Forensic terminal reporting and Markdown export module for Last Signal.

Produces structured terminal reports and sanitized Markdown documents
combining trace ingestion statistics with deterministic failure findings.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Union

from lastsignal.models import (
    AnalysisReport,
    Finding,
    Severity,
    TraceReadResult,
)

# Regex to strip ANSI terminal escape codes
_ANSI_STRIP_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


class ReportExportError(Exception):
    """Raised when an error occurs during report generation or file export."""
    pass


def sanitize_text(text: Optional[str]) -> str:
    """Sanitize arbitrary trace text to remove ANSI codes and control characters."""
    if text is None:
        return ""
    clean = _ANSI_STRIP_REGEX.sub("", str(text))
    # Remove raw null bytes and non-printable control characters (except newline and tab)
    return "".join(ch for ch in clean if ch in ("\n", "\t") or ord(ch) >= 32)


def sanitize_markdown(text: Optional[str]) -> str:
    """Escape text for safe inclusion in Markdown documents.

    Prevents untrusted text from breaking tables, injecting raw HTML,
    or escaping code fence blocks.
    """
    clean = sanitize_text(text)
    # Neutralize raw HTML script or dangerous tags
    clean = clean.replace("<script", "&lt;script").replace("</script>", "&lt;/script&gt;")
    clean = clean.replace("<style", "&lt;style").replace("</style>", "&lt;/style&gt;")
    # Escape triple backticks to prevent code fence breakout
    clean = clean.replace("```", r"\`\`\`")
    return clean


def sanitize_table_cell(text: Optional[str]) -> str:
    """Sanitize text specifically for Markdown table cells."""
    clean = sanitize_markdown(text)
    # Escape pipe characters and replace newlines with HTML breaks
    clean = clean.replace("|", r"\|")
    clean = clean.replace("\n", "<br>")
    return clean


def determine_outcome(read_result: TraceReadResult, analysis: AnalysisReport) -> str:
    """Determine the macro execution outcome based strictly on available evidence."""
    if read_result.total_lines == 0 or len(read_result.events) == 0:
        return "EMPTY (No events recorded)"

    # Look for agent_end event
    agent_end = None
    for e in reversed(read_result.events):
        if e.event_type == "agent_end":
            agent_end = e
            break

    if agent_end:
        if agent_end.is_failure or (agent_end.status and agent_end.status.lower() in {"failed", "fatal", "error"}):
            err_note = f" - {agent_end.error_message}" if agent_end.error_message else ""
            return f"FAILED (Confirmed by agent_end: {agent_end.status}{err_note})"
        if agent_end.status and agent_end.status.lower() in {"success", "completed"}:
            if analysis.has_failures and analysis.has_critical:
                return f"UNSTABLE (agent_end: {agent_end.status}, but critical tool errors observed)"
            return f"SUCCESSFUL (Confirmed by agent_end: {agent_end.status})"
        return f"CONCLUDED ({agent_end.status})"

    if analysis.has_failures or any(e.is_failure for e in read_result.events):
        return "INCOMPLETE (Halted abruptly following tool failure; no agent_end event)"

    return "INCOMPLETE (Trace truncated before agent_end event)"


def group_findings_by_severity(findings: List[Finding]) -> Dict[Severity, List[Finding]]:
    """Group findings into ordered buckets by severity level."""
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    grouped: Dict[Severity, List[Finding]] = {sev: [] for sev in order}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)
    return {k: v for k, v in grouped.items() if v}


# -----------------------------------------------------------------------------
# Terminal Report Formatter
# -----------------------------------------------------------------------------

def format_terminal_report(
    read_result: TraceReadResult,
    analysis: AnalysisReport,
    file_name: str,
) -> str:
    """Generate a clean, forensic-styled text report suitable for any terminal."""
    outcome = determine_outcome(read_result, analysis)
    grouped = group_findings_by_severity(analysis.findings)

    lines: List[str] = []
    separator = "=" * 80
    sub_sep = "-" * 80

    lines.append(separator)
    lines.append("LAST SIGNAL // FORENSIC INVESTIGATION REPORT")
    lines.append("Digital Autopsy of AI-Agent Execution Trace")
    lines.append(separator)
    lines.append(f"Trace File:         {sanitize_text(file_name)}")
    if analysis.trace_id:
        lines.append(f"Trace ID:           {sanitize_text(analysis.trace_id)}")
    lines.append(
        f"Lines Ingested:     {read_result.total_lines} "
        f"({read_result.valid_count} valid events, {read_result.error_count} malformed lines)"
    )
    lines.append(f"Execution Outcome:  {outcome}")
    lines.append(
        f"Findings Summary:   {analysis.finding_count} pattern(s) "
        f"({analysis.critical_count} critical, {analysis.high_count} high)"
    )
    lines.append(separator)

    # Ingestion errors section
    if read_result.errors:
        lines.append("")
        lines.append(f"[!] INGESTION WARNINGS ({read_result.error_count} Malformed Lines):")
        lines.append(sub_sep)
        for err in read_result.errors:
            lines.append(f"  Line {err.line_number}: {sanitize_text(err.reason)}")
        lines.append("")

    # Findings by severity
    if not analysis.findings:
        lines.append("")
        lines.append("NO DETECTED FAILURE PATTERNS")
        lines.append(sub_sep)
        lines.append("The trace exhibits no recurring tool errors, retry loops, or abnormal terminations.")
    else:
        finding_num = 1
        for severity, findings in grouped.items():
            lines.append("")
            lines.append(f"[{severity.value}] SEVERITY FINDINGS ({len(findings)})")
            lines.append(sub_sep)
            for f in findings:
                badge = "INFERRED" if f.inferred else "EXPLICIT"
                lines.append(f"{finding_num}. {sanitize_text(f.title)}")
                lines.append(f"   Severity:       {f.severity.value} ({badge})")
                lines.append(f"   Event Lines:    {f.line_numbers}")
                lines.append(f"   Explanation:    {sanitize_text(f.explanation)}")
                lines.append("   Evidence:")
                for ev in f.evidence:
                    lines.append(f"     - {sanitize_text(ev)}")
                lines.append(f"   Recommendation: {sanitize_text(f.recommendation)}")
                lines.append("")
                finding_num += 1

    # Local AI Interpretation Section
    if analysis.ai_diagnosis:
        diag = analysis.ai_diagnosis
        lines.append("")
        if diag.available:
            lines.append(f"[+] LOCAL AI INTERPRETATION (Model: {sanitize_text(diag.model_name or 'unknown')})")
            lines.append(sub_sep)
            lines.append("NOTE: Deterministic findings above are confirmed ground truth.")
            lines.append("The following diagnosis is an evidence-grounded hypothesis from a local model.")
            lines.append("")
            if diag.summary:
                lines.append(f"Incident Summary:\n  {sanitize_text(diag.summary)}")
                lines.append("")
            if diag.hypotheses:
                lines.append("Likely Failure Hypotheses:")
                for h in diag.hypotheses:
                    lines.append(f"  * {sanitize_text(h)}")
                lines.append("")
            if diag.evidence_citations:
                lines.append("Grounded Evidence Citations:")
                for c in diag.evidence_citations:
                    lines.append(f"  * {sanitize_text(c)}")
                lines.append("")
            if diag.recommendations:
                lines.append("Recommended Debugging Actions:")
                for r in diag.recommendations:
                    lines.append(f"  * {sanitize_text(r)}")
                lines.append("")
            if diag.uncertainty_note:
                lines.append(f"Evidence Limits / Uncertainty:\n  {sanitize_text(diag.uncertainty_note)}")
                lines.append("")
        else:
            lines.append("[-] LOCAL AI INTERPRETATION (Inactive)")
            lines.append(sub_sep)
            lines.append(f"  {sanitize_text(diag.error or 'AI diagnosis unavailable.')}")
            lines.append("  Core analysis completed using deterministic verification rules only.")
            lines.append("")

    lines.append(separator)
    lines.append("FINAL VERDICT")
    lines.append(sub_sep)
    lines.append(sanitize_text(analysis.summary))
    lines.append(separator)

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Markdown Report Generator
# -----------------------------------------------------------------------------

def generate_markdown_report(
    read_result: TraceReadResult,
    analysis: AnalysisReport,
    file_name: str,
) -> str:
    """Generate a sanitized GitHub-flavored Markdown investigation report."""
    outcome = determine_outcome(read_result, analysis)
    grouped = group_findings_by_severity(analysis.findings)

    md: List[str] = []

    # Title & Header
    md.append("# LAST SIGNAL // Forensic Investigation Report")
    md.append("")
    md.append("> *Digital autopsy and failure pattern analysis for recorded AI-agent executions.*")
    md.append("")

    # Metadata Table
    md.append("## Case Overview")
    md.append("")
    md.append("| Metric | Value |")
    md.append("| :--- | :--- |")
    md.append(f"| **Trace File** | `{sanitize_table_cell(file_name)}` |")
    if analysis.trace_id:
        md.append(f"| **Trace ID** | `{sanitize_table_cell(analysis.trace_id)}` |")
    md.append(f"| **Lines Ingested** | {read_result.total_lines} |")
    md.append(f"| **Valid Events** | {read_result.valid_count} |")
    md.append(f"| **Malformed Lines** | {read_result.error_count} |")
    md.append(f"| **Execution Outcome** | **{sanitize_table_cell(outcome)}** |")
    md.append(
        f"| **Findings Detected** | {analysis.finding_count} "
        f"({analysis.critical_count} critical, {analysis.high_count} high) |"
    )
    md.append("")

    # Executive Summary
    md.append("## Executive Summary")
    md.append("")
    md.append(f"{sanitize_markdown(analysis.summary)}")
    md.append("")

    # Ingestion warnings if malformed lines were encountered
    if read_result.errors:
        md.append("## Ingestion Warnings")
        md.append("")
        md.append(f"Encountered **{read_result.error_count}** malformed line(s) during JSONL parsing:")
        md.append("")
        for err in read_result.errors:
            md.append(f"- **Line {err.line_number}:** `{sanitize_markdown(err.reason)}`")
        md.append("")

    # Detected Findings
    md.append("## Detected Failure Patterns")
    md.append("")

    if not analysis.findings:
        md.append("_No failure patterns or anomalies detected in this execution trace._")
        md.append("")
    else:
        finding_idx = 1
        for severity, findings in grouped.items():
            md.append(f"### {severity.value} Severity ({len(findings)})")
            md.append("")
            for f in findings:
                badge = "Inferred Pattern" if f.inferred else "Explicit Error"
                lines_str = ", ".join(str(num) for num in f.line_numbers)
                md.append(f"#### {finding_idx}. {sanitize_markdown(f.title)}")
                md.append("")
                md.append(f"- **Rule ID:** `{f.id}`")
                md.append(f"- **Severity:** `{f.severity.value}`")
                md.append(f"- **Evidence Basis:** `{badge}`")
                md.append(f"- **Relevant Trace Line(s):** {lines_str}")
                md.append("")
                md.append("**Explanation:**")
                md.append(f"{sanitize_markdown(f.explanation)}")
                md.append("")
                md.append("**Supporting Evidence:**")
                for ev in f.evidence:
                    md.append(f"- {sanitize_markdown(ev)}")
                md.append("")
                md.append("**Recommended Action:**")
                md.append(f"> {sanitize_markdown(f.recommendation)}")
                md.append("")
                finding_idx += 1

    # Local AI Interpretation Section in Markdown
    if analysis.ai_diagnosis:
        diag = analysis.ai_diagnosis
        md.append("## Local AI Interpretation")
        md.append("")
        if diag.available:
            md.append(f"> **Local Model:** `{sanitize_markdown(diag.model_name or 'unknown')}`")
            md.append(">")
            md.append("> *Disclaimer: Deterministic findings above are the primary source of truth. The following section contains an evidence-grounded interpretation generated by a local open-weight model.*")
            md.append("")
            if diag.summary:
                md.append("### Incident Assessment")
                md.append(f"{sanitize_markdown(diag.summary)}")
                md.append("")
            if diag.hypotheses:
                md.append("### Hypotheses & Explanations")
                for h in diag.hypotheses:
                    md.append(f"- {sanitize_markdown(h)}")
                md.append("")
            if diag.evidence_citations:
                md.append("### Trace Evidence Citations")
                for c in diag.evidence_citations:
                    md.append(f"- {sanitize_markdown(c)}")
                md.append("")
            if diag.recommendations:
                md.append("### Recommended Debugging Actions")
                for r in diag.recommendations:
                    md.append(f"> - {sanitize_markdown(r)}")
                md.append("")
            if diag.uncertainty_note:
                md.append("### Uncertainty & Evidence Limitations")
                md.append(f"_{sanitize_markdown(diag.uncertainty_note)}_")
                md.append("")
        else:
            md.append(f"_Local AI diagnosis was not active: {sanitize_markdown(diag.error or 'unavailable')}_")
            md.append("")

    # Forensic Timeline of Events
    if read_result.events:
        md.append("## Key Event Timeline")
        md.append("")
        md.append("| Line | Event Type | Operation / Tool | Status | Error Snippet |")
        md.append("| :---: | :--- | :--- | :--- | :--- |")
        for e in read_result.events:
            status_badge = sanitize_table_cell(e.status or "-")
            op_str = sanitize_table_cell(e.operation or "-")
            err_snippet = sanitize_table_cell((e.error_message[:60] + "...") if e.error_message and len(e.error_message) > 60 else (e.error_message or "-"))
            md.append(f"| {e.line_number} | `{e.event_type}` | `{op_str}` | {status_badge} | {err_snippet} |")
        md.append("")

    # Footer
    md.append("---")
    md.append("*Report generated by [Last Signal](https://github.com/sahilsaunke/last-signal) — Ghost in the Machine.*")
    md.append("")

    return "\n".join(md)


# -----------------------------------------------------------------------------
# File Export Utility
# -----------------------------------------------------------------------------

def export_markdown_report(
    read_result: TraceReadResult,
    analysis: AnalysisReport,
    file_name: str,
    output_path: Union[str, Path],
) -> Path:
    """Export the forensic analysis as a Markdown file.

    Args:
        read_result: Trace parsing result.
        analysis: Deterministic failure detection report.
        file_name: Source trace file name for provenance.
        output_path: Destination path for the Markdown file.

    Returns:
        Path object of the written file.

    Raises:
        ReportExportError: If the file cannot be written due to permissions or invalid paths.
    """
    dest = Path(output_path).resolve()

    # Prevent writing if destination is an existing directory
    if dest.is_dir():
        raise ReportExportError(f"Cannot export to '{dest}': destination is a directory, not a file.")

    # Create parent directories if they don't exist
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError) as exc:
        raise ReportExportError(f"Cannot create directory '{dest.parent}': {exc}") from exc

    # Generate Markdown content
    content = generate_markdown_report(read_result, analysis, file_name)

    # Write file safely
    try:
        dest.write_text(content, encoding="utf-8")
    except (PermissionError, OSError) as exc:
        raise ReportExportError(f"Failed to write report to '{dest}': {exc}") from exc

    return dest
