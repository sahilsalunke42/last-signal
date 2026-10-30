"""Tests for Last Signal CLI commands, startup interface, and help system."""

from typer.testing import CliRunner
from lastsignal.cli import app, build_startup_interface

runner = CliRunner()


def test_cli_no_args_launches_startup_interface():
    """Verify that running 'lastsignal' with no arguments displays the Claude Code-style welcome screen."""
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    # Banner and ASCII wordmark spelling 'Last Signal'
    assert "LAST SIGNAL // FORENSIC TERMINAL" in result.output
    assert "✳" in result.output
    assert "/ __|" in result.output  # 's' in Last
    assert "Every failed agent leaves a trace." in result.output
    assert "Investigate execution failures. Preserve the evidence." in result.output
    assert "Ghost in the Machine" in result.output
    assert "recorded traces" in result.output

    # System Status area
    assert "SYSTEM STATUS:" in result.output
    assert "LOCAL / OFFLINE" in result.output
    assert "Version:" in result.output
    assert "Traces:" in result.output

    # Untruncated registered command names & shortcuts
    assert "run" in result.output
    assert "analyze" in result.output
    assert "report" in result.output
    assert "doctor" in result.output
    assert "help" in result.output

    # Syntax and examples
    assert "lastsignal run" in result.output
    assert "lastsignal analyze" in result.output
    assert "lastsignal report" in result.output
    assert "lastsignal doctor" in result.output
    assert "lastsignal help" in result.output

    # Subtle prompt instruction
    assert "Type a command to begin your investigation." in result.output

    # Deterministic / offline explanation
    assert "--no-ai" in result.output
    assert "OFFLINE & DETERMINISTIC ANALYSIS:" in result.output


def test_cli_startup_respects_no_color():
    """Verify that '--no-color' flag renders plain text without ANSI escapes."""
    result = runner.invoke(app, ["--no-color"])
    assert result.exit_code == 0
    assert "LAST SIGNAL // FORENSIC TERMINAL" in result.output
    assert "\x1B[" not in result.output


def test_cli_startup_narrow_terminal_width():
    """Verify that narrow terminal widths do not truncate command names."""
    # Test text generation at narrow widths (50 and 60 columns)
    for w in [50, 60, 70]:
        text = build_startup_interface(width=w)
        assert "run" in text
        assert "analyze" in text
        assert "report" in text
        assert "doctor" in text
        assert "help" in text
        # Verify no fixed-width clipping into 'Comm…'
        assert "Comm…" not in text
        assert "anal…" not in text


def test_cli_help_displays_complete_reference():
    """Verify that 'lastsignal help' prints the untruncated command reference."""
    result = runner.invoke(app, ["help"])
    assert result.exit_code == 0
    assert "LAST SIGNAL // COMMAND REFERENCE" in result.output
    assert "REGISTERED COMMANDS:" in result.output
    assert "run" in result.output
    assert "analyze" in result.output
    assert "report" in result.output
    assert "doctor" in result.output
    assert "help" in result.output
    assert "--no-ai" in result.output


def test_cli_help_subcommand():
    """Verify that 'lastsignal help analyze' prints detailed usage for analyze."""
    result = runner.invoke(app, ["help", "analyze"])
    assert result.exit_code == 0
    assert "COMMAND: lastsignal analyze" in result.output
    assert "--output" in result.output
    assert "--no-ai" in result.output

    # Also test help for run command
    run_res = runner.invoke(app, ["help", "run"])
    assert run_res.exit_code == 0
    assert "COMMAND: lastsignal run" in run_res.output
    assert "--trace-out" in run_res.output
    assert "--output" in run_res.output


def test_cli_help_unknown_subcommand():
    """Verify that 'lastsignal help unknown' shows warning and general reference."""
    result = runner.invoke(app, ["help", "nonexistent"])
    assert result.exit_code == 0
    assert "Unknown command 'nonexistent'" in result.output
    assert "REGISTERED COMMANDS:" in result.output


def test_existing_commands_preserved():
    """Verify that existing commands (doctor, analyze) continue to function."""
    doc_res = runner.invoke(app, ["doctor"])
    assert doc_res.exit_code == 0
    assert "LAST SIGNAL SYSTEM DIAGNOSTICS" in doc_res.output

    # Analyze clean trace
    ana_res = runner.invoke(app, ["analyze", "examples/successful_execution.jsonl", "--no-ai"])
    assert ana_res.exit_code == 0
    assert "SUCCESSFUL" in ana_res.output


def test_cli_analyze_auto_detects_recent_trace():
    """Verify that 'lastsignal analyze' with no file argument auto-detects recent trace."""
    res = runner.invoke(app, ["analyze", "--no-ai"])
    assert res.exit_code in (0, 1)  # 1 because demo trace had failures
    assert "Auto-detected" in res.output
    assert ".jsonl" in res.output
    assert "LAST SIGNAL // FORENSIC INVESTIGATION REPORT" in res.output


def test_cli_report_auto_detects_recent_trace(tmp_path):
    """Verify that 'lastsignal report' auto-detects trace and defaults destination."""
    res = runner.invoke(app, ["report", "--no-ai"])
    assert res.exit_code in (0, 1)
    assert "Auto-detected" in res.output
    assert "Auto-selected report destination" in res.output
    assert "Forensic Markdown report written to" in res.output


def test_scan_workspace_detects_agent_and_traces():
    """Verify workspace scanner auto-identifies agent and traces."""
    from lastsignal.cli import scan_workspace
    ws = scan_workspace()
    assert ws["detected_agent"] is not None
    assert "demo_agent.py" in ws["detected_agent"]
    assert ws["latest_trace"] is not None

