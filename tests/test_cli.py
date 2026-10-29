"""Tests for Last Signal CLI commands and help system."""

from typer.testing import CliRunner
from lastsignal.cli import app

runner = CliRunner()


def test_cli_help_command():
    """Verify that 'lastsignal help' prints the command reference table."""
    result = runner.invoke(app, ["help"])
    assert result.exit_code == 0
    assert "Available Commands" in result.output
    assert "analyze" in result.output
    assert "report" in result.output
    assert "doctor" in result.output
    assert "--no-ai" in result.output


def test_cli_help_subcommand():
    """Verify that 'lastsignal help analyze' prints detailed usage for analyze."""
    result = runner.invoke(app, ["help", "analyze"])
    assert result.exit_code == 0
    assert "COMMAND: lastsignal analyze" in result.output
    assert "--output" in result.output
    assert "--no-ai" in result.output


def test_cli_help_unknown_subcommand():
    """Verify that 'lastsignal help unknown' shows warning and general table."""
    result = runner.invoke(app, ["help", "nonexistent"])
    assert result.exit_code == 0
    assert "Unknown command 'nonexistent'" in result.output
    assert "Available Commands" in result.output
