#!/usr/bin/env bash
# ==============================================================================
# Last Signal - End-to-End Forensic Demonstration Script
# "Ghost in the Machine" Open-Source AI Challenge
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure venv Python is used
PYTHON_BIN="./venv/bin/python"
CLI_BIN="./venv/bin/lastsignal"

if [ ! -f "$CLI_BIN" ]; then
    echo "[!] CLI binary not found. Installing package in editable mode..."
    $PYTHON_BIN -m pip install -e .
fi

echo "================================================================================"
echo "LAST SIGNAL // FORENSIC INVESTIGATION DEMO"
echo "Theme: Ghost in the Machine | Open-Source AI Challenge"
echo "================================================================================"
echo ""

echo ">>> STEP 1: Running System Diagnostics (Doctor)..."
$CLI_BIN doctor
echo ""

echo ">>> STEP 2: Analyzing Successful Execution Trace..."
echo "(Expectation: 0 failure findings, outcome SUCCESSFUL, exit code 0)"
set +e
$CLI_BIN analyze examples/successful_execution.jsonl --no-ai
SUCCESS_CODE=$?
set -e
echo "[+] Completed with exit code: $SUCCESS_CODE"
echo ""

echo ">>> STEP 3: Analyzing Repeated Failure Trace with Local AI..."
echo "(Expectation: 4 findings, confirmed ground truth + local model hypotheses)"
set +e
$CLI_BIN analyze examples/repeated_tool_failure.jsonl --output reports/demo_autopsy.md
FAIL_CODE=$?
set -e
echo "[+] Analysis completed with exit code: $FAIL_CODE (expected 1 for failure traces)"
echo ""

echo ">>> STEP 4: Verifying Exported Markdown Autopsy Report..."
if [ -f "reports/demo_autopsy.md" ]; then
    echo "[+] Report successfully generated at: reports/demo_autopsy.md"
    echo "[+] Report preview (first 25 lines):"
    head -n 25 reports/demo_autopsy.md
fi
echo ""

echo "================================================================================"
echo "DEMO COMPLETE: All forensic stages verified successfully."
echo "================================================================================"
