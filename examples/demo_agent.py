#!/usr/bin/env python3
"""Simulated AI Agent demonstrating controlled failure and recovery scenarios.

This demo runs as a standalone Python process without requiring real databases,
API keys, or network services. It outputs structured execution progress
that Last Signal captures and investigates automatically.

Usage:
  python examples/demo_agent.py            # Simulates realistic tool timeout & failure
  python examples/demo_agent.py --succeed  # Simulates clean successful execution
"""

import sys
import time


def run_demo_agent(succeed: bool = False):
    print("[INFO] Initializing Autonomous Research Agent (v1.2.0)...", flush=True)
    time.sleep(0.05)

    # Step 1: Initial tool call (configuration load)
    print("[tool_call] tool=load_configuration status=success", flush=True)
    print("[INFO] Goal: Synchronize document embeddings with local vector store.", flush=True)
    time.sleep(0.05)

    if succeed:
        # Successful path
        print("[tool_call] tool=vector_sync attempt=1 status=started", flush=True)
        time.sleep(0.05)
        print("[tool_result] tool=vector_sync attempt=1 status=success", flush=True)
        print("[INFO] Successfully synchronized 256 document embeddings.", flush=True)
        print("[INFO] Agent goal completed.", flush=True)
        sys.exit(0)

    # Failing path: Tool attempts to connect to local vector store, times out, retries, and fails
    for attempt in range(1, 4):
        print(f"[tool_call] tool=vector_sync attempt={attempt} status=started", flush=True)
        time.sleep(0.05)
        print(
            f'[tool_result] tool=vector_sync attempt={attempt} status=failed '
            f'error="TimeoutError: Connection to vector store at 127.0.0.1:6333 timed out after 5.0s"',
            flush=True,
        )
        if attempt < 3:
            print(f"[retry] tool=vector_sync attempt={attempt + 1} status=pending", flush=True)
            time.sleep(0.05)

    # Terminal abort
    print("[ERROR] Exceeded retry threshold (3 attempts). Vector store unreachable.", file=sys.stderr, flush=True)
    print("RuntimeError: Fatal: Vector store sync failed after 3 retry attempts.", file=sys.stderr, flush=True)
    sys.exit(1)


if __name__ == "__main__":
    should_succeed = "--succeed" in sys.argv
    run_demo_agent(succeed=should_succeed)
