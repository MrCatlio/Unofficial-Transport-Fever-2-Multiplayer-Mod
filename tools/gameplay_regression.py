"""Run the deterministic, offline gameplay regression suite.

This covers gameplay logic that does not require Transport Fever 2 itself:
pacing, command delay, catch-up/history, recovery barriers, hot join ordering,
companies, hashing cadence, and player-facing state formatting.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

QUICK_TESTS = [
    "tools/delay_hold_test.py",
    "tools/pacing_sim.py",
    "tools/test_sync_operation.py",
    "tools/test_sync_readiness.py",
    "tools/company_rules_test.py",
    "tools/company_registry_test.py",
    "tools/hash_cadence_test.py",
    "tools/loading_panel_test.py",
    "tools/session_health_test.py",
]

FULL_TESTS = QUICK_TESTS + [
    "tools/live_catchup_gap_test.py",
    "tools/hist_retention_test.py",
    "tools/resync_test.py",
    "tools/test_auto_sync_lobby.py",
    "tools/hotjoin_stage_test.py",
    "tools/hotjoin_order_bytes_test.py",
    "tools/perf_lanes_test.py",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="include slower catch-up and hot-join tests")
    args = parser.parse_args()
    tests = FULL_TESTS if args.full else QUICK_TESTS
    for relative_path in tests:
        path = os.path.join(REPO, relative_path.replace("/", os.sep))
        print(f"\n=== {relative_path} ===", flush=True)
        result = subprocess.run([sys.executable, path], cwd=REPO)
        if result.returncode:
            print(f"FAILED: {relative_path} (exit {result.returncode})", file=sys.stderr)
            return result.returncode
    print(f"\nPASS: {len(tests)} offline gameplay regression tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
