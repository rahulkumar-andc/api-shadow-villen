#!/usr/bin/env python3
"""
CI script: fail if new shadow APIs appear vs baseline.

Usage:
    python scripts/check_new_shadows.py --baseline baseline.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def load_report(path: Path) -> dict:
    if not path.exists():
        print(f"[error] File not found: {path}")
        sys.exit(1)
    return json.loads(path.read_text())


def get_endpoint_sigs(report: dict) -> set[str]:
    return {
        f"{e.get('method','GET')}:{e.get('url','')}"
        for e in report.get("endpoints", [])
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, default=Path("baseline.json"))
    parser.add_argument("--current",  type=Path, default=None)
    parser.add_argument("--source",   type=Path, default=Path("./src"))
    args = parser.parse_args()

    if args.current is None:
        print(f"Running fresh parse on {args.source} ...")
        tmp = Path("/tmp/shadow-current.json")
        result = subprocess.run(
            ["poetry", "run", "shadow-mapper", "parse",
             str(args.source), "--output", str(tmp)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"Parse failed:\n{result.stderr}")
            sys.exit(1)
        args.current = tmp

    baseline = load_report(args.baseline)
    current  = load_report(args.current)

    new_eps     = get_endpoint_sigs(current) - get_endpoint_sigs(baseline)
    new_secrets = max(0, len(current.get("secrets",[])) - len(baseline.get("secrets",[])))

    print(f"\n{'='*50}")
    print(f"New endpoints : {len(new_eps)}")
    print(f"New secrets   : {new_secrets}")
    print(f"{'='*50}")

    if new_eps:
        print("\n⚠️  New undocumented endpoints:")
        for s in sorted(new_eps):
            print(f"   + {s}")

    if new_secrets:
        print(f"\n🔐 {new_secrets} new secret(s) detected!")

    if new_eps or new_secrets:
        print("\n❌ CI FAILED")
        sys.exit(1)
    else:
        print("\n✅ CI PASSED — no new shadow APIs")
        sys.exit(0)


if __name__ == "__main__":
    main()
