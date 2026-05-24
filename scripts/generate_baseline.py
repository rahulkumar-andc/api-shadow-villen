#!/usr/bin/env python3
"""
Generate a baseline scan for diff comparisons.

Run this once on a clean/known-good branch, then commit baseline.json.
CI will compare future scans against this baseline.

Usage:
    python scripts/generate_baseline.py
    python scripts/generate_baseline.py --source ./src --output baseline.json
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Generate Shadow-API baseline")
    parser.add_argument("--source", type=Path, default=Path("./src"),
                        help="Source directory to scan")
    parser.add_argument("--output", type=Path, default=Path("baseline.json"),
                        help="Output baseline file")
    args = parser.parse_args()

    if not args.source.exists():
        print(f"[error] Source directory not found: {args.source}")
        sys.exit(1)

    print(f"📍 Generating baseline from {args.source} → {args.output}")

    result = subprocess.run(
        [
            "poetry", "run", "shadow-mapper", "parse",
            str(args.source),
            "--output", str(args.output),
            "--secrets",
            "--resolve",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"[error] Scan failed:\n{result.stderr}")
        sys.exit(1)

    print(result.stdout)
    print(f"\n✅ Baseline saved to {args.output}")
    print("   Commit this file to track shadow API changes over time.")
    print("\nNext steps:")
    print(f"   git add {args.output}")
    print("   git commit -m 'chore: update shadow-api baseline'")


if __name__ == "__main__":
    main()
