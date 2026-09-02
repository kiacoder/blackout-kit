#!/usr/bin/env python3
"""Measure local Blackout Kit startup paths without network or system changes."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time


def commands(*, installed: bool = False) -> dict[str, list[str]]:
    prefix = [sys.executable, "-I"] if installed else [sys.executable]
    return {
        "import": [*prefix, "-c", "import blackoutkit"],
        "help": [*prefix, "-m", "blackoutkit.typer_cli", "--help"],
        "json-version": [*prefix, "-m", "blackoutkit.typer_cli", "--json", "version"],
    }


def measure(command: list[str], runs: int) -> list[float]:
    values = []
    env = os.environ.copy()
    env["PYTHONWARNINGS"] = "ignore"
    for _ in range(runs):
        started = time.perf_counter()
        result = subprocess.run(
            command,
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        if result.returncode:
            raise SystemExit(f"startup command failed: {' '.join(command)}")
        values.append(elapsed_ms)
    return values


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, round((len(ordered) - 1) * fraction))
    return ordered[index]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=7, help="Fresh subprocesses per command")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable results")
    parser.add_argument("--installed", action="store_true", help="Run isolated subprocesses against an installed package")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    results = {}
    for name, command in commands(installed=args.installed).items():
        samples = measure(command, args.runs)
        results[name] = {
            "runs": args.runs,
            "median_ms": round(statistics.median(samples), 2),
            "p95_ms": round(percentile(samples, 0.95), 2),
            "samples_ms": [round(value, 2) for value in samples],
        }

    if args.json:
        print(json.dumps({"commands": results}, sort_keys=True, separators=(",", ":")))
        return
    for name, result in results.items():
        print(f"{name}: median={result['median_ms']:.2f}ms p95={result['p95_ms']:.2f}ms")


if __name__ == "__main__":
    main()
