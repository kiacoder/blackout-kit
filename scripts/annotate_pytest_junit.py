#!/usr/bin/env python3
"""Turn a pytest JUnit report into GitHub Actions error annotations.

A failing pytest step only reports its exit code in the job summary. This
helper lifts the failing test names and assertion messages out of the JUnit
report and prints them as workflow annotations, so the failures are visible on
the check run without opening the raw step log.

Usage:
    python scripts/annotate_pytest_junit.py path/to/junit.xml
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_ANNOTATIONS = 50
MAX_MESSAGE_CHARS = 2000


def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: annotate_pytest_junit.py <junit.xml>", file=sys.stderr)
        return 2

    report = Path(argv[1])
    if not report.is_file():
        print(f"::error title=pytest::No JUnit report at {report}; see the test step log.")
        return 0

    total = 0
    annotated = 0
    for case in ET.parse(report).getroot().iter("testcase"):
        for kind in ("failure", "error"):
            node = case.find(kind)
            if node is None:
                continue
            total += 1
            if annotated >= MAX_ANNOTATIONS:
                continue
            annotated += 1
            name = f"{case.get('classname', '')}::{case.get('name', '')}"
            detail = "\n".join(part for part in (node.get("message"), node.text) if part).strip()
            print(
                f"::error title={_escape_property(name)}::"
                f"{_escape_data(detail[:MAX_MESSAGE_CHARS])}"
            )

    if total:
        print(f"::notice::{total} failing test entries recorded; {annotated} annotated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
