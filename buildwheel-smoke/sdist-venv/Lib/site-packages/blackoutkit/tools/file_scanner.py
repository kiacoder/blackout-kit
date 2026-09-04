from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

DEFENDER_PLATFORM_DIR = Path("Microsoft") / "Windows Defender" / "Platform"


def find_defender() -> Path | None:
    if sys.platform != "win32":
        return None

    platform_dir = Path(os.environ.get("ProgramData", "C:/ProgramData")) / DEFENDER_PLATFORM_DIR
    candidates = []
    if platform_dir.is_dir():
        candidates.extend(
            platform_dir / child / "MpCmdRun.exe"
            for child in sorted(platform_dir.iterdir(), reverse=True)
            if child.is_dir()
        )
    candidates.append(
        Path(os.environ.get("ProgramFiles", "C:/Program Files"))
        / "Windows Defender"
        / "MpCmdRun.exe"
    )

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _output_confirms_detection(output: str) -> bool:
    normalized = " ".join(output.lower().split())
    if "no threat detected" in normalized or "no threats detected" in normalized:
        return False
    return "threat detected" in normalized or "threats detected" in normalized


def _result(status: str, target: Path | None = None, **details: str | int | None) -> dict:
    return {"status": status, "target": str(target) if target else None, **details}


def scan_file(path: str | Path) -> dict:
    target = Path(path).expanduser().resolve()
    if not target.is_file():
        return _result("invalid-target", target, detail="Provide an existing regular file.")
    if sys.platform != "win32":
        return _result("unsupported-platform", target, detail="Windows Defender scanning is available only on Windows.")

    defender = find_defender()
    if defender is None:
        return _result("scanner-unavailable", target, detail="Windows Defender was not found.")

    command = [
        str(defender),
        "-Scan",
        "-ScanType",
        "3",
        "-File",
        str(target),
        "-DisableRemediation",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _result("scanner-error", target, detail=str(exc))

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if completed.returncode == 0:
        return _result("clean", target, detail=output or None, returncode=0)
    if completed.returncode == 2 and _output_confirms_detection(output):
        return _result("detected", target, detail=output, returncode=2)
    if completed.returncode == 2:
        return _result(
            "indeterminate",
            target,
            detail=output or "Windows Defender returned an ambiguous result.",
            returncode=2,
        )
    return _result("scanner-error", target, detail=output or "Windows Defender scan failed.", returncode=completed.returncode)
