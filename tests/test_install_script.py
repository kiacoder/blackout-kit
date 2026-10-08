"""Checks for install.ps1 release verification and the release checksum job.

Static checks run everywhere. The behavioural checks execute the real
Get-ExpectedSha256 function (extracted from install.ps1 with the PowerShell
parser) under pwsh, which is present on the GitHub Actions runners and skipped
elsewhere.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL_PS1 = ROOT / "install.ps1"
BUILD_YML = ROOT / ".github" / "workflows" / "build.yml"

GOOD = "34f2ceae68695a978c5f3bf100de9d47d7d6a520cc3790b439bb36180a74cc50"
OTHER = "af06898f71f620548d0691aa732e46d6730c4b10b02dc4c06570d6577137dca8"


def _install_text() -> str:
    return INSTALL_PS1.read_text(encoding="utf-8")


def test_install_script_is_ascii_only():
    # Windows PowerShell 5.1 reads BOM-less UTF-8 as Windows-1252, where some
    # emoji bytes decode to quote characters. Keep the script pure ASCII.
    assert all(ord(ch) < 128 for ch in _install_text())


def test_install_script_verifies_sha256_before_the_binary_runs():
    text = _install_text()
    verify = text.index("Get-FileHash -LiteralPath $StagedPath -Algorithm SHA256")
    move = text.index("Move-Item -LiteralPath $StagedPath")
    run_doctor = text.index("& $ExePath doctor")
    assert verify < move < run_doctor
    assert "[OK] SHA-256 checksum verified: $ActualHash" in text


def test_install_script_compares_case_insensitively_with_trim():
    text = _install_text()
    assert "$ActualHash.Trim() -ieq $ExpectedHash.Trim()" in text


def test_install_script_fails_closed_on_missing_or_mismatched_checksum():
    text = _install_text()
    assert "publishes no SHA-256 checksum" in text
    assert "SHA-256 mismatch" in text
    assert "is missing, ambiguous, or malformed" in text
    # Every failure path deletes the staged download and exits non-zero.
    stop = re.search(r"function Stop-Install \{(.*?)\n\}", text, re.S)
    assert stop is not None
    assert "Remove-Item -LiteralPath $StagedPath" in stop.group(1)
    assert "exit 1" in stop.group(1)


def test_install_script_accepts_checksums_txt_or_single_sha256_asset():
    text = _install_text()
    assert '"checksums.txt"' in text
    assert '"blackout.exe.sha256"' in text


def test_install_script_never_changes_defender_or_firewall_settings():
    text = _install_text()
    for cmdlet in ("Add-MpPreference", "Set-MpPreference", "netsh advfirewall"):
        assert cmdlet not in text


def test_release_job_generates_and_publishes_checksums():
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(BUILD_YML.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["release"]["steps"]
    names = [step.get("name", "") for step in steps]
    generate = steps[names.index("Generate and verify SHA-256 checksums")]["run"]
    assert "sha256sum blackout.exe blackout-engine-linux-amd64 blackout-source.zip > checksums.txt" in generate
    assert "sha256sum blackout.exe > blackout.exe.sha256" in generate
    assert "sha256sum -c checksums.txt" in generate
    publish = steps[names.index("Create Release")]["with"]["files"]
    assert "dist/checksums.txt" in publish
    assert "dist/blackout.exe.sha256" in publish
    # The checksum step must run after the artifacts exist and before publishing.
    assert names.index("Generate and verify SHA-256 checksums") < names.index("Create Release")


def test_windows_job_parses_install_script_with_pwsh():
    text = BUILD_YML.read_text(encoding="utf-8")
    assert "[System.Management.Automation.Language.Parser]::ParseFile" in text
    assert "install.ps1" in text


_EXTRACT_AND_RUN = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'install.ps1 does not parse' }
$fn = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ExpectedSha256' }, $true) | Select-Object -First 1
if (-not $fn) { throw 'Get-ExpectedSha256 not found' }
Invoke-Expression $fn.Extent.Text
$cases = Get-Content -LiteralPath $args[1] -Raw | ConvertFrom-Json
$results = foreach ($case in @($cases)) {
    [pscustomobject]@{ id = [string]$case.id; hash = (Get-ExpectedSha256 -Text ([string]$case.text) -FileName 'blackout.exe') }
}
ConvertTo-Json -InputObject @($results) -Depth 3 -Compress
"""

_CHECKSUM_CASES = [
    ("sha256sum two-space line", f"{GOOD}  blackout.exe\n{OTHER}  blackout-engine-linux-amd64\n", GOOD),
    ("binary-mode asterisk", f"{GOOD} *blackout.exe\n", GOOD),
    ("uppercase hash with CRLF", f"{GOOD.upper()}  blackout.exe\r\n", GOOD),
    ("UTF-8 BOM prefix", "\ufeff" + f"{GOOD}  blackout.exe\n", GOOD),
    ("bare hash file", f"{GOOD}\n", GOOD),
    ("identical duplicate entries", f"{GOOD}  blackout.exe\n{GOOD}  blackout.exe\n", GOOD),
    ("only other assets listed", f"{OTHER}  blackout-engine-linux-amd64\n", None),
    ("conflicting duplicate entries", f"{GOOD}  blackout.exe\n{OTHER}  blackout.exe\n", None),
    ("truncated hash", f"{GOOD[:-2]}  blackout.exe\n", None),
    ("non-hex characters", "h" * 64 + "  blackout.exe\n", None),
    ("empty checksum text", "", None),
    ("similar file name", f"{GOOD}  blackout.exe.bak\n", None),
    ("path-prefixed name", f"{GOOD}  dist/blackout.exe\n", None),
]


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not installed")
def test_checksum_parser_behaviour(tmp_path):
    script = tmp_path / "extract_and_run.ps1"
    script.write_text(_EXTRACT_AND_RUN, encoding="utf-8")
    cases_file = tmp_path / "cases.json"
    cases_file.write_text(
        json.dumps([{"id": name, "text": text} for name, text, _ in _CHECKSUM_CASES]),
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), str(INSTALL_PS1), str(cases_file)],
        capture_output=True, text=True, timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    results = {item["id"]: item["hash"] for item in json.loads(completed.stdout)}
    for name, _text, expected in _CHECKSUM_CASES:
        assert results[name] == expected, name
