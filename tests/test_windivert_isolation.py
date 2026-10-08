"""WinDivert driver isolation: the driver lives only in bins/windivert, every launch
path loads it from there, and nothing else is ever placed in that folder."""
import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from blackoutkit import WINDIVERT_DIR, downloader
from blackoutkit import doctor as doc
from blackoutkit.engines import gdpi


def test_windivert_folder_is_a_child_of_bins():
    assert WINDIVERT_DIR.name == "windivert"
    assert WINDIVERT_DIR.parent == downloader.BINS_DIR


def test_goodbyedpi_driver_outputs_are_isolated_in_windivert_folder():
    info = downloader.BIN_REGISTRY["goodbyedpi"]
    assert "windivert/WinDivert.dll" in info.output_bins
    assert "windivert/WinDivert64.sys" in info.output_bins
    assert "WinDivert.dll" not in info.output_bins
    assert info.extract_map["*/WinDivert.dll"] == "windivert/WinDivert.dll"
    assert info.extract_map["*/WinDivert64.sys"] == "windivert/WinDivert64.sys"


def test_zip_extraction_creates_the_windivert_subfolder(tmp_path):
    archive = tmp_path / "goodbyedpi.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("goodbyedpi-0.2/WinDivert.dll", b"MZ-dll")
        zipped.writestr("goodbyedpi-0.2/WinDivert64.sys", b"MZ-sys")
    stage = tmp_path / "stage"
    ok, detail = downloader._extract_from_zip(
        archive,
        {"*/WinDivert.dll": "windivert/WinDivert.dll", "*/WinDivert64.sys": "windivert/WinDivert64.sys"},
        stage,
    )
    assert ok is True, detail
    assert (stage / "windivert" / "WinDivert.dll").read_bytes() == b"MZ-dll"
    assert (stage / "windivert" / "WinDivert64.sys").read_bytes() == b"MZ-sys"
    assert not (stage / "WinDivert.dll").exists()


def test_legacy_flat_driver_copies_are_removed_with_their_provenance(tmp_path, monkeypatch):
    bins = tmp_path / "bins"
    bins.mkdir()
    monkeypatch.setattr(downloader, "BINS_DIR", bins)
    monkeypatch.setattr(downloader, "_PROVENANCE_FILE", bins / ".provenance.json")
    (bins / "WinDivert.dll").write_bytes(b"old")
    (bins / "WinDivert64.sys").write_bytes(b"old")
    (bins / "goodbyedpi.exe").write_bytes(b"keep")
    (bins / ".provenance.json").write_text(json.dumps({"schema_version": 1, "artifacts": [
        {"key": "goodbyedpi", "output": "WinDivert.dll", "sha256": "a"},
        {"key": "goodbyedpi", "output": "goodbyedpi.exe", "sha256": "b"},
    ]}), encoding="utf-8")

    downloader._remove_legacy_windivert_copies()

    assert not (bins / "WinDivert.dll").exists()
    assert not (bins / "WinDivert64.sys").exists()
    assert (bins / "goodbyedpi.exe").exists()
    remaining = json.loads((bins / ".provenance.json").read_text(encoding="utf-8"))["artifacts"]
    assert [record["output"] for record in remaining] == ["goodbyedpi.exe"]


def test_legacy_cleanup_does_not_create_provenance_when_none_existed(tmp_path, monkeypatch):
    bins = tmp_path / "bins"
    bins.mkdir()
    monkeypatch.setattr(downloader, "BINS_DIR", bins)
    monkeypatch.setattr(downloader, "_PROVENANCE_FILE", bins / ".provenance.json")
    downloader._remove_legacy_windivert_copies()
    assert not (bins / ".provenance.json").exists()


def _windivert_folder(tmp_path: Path) -> Path:
    folder = tmp_path / "bins" / "windivert"
    folder.mkdir(parents=True)
    (folder / "WinDivert.dll").write_bytes(b"MZ")
    (folder / "WinDivert64.sys").write_bytes(b"MZ")
    return folder


def test_legacy_gdpi_launches_with_driver_folder_as_working_directory(tmp_path, monkeypatch):
    folder = _windivert_folder(tmp_path)
    binary = tmp_path / "bins" / "goodbyedpi.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(gdpi, "WINDIVERT_DIR", folder)

    engine = gdpi._LegacyGoodbyeDPIEngine(flags="-1")
    with patch("blackoutkit.engines.gdpi.subprocess.Popen") as popen, \
         patch("blackoutkit.engines.gdpi.time.sleep"), \
         patch.object(engine, "check_process_alive", return_value=True):
        popen.return_value = MagicMock(pid=4321)
        assert engine._try_direct_launch(binary) is True

    assert popen.call_args.kwargs["cwd"] == str(folder)
    assert popen.call_args.args[0][0] == str(binary)


def test_legacy_gdpi_refuses_to_start_without_driver_in_isolated_folder(tmp_path, monkeypatch):
    binary = tmp_path / "bins" / "goodbyedpi.exe"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"MZ")
    (binary.parent / "WinDivert.dll").write_bytes(b"MZ")  # legacy flat copy must not count
    (binary.parent / "WinDivert64.sys").write_bytes(b"MZ")
    monkeypatch.setattr(gdpi, "WINDIVERT_DIR", tmp_path / "bins" / "windivert")

    engine = gdpi._LegacyGoodbyeDPIEngine(flags="-1")
    with patch.object(engine, "find_binary", return_value=binary), \
         patch("blackoutkit.engines.gdpi.subprocess.Popen") as popen:
        assert engine.start() is False
    popen.assert_not_called()


def test_doctor_reports_driver_from_isolated_folder(tmp_path, monkeypatch):
    folder = _windivert_folder(tmp_path)
    monkeypatch.setattr(doc, "WINDIVERT_DIR", folder)
    monkeypatch.setattr(doc, "_gdpi_backend", lambda: "legacy")
    result = doc.check_windivert()
    assert result.ok is True
    assert "bins/windivert" in result.message


def test_doctor_does_not_count_flat_copies(tmp_path, monkeypatch):
    bins = tmp_path / "bins"
    bins.mkdir()
    (bins / "WinDivert.dll").write_bytes(b"MZ")
    (bins / "WinDivert64.sys").write_bytes(b"MZ")
    monkeypatch.setattr(doc, "WINDIVERT_DIR", bins / "windivert")
    monkeypatch.setattr(doc, "_gdpi_backend", lambda: "legacy")
    assert doc.check_windivert().ok is False


def test_driver_check_and_tools_candidates_use_isolated_folder():
    from blackoutkit import tools
    from blackoutkit.daemon import qos_shaper

    assert tools.WINDIVERT_DIR == WINDIVERT_DIR
    assert qos_shaper.WINDIVERT_DIR == WINDIVERT_DIR


@pytest.fixture
def interactive_cli(monkeypatch):
    """Make the CLI believe it has a terminal so the confirmation path is reachable."""
    from blackoutkit import cli

    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    return cli


def test_config_defender_flag_refuses_without_terminal(monkeypatch):
    from typer.testing import CliRunner

    from blackoutkit import cli, typer_cli

    monkeypatch.setattr(cli, "is_interactive", lambda: False)
    with patch("blackoutkit.security.run_windivert_exclusion_setup") as setup:
        result = CliRunner().invoke(typer_cli.app, ["config", "--setup-defender-exclusion"])
    setup.assert_not_called()
    assert result.exit_code == 2
    assert "No changes were made" in result.output


def test_config_defender_flags_are_mutually_exclusive(monkeypatch):
    from typer.testing import CliRunner

    from blackoutkit import typer_cli

    with patch("blackoutkit.security.run_windivert_exclusion_setup") as setup:
        result = CliRunner().invoke(
            typer_cli.app, ["config", "--setup-defender-exclusion", "--remove-defender-exclusion"]
        )
    setup.assert_not_called()
    assert result.exit_code == 2


def test_config_defender_flag_runs_setup_when_interactive(interactive_cli, monkeypatch):
    from typer.testing import CliRunner

    from blackoutkit import typer_cli

    with patch("blackoutkit.security.run_windivert_exclusion_setup", return_value="declined") as setup:
        result = CliRunner().invoke(typer_cli.app, ["config", "--setup-defender-exclusion"])
    assert setup.call_count == 1
    assert setup.call_args.kwargs["remove"] is False
    assert result.exit_code == 0


@pytest.mark.parametrize("answer, expected", [
    ("yes", True),
    ("YES ", True),
    ("y", False),
    ("no", False),
    ("", False),
])
def test_typed_confirmation_accepts_only_yes(interactive_cli, monkeypatch, answer, expected):
    monkeypatch.setattr("builtins.input", lambda _prompt="": answer)
    captured = {}

    def fake_setup(*, confirm, emit, remove=False):
        captured["confirmed"] = confirm()
        return "declined"

    with patch("blackoutkit.security.run_windivert_exclusion_setup", side_effect=fake_setup):
        interactive_cli._run_defender_exclusion_setup(remove=False)
    assert captured["confirmed"] is expected


def test_typed_confirmation_treats_end_of_input_as_cancel(interactive_cli, monkeypatch):
    def closed_stdin(_prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", closed_stdin)
    captured = {}

    def fake_setup(*, confirm, emit, remove=False):
        captured["confirmed"] = confirm()
        return "declined"

    with patch("blackoutkit.security.run_windivert_exclusion_setup", side_effect=fake_setup):
        interactive_cli._run_defender_exclusion_setup(remove=False)
    assert captured["confirmed"] is False


def test_doctor_fix_av_uses_the_confirmed_setup(monkeypatch):
    from blackoutkit import cli

    calls = []
    monkeypatch.setattr(cli, "_run_defender_exclusion_setup", lambda remove=False: calls.append(remove) or "declined")
    cli.cmd_doctor(MagicMock(fix=False, fix_av=True, local_only=False, include_optional=False))
    assert calls == [False]
