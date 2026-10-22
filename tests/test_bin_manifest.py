"""Binary integrity manifest: pin on first sight, refuse on change."""
import pytest

from blackoutkit import bin_manifest


@pytest.fixture
def sandbox(monkeypatch, tmp_path):
    monkeypatch.setattr(bin_manifest, "BINS_DIR", tmp_path)
    monkeypatch.setattr(bin_manifest, "MANIFEST_FILE", tmp_path / ".manifest.json")
    return tmp_path


def test_first_use_pins_then_accepts(sandbox):
    binary = sandbox / "engine.exe"
    binary.write_bytes(b"MZ-original")

    ok, detail = bin_manifest.verify(binary)
    assert ok and detail == ""
    # Second check hits the recorded hash.
    assert bin_manifest.verify(binary) == (True, "")


def test_changed_binary_is_refused(sandbox):
    binary = sandbox / "engine.exe"
    binary.write_bytes(b"MZ-original")
    bin_manifest.verify(binary)

    binary.write_bytes(b"MZ-replaced-payload")
    ok, detail = bin_manifest.verify(binary)
    assert not ok
    assert "hash mismatch" in detail


def test_missing_binary_is_refused(sandbox):
    ok, detail = bin_manifest.verify(sandbox / "absent.exe")
    assert not ok
    assert "missing" in detail


def test_verify_all_reports_each_pinned_binary(sandbox):
    good = sandbox / "good.exe"
    good.write_bytes(b"MZ-good")
    bin_manifest.verify(good)

    results = bin_manifest.verify_all()
    assert results and results[0][0] == "good.exe"
    assert results[0][1] is True
