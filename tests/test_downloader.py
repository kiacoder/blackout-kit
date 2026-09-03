import hashlib
import io
import json
import zipfile

from blackoutkit import downloader


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes):
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _zip_bytes(name="xray.exe", data=None):
    if data is None:
        data = bytearray(b"MZ" + b"\0" * 100)
        data[0x3C:0x40] = (0x40).to_bytes(4, "little")
        data[0x40:0x44] = b"PE\0\0"
        data = bytes(data)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def _release(asset_name, body, digest=None):
    asset = {
        "name": asset_name,
        "browser_download_url": f"https://github.com/example/release/{asset_name}",
        "size": len(body),
    }
    if digest is not None:
        asset["digest"] = f"sha256:{digest}"
    return {"tag_name": "v1.2.3", "assets": [asset]}


def test_sha256_file_reports_digest(tmp_path):
    path = tmp_path / "artifact"
    path.write_bytes(b"fixture")

    assert downloader.sha256_file(path) == hashlib.sha256(b"fixture").hexdigest()


def test_verified_download_rejects_missing_digest_and_preserves_existing_file(monkeypatch, tmp_path):
    archive = _zip_bytes()
    monkeypatch.setattr(downloader, "BINS_DIR", tmp_path)
    monkeypatch.setattr(downloader, "_PROVENANCE_FILE", tmp_path / ".provenance.json")
    monkeypatch.setattr(downloader, "BIN_REGISTRY", {
        "fixture": downloader.BinInfo(
            key="fixture", display_name="Fixture", description="fixture",
            github_repo="example/repo", asset_pattern="fixture.zip", asset_exclude=None,
            extract_map={"xray.exe": "xray.exe"}, output_bins=["xray.exe"], required=False,
            manual_url="https://github.com/example/repo/releases", manual_note="",
        ),
    })
    existing = tmp_path / "xray.exe"
    existing.write_bytes(b"old")
    monkeypatch.setattr(downloader, "_fetch_release", lambda _repo: _release("fixture.zip", archive))

    ok, message = downloader.download_binary("fixture")

    assert ok is False
    assert "digest metadata is missing" in message
    assert existing.read_bytes() == b"old"
    assert not (tmp_path / ".provenance.json").exists()


def test_verified_download_hash_mismatch_does_not_promote_staged_output(monkeypatch, tmp_path):
    archive = _zip_bytes()
    monkeypatch.setattr(downloader, "BINS_DIR", tmp_path)
    monkeypatch.setattr(downloader, "_PROVENANCE_FILE", tmp_path / ".provenance.json")
    monkeypatch.setattr(downloader, "BIN_REGISTRY", {
        "fixture": downloader.BinInfo(
            key="fixture", display_name="Fixture", description="fixture",
            github_repo="example/repo", asset_pattern="fixture.zip", asset_exclude=None,
            extract_map={"xray.exe": "xray.exe"}, output_bins=["xray.exe"], required=False,
            manual_url="https://github.com/example/repo/releases", manual_note="",
        ),
    })
    existing = tmp_path / "xray.exe"
    existing.write_bytes(b"old")
    wrong_digest = "0" * 64
    monkeypatch.setattr(downloader, "_fetch_release", lambda _repo: _release("fixture.zip", archive, wrong_digest))
    monkeypatch.setattr(downloader.urllib.request, "urlopen", lambda *_args, **_kwargs: FakeResponse(archive))

    ok, message = downloader.download_binary("fixture")

    assert ok is False
    assert "does not match" in message
    assert existing.read_bytes() == b"old"
    assert not (tmp_path / ".provenance.json").exists()


def test_verified_download_promotes_and_records_provenance(monkeypatch, tmp_path):
    archive = _zip_bytes()
    digest = hashlib.sha256(archive).hexdigest()
    monkeypatch.setattr(downloader, "BINS_DIR", tmp_path)
    monkeypatch.setattr(downloader, "_PROVENANCE_FILE", tmp_path / ".provenance.json")
    monkeypatch.setattr(downloader, "BIN_REGISTRY", {
        "fixture": downloader.BinInfo(
            key="fixture", display_name="Fixture", description="fixture",
            github_repo="example/repo", asset_pattern="fixture.zip", asset_exclude=None,
            extract_map={"xray.exe": "xray.exe"}, output_bins=["xray.exe"], required=False,
            manual_url="https://github.com/example/repo/releases", manual_note="",
        ),
    })
    monkeypatch.setattr(downloader, "_fetch_release", lambda _repo: _release("fixture.zip", archive, digest))
    monkeypatch.setattr(downloader.urllib.request, "urlopen", lambda *_args, **_kwargs: FakeResponse(archive))

    ok, message = downloader.download_binary("fixture")

    assert ok is True
    assert "SHA-256 verified" in message
    expected = bytearray(b"MZ" + b"\0" * 100)
    expected[0x3C:0x40] = (0x40).to_bytes(4, "little")
    expected[0x40:0x44] = b"PE\0\0"
    assert (tmp_path / "xray.exe").read_bytes() == bytes(expected)
    provenance = json.loads((tmp_path / ".provenance.json").read_text())
    assert provenance["artifacts"][0]["sha256"] == digest
    assert provenance["artifacts"][0]["output_sha256"] == hashlib.sha256(bytes(expected)).hexdigest()
    assert provenance["artifacts"][0]["verification"] == "sha256_and_structural"
    assert downloader.artifact_status()["fixture"] == "verified"
    assert downloader.verify_provenance()["xray.exe"] == "OK"

    (tmp_path / "xray.exe").write_bytes(b"tampered")
    assert downloader.artifact_status()["fixture"] == "invalid"


def test_zip_extraction_rejects_path_traversal(tmp_path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("xray.exe", b"safe")

    ok, detail = downloader._extract_from_zip(
        archive,
        {"xray.exe": "../escape.exe"},
        tmp_path / "stage",
    )

    assert ok is False
    assert detail == "unsafe_output_path"
    assert not (tmp_path / "escape.exe").exists()
