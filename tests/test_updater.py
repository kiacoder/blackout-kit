import hashlib
import io
import json
import zipfile
from unittest.mock import patch

from blackoutkit import updater


class _Response(io.BytesIO):
    def __init__(self, body: bytes):
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _archive() -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("blackout-kit/blackoutkit/version_marker.py", "VALUE = 2\n")
    return payload.getvalue()


def _release(body: bytes, digest: str | None):
    asset = {
        "name": "blackout-source.zip",
        "browser_download_url": "https://github.com/kiacoder/blackout-kit/releases/download/v2.0.0/blackout-source.zip",
        "size": len(body),
    }
    if digest is not None:
        asset["digest"] = f"sha256:{digest}"
    return {
        "tag_name": "v2.0.0",
        "assets": [asset],
        "source_asset": asset,
        "zipball_url": asset["browser_download_url"],
    }


def test_check_for_update_selects_digest_bearing_source_asset(monkeypatch):
    body = _archive()
    release = _release(body, hashlib.sha256(body).hexdigest())
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response(json.dumps(release).encode()))

    result = updater.check_for_update()

    assert result["source_asset"]["name"] == "blackout-source.zip"
    assert result["zipball_url"].endswith("blackout-source.zip")


def test_download_and_apply_rejects_missing_digest_before_download(monkeypatch):
    release = _release(_archive(), None)
    download = patch.object(updater.urllib.request, "urlopen")
    with download as urlopen:
        assert updater.download_and_apply(release) is False
    urlopen.assert_not_called()


def test_download_and_apply_rejects_digest_mismatch_before_replacement(monkeypatch, tmp_path):
    body = _archive()
    release = _release(body, "0" * 64)
    monkeypatch.setattr(updater, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(updater, "APP_DATA_DIR", tmp_path / "app")
    (tmp_path / "blackoutkit").mkdir()
    marker = tmp_path / "blackoutkit" / "marker.py"
    marker.write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response(body))

    assert updater.download_and_apply(release) is False
    assert marker.read_text(encoding="utf-8") == "old\n"


def test_download_and_apply_accepts_matching_digest_and_applies_source(monkeypatch, tmp_path):
    body = _archive()
    release = _release(body, hashlib.sha256(body).hexdigest())
    monkeypatch.setattr(updater, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(updater, "APP_DATA_DIR", tmp_path / "app")
    package = tmp_path / "blackoutkit"
    package.mkdir()
    (package / "marker.py").write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response(body))

    assert updater.download_and_apply(release) is True
    assert (package / "version_marker.py").read_text(encoding="utf-8") == "VALUE = 2\n"
