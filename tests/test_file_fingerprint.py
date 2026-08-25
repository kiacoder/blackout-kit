import hashlib
from pathlib import Path
from unittest.mock import Mock

from blackoutkit.tools import file_fingerprint


def _target(tmp_path: Path, contents: bytes = b"sample") -> Path:
    target = tmp_path / "sample.bin"
    target.write_bytes(contents)
    return target


def test_fingerprint_file_reports_known_sha256_and_byte_count(tmp_path):
    contents = b"blackout-kit"
    target = _target(tmp_path, contents)

    result = file_fingerprint.fingerprint_file(target)

    assert result == {
        "status": "fingerprinted",
        "target": str(target.resolve()),
        "sha256": hashlib.sha256(contents).hexdigest(),
        "bytes": len(contents),
    }


def test_fingerprint_file_handles_empty_file(tmp_path):
    target = _target(tmp_path, b"")

    result = file_fingerprint.fingerprint_file(target)

    assert result["status"] == "fingerprinted"
    assert result["sha256"] == hashlib.sha256(b"").hexdigest()
    assert result["bytes"] == 0


def test_fingerprint_file_reads_large_files_in_bounded_chunks(monkeypatch, tmp_path):
    contents = b"a" * (file_fingerprint.CHUNK_SIZE * 2 + 7)
    target = _target(tmp_path, contents)
    read_sizes = []

    class Source:
        def __init__(self):
            self.position = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, size):
            read_sizes.append(size)
            chunk = contents[self.position:self.position + size]
            self.position += len(chunk)
            return chunk

    monkeypatch.setattr(Path, "open", lambda _path, _mode: Source())

    result = file_fingerprint.fingerprint_file(target)

    assert result["status"] == "fingerprinted"
    assert result["sha256"] == hashlib.sha256(contents).hexdigest()
    assert result["bytes"] == len(contents)
    assert read_sizes == [
        file_fingerprint.CHUNK_SIZE,
        file_fingerprint.CHUNK_SIZE,
        file_fingerprint.CHUNK_SIZE,
        file_fingerprint.CHUNK_SIZE,
    ]


def test_fingerprint_file_rejects_missing_target_without_opening(monkeypatch, tmp_path):
    open_file = Mock()
    monkeypatch.setattr(Path, "open", open_file)

    result = file_fingerprint.fingerprint_file(tmp_path / "missing.bin")

    assert result["status"] == "invalid-target"
    open_file.assert_not_called()


def test_fingerprint_file_rejects_directory_without_opening(monkeypatch, tmp_path):
    open_file = Mock()
    monkeypatch.setattr(Path, "open", open_file)

    result = file_fingerprint.fingerprint_file(tmp_path)

    assert result["status"] == "invalid-target"
    open_file.assert_not_called()


def test_fingerprint_file_reports_read_failure(monkeypatch, tmp_path):
    target = _target(tmp_path)
    monkeypatch.setattr(Path, "open", Mock(side_effect=OSError("file is locked")))

    result = file_fingerprint.fingerprint_file(target)

    assert result["status"] == "read-error"
    assert result["detail"] == "file is locked"


def test_fingerprint_file_withholds_digest_when_file_changes_during_read(monkeypatch, tmp_path):
    target = _target(tmp_path)
    monkeypatch.setattr(
        file_fingerprint,
        "_stat_snapshot",
        Mock(side_effect=[(1, 2, 6, 3), (1, 2, 7, 4)]),
    )

    result = file_fingerprint.fingerprint_file(target)

    assert result["status"] == "changed-during-read"
    assert "sha256" not in result
    assert "stable digest" in result["detail"]


def test_tools_dispatcher_renders_local_fingerprint_without_malware_verdict(monkeypatch, tmp_path):
    from blackoutkit import cli

    target = tmp_path / "sample.bin"
    printed = []
    monkeypatch.setattr(
        "blackoutkit.tools.file_fingerprint.fingerprint_file",
        lambda _path: {
            "status": "fingerprinted",
            "target": str(target),
            "sha256": "a" * 64,
            "bytes": 42,
        },
    )
    monkeypatch.setattr(cli.console, "print", lambda message: printed.append(str(message)))

    cli.cmd_tools(type("Args", (), {"tools_command": "file-hash", "path": str(target)})())

    output = "\n".join(printed).lower()
    assert "sha-256" in output
    assert "a" * 64 in output
    assert "42 bytes" in output
    assert "threat" not in output


def test_tools_dispatcher_withholds_digest_for_changed_file(monkeypatch, tmp_path):
    from blackoutkit import cli

    target = tmp_path / "sample.bin"
    printed = []
    monkeypatch.setattr(
        "blackoutkit.tools.file_fingerprint.fingerprint_file",
        lambda _path: {
            "status": "changed-during-read",
            "target": str(target),
            "detail": "The file changed while it was being read; no stable digest was produced.",
        },
    )
    monkeypatch.setattr(cli.console, "print", lambda message: printed.append(str(message)))

    cli.cmd_tools(type("Args", (), {"tools_command": "file-hash", "path": str(target)})())

    output = "\n".join(printed).lower()
    assert "no stable sha-256" in output
    assert "a" * 64 not in output
