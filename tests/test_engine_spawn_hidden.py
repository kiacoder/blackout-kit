"""Regression tests: engine process spawns must stay invisible.

The daemon runs console-free (pythonw.exe). A console-subsystem engine
binary spawned without CREATE_NO_WINDOW makes Windows allocate a brand-new
console window for every engine start, restart and config rotation —
reported live as "empty powershell windows keep opening and closing".
"""
import os
import subprocess
import sys

import pytest

from blackoutkit.engines.base import Engine


class _DummyEngine(Engine):
    name = "dummy"

    def start(self) -> bool:
        return True


class _FakeProcess:
    pid = 4242

    def poll(self):
        return None


def _capture_popen(monkeypatch):
    captured = {}

    def fake_popen(command, **kwargs):
        captured.update(kwargs)
        return _FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return captured


@pytest.mark.skipif(sys.platform != "win32", reason="CREATE_NO_WINDOW exists only on Windows")
def test_start_process_hides_console_on_windows(monkeypatch):
    captured = _capture_popen(monkeypatch)
    # sys.platform, not os.name: patching os.name makes pathlib.Path() raise
    # NotImplementedError on Windows ("cannot instantiate 'PosixPath'"), so the
    # engine could not even be constructed and the test failed before it could
    # assert anything.
    monkeypatch.setattr(sys, "platform", "win32")

    engine = _DummyEngine()
    assert engine.start_process(["xray.exe", "run", "-c", "config.json"]) is True
    assert captured["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert captured["creationflags"] == 0x08000000
    engine.stop()


def test_start_process_no_window_flag_off_platform(monkeypatch):
    captured = _capture_popen(monkeypatch)
    monkeypatch.setattr(sys, "platform", "linux")

    engine = _DummyEngine()
    assert engine.start_process(["xray", "run"]) is True
    assert captured["creationflags"] == 0
    engine.stop()
