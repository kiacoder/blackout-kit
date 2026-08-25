import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from blackoutkit.engines.base import Engine

class DummyEngine(Engine):
    name = "dummy"
    description = "A dummy engine"
    def start(self):
        return True

def test_engine_init():
    engine = DummyEngine()
    assert engine.name == "dummy"
    assert engine._process is None
    assert engine._dll_stop_func is None
    assert engine._health_check_addr is None
    assert isinstance(engine._config_dir, Path)
    assert engine._config_dir.exists()

def test_engine_stop_with_dll_func():
    engine = DummyEngine()
    mock_stop_func = MagicMock()
    engine._dll_stop_func = mock_stop_func
    
    with patch.object(engine, '_cleanup_config_dir') as mock_cleanup:
        engine.stop()
        
        mock_stop_func.assert_called_once()
        assert engine._dll_stop_func is None
        mock_cleanup.assert_called_once()

def test_engine_stop_no_process():
    engine = DummyEngine()
    engine._process = None
    
    with patch.object(engine, '_cleanup_config_dir') as mock_cleanup:
        engine.stop()
        mock_cleanup.assert_called_once()

def test_cleanup_config_dir():
    engine = DummyEngine()
    config_dir = engine._config_dir
    assert config_dir.exists()
    
    engine._cleanup_config_dir()
    
    assert not config_dir.exists()

def test_engine_health_check_addr():
    engine = DummyEngine()
    engine._health_check_addr = ("127.0.0.1", 8080)
    assert engine._health_check_addr[1] == 8080


def test_graceful_process_stop_cleans_config_dir_and_clears_process(monkeypatch):
    class NoSuchProcess(Exception):
        pass

    child = MagicMock(pid=456)
    parent = MagicMock()
    parent.children.return_value = [child]
    process = MagicMock(pid=123)
    engine = DummyEngine()
    config_dir = engine._config_dir
    engine._process = process
    fake_psutil = SimpleNamespace(
        Process=lambda pid: parent,
        NoSuchProcess=NoSuchProcess,
    )
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)

    engine.stop()

    assert config_dir.exists() is False
    assert engine._process is None
    parent.terminate.assert_called_once_with()
    child.terminate.assert_called_once_with()
    process.wait.assert_called_once_with(timeout=3.0)
    parent.kill.assert_not_called()
    child.kill.assert_not_called()


def test_config_directory_cleanup_failure_is_logged(caplog, monkeypatch):
    engine = DummyEngine()
    config_dir = engine._config_dir
    monkeypatch.setattr(
        "blackoutkit.engines.base.shutil.rmtree",
        lambda _path: (_ for _ in ()).throw(OSError("permission denied")),
    )

    with caplog.at_level(logging.WARNING, logger="blackoutkit.engine"):
        engine._cleanup_config_dir()

    assert config_dir.exists()
    assert "Failed to clean up config directory" in caplog.text
    assert "permission denied" in caplog.text
