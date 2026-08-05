import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
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
