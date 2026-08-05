import pytest
from unittest.mock import patch, MagicMock
from blackoutkit.engines.sni import SNIEngine
from blackoutkit.engines.xray import XRayEngine

def test_sni_engine_init():
    engine = SNIEngine()
    assert engine.name == "sni"
    assert engine.listen_port > 0

def test_xray_engine_init():
    engine = XRayEngine()
    assert engine.name == "xray"
    

