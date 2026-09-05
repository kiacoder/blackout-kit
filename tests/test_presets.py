"""Tests for Phase 5D Regional Presets."""
import re
from pathlib import Path

def test_regional_presets_exist_and_valid():
    presets_dir = Path("configs/presets")
    for region in ["ru", "ir", "cn"]:
        config_path = presets_dir / f"{region}.yaml"
        assert config_path.exists(), f"Preset {config_path} missing"
        content = config_path.read_text(encoding="utf-8")
        assert f"region: {region.upper()}" in content
        assert "dns:" in content
        assert "routing:" in content
