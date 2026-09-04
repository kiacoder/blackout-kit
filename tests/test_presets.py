"""Tests for Phase 5D Regional Presets."""
import yaml
from pathlib import Path

def test_regional_presets_exist_and_valid():
    presets_dir = Path("configs/presets")
    for region in ["ru", "ir", "cn"]:
        config_path = presets_dir / f"{region}.yaml"
        assert config_path.exists(), f"Preset {config_path} missing"
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            assert data["region"] == region.upper()
            assert "dns" in data
            assert "routing" in data
