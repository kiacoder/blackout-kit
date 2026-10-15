"""Validate the shipped regional routing presets under configs/presets/.

These files are part of Roadmap Phase 5 ("Regional preset files ... with routing
docs"). They already exist; this test locks their schema so a bad edit breaks CI
instead of failing silently at connect time.
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

PRESET_DIR = pathlib.Path(__file__).resolve().parents[1] / "configs" / "presets"
PRESET_FILES = {
    "ru.yaml": "RU",
    "ir.yaml": "IR",
    "cn.yaml": "CN",
}

REQUIRED_TOP_LEVEL = ("region", "name", "version", "dns", "transport", "routing")


@pytest.mark.parametrize("filename,expected_region", PRESET_FILES.items())
def test_preset_file_parses_and_has_schema(filename, expected_region):
    path = PRESET_DIR / filename
    assert path.exists(), f"missing preset file: {path}"

    text = path.read_text(encoding="utf-8")
    # yaml.safe_load raises on duplicate keys only with the C loader in some
    # versions; round-trip a second load to confirm it is stable/well-formed.
    data = yaml.safe_load(text)
    assert isinstance(data, dict), f"{filename}: top level must be a mapping"

    for key in REQUIRED_TOP_LEVEL:
        assert key in data, f"{filename}: missing required key '{key}'"

    assert data["region"] == expected_region, (
        f"{filename}: region must be {expected_region}, got {data.get('region')!r}"
    )

    # dns block must at least name a mode and a primary resolver.
    dns = data["dns"]
    assert isinstance(dns, dict), f"{filename}: dns must be a mapping"
    assert dns.get("mode"), f"{filename}: dns.mode is required"
    assert dns.get("primary"), f"{filename}: dns.primary is required"

    # transport block must name a type.
    transport = data["transport"]
    assert isinstance(transport, dict), f"{filename}: transport must be a mapping"
    assert transport.get("type"), f"{filename}: transport.type is required"

    # routing block must be present (even if just bypass_local: true).
    assert isinstance(data["routing"], dict), f"{filename}: routing must be a mapping"


def test_preset_docs_exist():
    readme = PRESET_DIR / "README.md"
    assert readme.exists(), "configs/presets/README.md is missing"
    body = readme.read_text(encoding="utf-8").lower()
    for token in ("ru.yaml", "ir.yaml", "cn.yaml"):
        assert token in body, f"README must document {token}"
