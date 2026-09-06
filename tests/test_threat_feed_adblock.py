"""Threat-feed integration with the DNS sinkhole rule matcher."""

import json

from blackoutkit.tools import adblock


def _configure_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(adblock, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(adblock, "ADBLOCK_RULES_FILE", tmp_path / "adblock_rules.json")
    monkeypatch.setattr(adblock, "ADBLOCK_CACHE_DIR", tmp_path / "adblock_cache")


def test_threat_domain_matches_exact_and_subdomains(monkeypatch, tmp_path):
    _configure_paths(monkeypatch, tmp_path)
    threat_dir = tmp_path / "threat-feeds"
    threat_dir.mkdir()
    (threat_dir / "blocked_domains.json").write_text(
        json.dumps(["evil.example"]), encoding="utf-8"
    )
    assert adblock.check_domain_blocked("evil.example") == (True, "evil.example")
    assert adblock.check_domain_blocked("sub.evil.example") == (
        True,
        "evil.example",
    )


def test_adblock_whitelist_overrides_threat_domain(monkeypatch, tmp_path):
    _configure_paths(monkeypatch, tmp_path)
    threat_dir = tmp_path / "threat-feeds"
    threat_dir.mkdir()
    (threat_dir / "blocked_domains.json").write_text(
        json.dumps(["evil.example"]), encoding="utf-8"
    )
    (tmp_path / "adblock_rules.json").write_text(
        json.dumps(
            {
                "sources": [],
                "custom_blocks": [],
                "whitelist": ["evil.example"],
                "stats": {"total_rules": 0, "queries_blocked_today": 0},
            }
        ),
        encoding="utf-8",
    )
    assert adblock.check_domain_blocked("sub.evil.example") == (False, "")


def test_corrupt_threat_domain_file_is_ignored(monkeypatch, tmp_path):
    _configure_paths(monkeypatch, tmp_path)
    threat_dir = tmp_path / "threat-feeds"
    threat_dir.mkdir()
    (threat_dir / "blocked_domains.json").write_text("invalid", encoding="utf-8")
    assert adblock.check_domain_blocked("evil.example") == (False, "")
