"""Phase 8 — community marketplace (blackoutkit.marketplace)."""
from __future__ import annotations

import hashlib
import json

import pytest

from blackoutkit.marketplace import Marketplace, MarketplaceEntry, MarketplaceError

PLUGIN_BYTES = b"# a plugin\nPLUGIN = None\n"
SHA = hashlib.sha256(PLUGIN_BYTES).hexdigest()


def _entry(**over):
    base = {
        "name": "hello", "kind": "rule", "url": "https://example.test/hello.py",
        "sha256": SHA, "version": "1.0", "description": "says hello", "author": "me",
    }
    base.update(over)
    return base


def _fetcher(payload: bytes):
    return lambda url: payload


# ── catalog loading ──────────────────────────────────────────────────────────

def test_load_catalog_list():
    m = Marketplace(catalog=[_entry()])
    assert [e.name for e in m.entries()] == ["hello"]
    assert m.info("hello").sha256 == SHA


def test_load_catalog_mapping():
    m = Marketplace(catalog={"hello": _entry()})
    assert m.info("hello").kind == "rule"


def test_load_catalog_wrapped_plugins_key():
    m = Marketplace(catalog={"plugins": [_entry()]})
    assert len(m.entries()) == 1


def test_load_catalog_from_file(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps([_entry()]), encoding="utf-8")
    m = Marketplace(catalog=path)
    assert [e.name for e in m.entries()] == ["hello"]


@pytest.mark.parametrize("bad", [
    {"name": "", "kind": "rule", "url": "x", "sha256": SHA},
    {"name": "p", "kind": "rule", "url": "", "sha256": SHA},
    {"name": "p", "kind": "rule", "url": "x", "sha256": "deadbeef"},
    {"name": "p", "kind": "bogus", "url": "x", "sha256": SHA},
])
def test_invalid_entries_rejected(bad):
    with pytest.raises(MarketplaceError):
        Marketplace(catalog=[bad])


def test_search_and_unknown():
    m = Marketplace(catalog=[_entry(), _entry(name="world", description="greets earth")])
    assert [e.name for e in m.search("hello")] == ["hello"]
    assert {e.name for e in m.search("e")} == {"hello", "world"}  # 'e' appears in both names/descriptions
    with pytest.raises(MarketplaceError):
        m.info("nope")


def test_refresh_merges_catalog():
    m = Marketplace()
    added = m.refresh(fetcher=_fetcher(json.dumps([_entry()]).encode()))
    assert added == 1
    assert m.info("hello").name == "hello"


def test_refresh_rejects_bad_json():
    m = Marketplace()
    with pytest.raises(MarketplaceError):
        m.refresh(fetcher=_fetcher(b"not json"))


# ── install / remove ─────────────────────────────────────────────────────────

def test_install_verifies_and_writes(tmp_path):
    m = Marketplace(tmp_path, catalog=[_entry()])
    path = m.install("hello", fetcher=_fetcher(PLUGIN_BYTES))
    assert path == tmp_path / "hello.py"
    assert path.read_bytes() == PLUGIN_BYTES


def test_install_checksum_mismatch_raises(tmp_path):
    m = Marketplace(tmp_path, catalog=[_entry()])
    with pytest.raises(MarketplaceError):
        m.install("hello", fetcher=_fetcher(b"tampered"))
    assert not (tmp_path / "hello.py").exists()  # nothing written


def test_install_without_verify_writes(tmp_path):
    m = Marketplace(tmp_path, catalog=[_entry()])
    m.install("hello", fetcher=_fetcher(b"anything"), verify=False)
    assert (tmp_path / "hello.py").read_bytes() == b"anything"


def test_install_unknown_raises(tmp_path):
    with pytest.raises(MarketplaceError):
        Marketplace(tmp_path).install("nope", fetcher=_fetcher(PLUGIN_BYTES))


def test_remove_and_installed(tmp_path):
    m = Marketplace(tmp_path, catalog=[_entry()])
    m.install("hello", fetcher=_fetcher(PLUGIN_BYTES))
    assert m.installed() == ["hello"]
    assert m.remove("hello") is True
    assert m.remove("hello") is False
    assert m.installed() == []


def test_entry_dicts_roundtrip():
    m = Marketplace(catalog=[_entry()])
    d = m.entry_dicts()[0]
    assert d["name"] == "hello" and d["sha256"] == SHA
    assert MarketplaceEntry.from_dict(d).name == "hello"
