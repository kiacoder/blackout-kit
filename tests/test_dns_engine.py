"""DNS engine: catalogue fidelity, target parsing, apply/restore bookkeeping.

The catalogue values are copied from XDNS, so these tests pin the exact pairs:
a typo in an address is the kind of bug that only shows up as "DNS is broken
in Iran" months later.
"""
from __future__ import annotations

import json

import pytest

from blackoutkit import dns_engine as dns


# ───────────── catalogue ─────────────


def test_sanctions_pairs_match_xdns():
    # Subset, not equality: the catalogue is allowed to grow, but these exact
    # pairs must never change or disappear.
    expected = {
        "shecan": ("178.22.122.100", "185.51.200.2"),
        "electro": ("78.157.42.100", "78.157.42.101"),
        "begzar": ("185.55.226.26", "185.55.226.25"),
        "radar": ("10.202.10.10", "10.202.10.11"),
        "opendns": ("208.67.222.222", "208.67.220.220"),
    }
    actual = {p.key: p.servers for p in dns.providers(dns.CATEGORY_SANCTIONS)}
    for key, pair in expected.items():
        assert actual.get(key) == pair


def test_speed_pairs_match_xdns():
    expected = {
        "yandex": ("77.88.8.8", "77.88.8.1"),
        "cloudflare": ("1.1.1.1", "1.0.0.1"),
        "google": ("8.8.8.8", "8.8.4.4"),
    }
    actual = {p.key: p.servers for p in dns.providers(dns.CATEGORY_SPEED)}
    for key, pair in expected.items():
        assert actual.get(key) == pair


def test_every_key_is_unique():
    keys = [p.key for p in dns.providers()]
    assert len(keys) == len(set(keys))


def test_no_address_is_shared_between_providers():
    """Two providers claiming one address would make `find` ambiguous."""
    seen: dict[str, str] = {}
    for prov in dns.providers():
        for server in prov.servers:
            assert server not in seen, f"{server} used by {seen.get(server)} and {prov.key}"
            seen[server] = prov.key


def test_every_catalogue_address_is_an_ip_literal():
    for prov in dns.providers():
        for server in prov.servers:
            assert dns.is_ip_literal(server), f"{prov.key} -> {server}"


def test_categories_are_ordered_and_non_empty():
    cats = [cat for cat, _label, provs in dns.DNSEngine().categories() if provs]
    assert cats == [dns.CATEGORY_SANCTIONS, dns.CATEGORY_SPEED, dns.CATEGORY_EXTRA]


def test_find_by_key_name_and_address():
    assert dns.find("shecan").key == "shecan"
    assert dns.find("Shecan").key == "shecan"
    assert dns.find("SHEcan").key == "shecan"
    assert dns.find("185.51.200.2").key == "shecan"      # secondary resolves too
    assert dns.find("1.0.0.1").key == "cloudflare"
    assert dns.find("nope.example") is None
    assert dns.find("") is None


def test_active_provider_infers_from_servers():
    assert dns.active_provider(["178.22.122.100", "185.51.200.2"]).key == "shecan"
    assert dns.active_provider(["203.0.113.9"]) is None


# ───────────── target parsing ─────────────


@pytest.mark.parametrize(
    "query, servers",
    [
        ("shecan", ["178.22.122.100", "185.51.200.2"]),
        ("cloudflare", ["1.1.1.1", "1.0.0.1"]),
        ("1.2.3.4", ["1.2.3.4"]),
        ("1.2.3.4,5.6.7.8", ["1.2.3.4", "5.6.7.8"]),
        ("1.2.3.4 5.6.7.8", ["1.2.3.4", "5.6.7.8"]),
        ("2606:4700:4700::1111", ["2606:4700:4700::1111"]),
    ],
)
def test_resolve_target_accepts_keys_and_ip_lists(query, servers):
    got, _label = dns.DNSEngine()._resolve_target(query)
    assert got == servers


@pytest.mark.parametrize("query", ["", "not-a-provider", "1.2.3.4,bogus"])
def test_resolve_target_rejects_junk(query):
    servers, _label = dns.DNSEngine()._resolve_target(query)
    assert servers == []


# ───────────── apply / restore ─────────────


class _FakeEngine(dns.DNSEngine):
    """Records dispatch calls instead of touching the OS."""

    def __init__(self, current=("1.1.1.1", "1.0.0.1")):
        super().__init__()
        self._current = list(current)
        self.applied_calls = []
        self.restored_calls = []
        self.apply_ok = True

    def current_servers(self):
        return list(self._current)

    def _dispatch_apply(self, servers, adapter):
        self.applied_calls.append((tuple(servers), adapter))
        if self.apply_ok:
            self._current = list(servers)
        return dns.DNSApplyResult(self.apply_ok, "fake apply", adapter=adapter)

    def _dispatch_restore(self, adapters):
        self.restored_calls.append(tuple(adapters))
        self._current = ["1.1.1.1"]
        return dns.DNSApplyResult(True, "fake restore")


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    path = tmp_path / "dns_state.json"
    monkeypatch.setattr(dns, "STATE_FILE", path)
    monkeypatch.setattr(dns, "APP_DATA_DIR", tmp_path)
    return path


def test_apply_writes_both_addresses_and_records_previous(state_file):
    engine = _FakeEngine(current=("8.8.8.8", "8.8.4.4"))
    result = engine.apply("shecan")

    assert result.ok
    assert result.applied == ("178.22.122.100", "185.51.200.2")
    assert result.previous == ("8.8.8.8", "8.8.4.4")
    assert engine.applied_calls == [(("178.22.122.100", "185.51.200.2"), None)]

    saved = json.loads(state_file.read_text(encoding="utf-8"))
    assert saved["applied"] == ["178.22.122.100", "185.51.200.2"]
    assert saved["previous"] == ["8.8.8.8", "8.8.4.4"]
    assert "Shecan" in saved["provider"]


def test_apply_is_a_noop_when_already_active(state_file):
    engine = _FakeEngine(current=("178.22.122.100", "185.51.200.2"))
    result = engine.apply("shecan")
    assert result.ok
    assert "Already using" in result.detail
    assert engine.applied_calls == []


def test_apply_unknown_provider_fails_with_the_catalogue_listed(state_file):
    engine = _FakeEngine()
    result = engine.apply("definitely-not-a-dns")
    assert not result.ok
    assert "shecan" in result.detail
    assert engine.applied_calls == []


def test_failed_apply_keeps_the_previous_state_for_a_retry(state_file):
    engine = _FakeEngine(current=("8.8.8.8",))
    engine.apply_ok = False
    result = engine.apply("google")
    assert not result.ok
    # The snapshot was taken before the attempt, so restore still knows what
    # the machine looked like.
    assert json.loads(state_file.read_text(encoding="utf-8"))["previous"] == ["8.8.8.8"]


def test_restore_clears_state_and_uses_saved_adapters(state_file):
    engine = _FakeEngine(current=("8.8.8.8",))
    engine.apply("shecan", adapter="Ethernet")
    result = engine.restore()

    assert result.ok
    assert engine.restored_calls == [("Ethernet",)]
    assert json.loads(state_file.read_text(encoding="utf-8")) == {}


def test_state_survives_a_corrupt_file(state_file):
    state_file.write_text("{not json", encoding="utf-8")
    assert dns.load_state() == {}


def test_describe_includes_both_addresses():
    assert dns.find("cloudflare").describe() == "Cloudflare (1.1.1.1, 1.0.0.1)"
