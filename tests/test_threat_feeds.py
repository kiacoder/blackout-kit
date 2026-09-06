"""Tests for threat intelligence feed management."""

import json

import httpx
import pytest

from blackoutkit.threat_feeds import ThreatFeed, ThreatFeedsManager


class FakeResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://example.com")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("error", request=request, response=response)


class TestFeedCRUD:
    """Test add/remove/list feeds."""

    def test_default_feeds_loaded(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        names = {f.name for f in manager.list_feeds()}
        assert "abuse.ch-ips" in names
        assert "phishtank-domains" in names
        assert "emergingthreats-ips" in names

    def test_add_feed(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        feed = ThreatFeed(name="custom-feed", url="https://example.com/feed.txt", feed_type="ip")
        assert manager.add_feed(feed) is True
        assert "custom-feed" in manager.feeds

    def test_add_duplicate_feed_fails(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        feed = ThreatFeed(name="abuse.ch-ips", url="https://example.com", feed_type="ip")
        assert manager.add_feed(feed) is False

    @pytest.mark.parametrize(
        "feed",
        [
            ThreatFeed(name="bad-url", url="file:///tmp/feed.txt", feed_type="ip"),
            ThreatFeed(name="bad-type", url="https://example.com/feed", feed_type="asn"),
            ThreatFeed(name="", url="https://example.com/feed", feed_type="domain"),
        ],
    )
    def test_add_feed_rejects_invalid_configuration(self, tmp_path, feed):
        manager = ThreatFeedsManager(config_dir=tmp_path)

        assert manager.add_feed(feed) is False
        assert feed.name not in manager.feeds

    def test_add_feed_normalizes_type(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        feed = ThreatFeed(name="upper-type", url="https://example.com/feed", feed_type="IP")

        assert manager.add_feed(feed) is True
        assert manager.feeds[feed.name].feed_type == "ip"

    def test_remove_feed(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager.remove_feed("abuse.ch-ips") is True
        assert "abuse.ch-ips" not in manager.feeds

    def test_remove_unknown_feed_fails(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager.remove_feed("nonexistent") is False

    def test_feeds_persisted_across_instances(self, tmp_path):
        manager1 = ThreatFeedsManager(config_dir=tmp_path)
        manager1.add_feed(ThreatFeed(name="custom", url="https://x.com", feed_type="ip"))

        manager2 = ThreatFeedsManager(config_dir=tmp_path)
        assert "custom" in manager2.feeds


class TestUpdateFeeds:
    """Test fetching and updating feeds, including HTTP error handling."""

    def test_update_skips_disabled_feeds(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        manager.feeds["abuse.ch-ips"].enabled = False
        results = manager.update_feeds()
        assert results["abuse.ch-ips"] is False

    def test_update_succeeds_on_valid_response(self, tmp_path, monkeypatch):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        monkeypatch.setattr(httpx, "get", lambda url, timeout=30: FakeResponse("1.2.3.4\n5.6.7.8\n"))

        results = manager.update_feeds()
        assert results["abuse.ch-ips"] is True
        assert "1.2.3.4" in manager.ip_set

    def test_update_handles_http_status_error(self, tmp_path, monkeypatch):
        """Verifies the fix: raise_for_status() raising HTTPStatusError must be caught."""
        manager = ThreatFeedsManager(config_dir=tmp_path)
        monkeypatch.setattr(httpx, "get", lambda url, timeout=30: FakeResponse("", status_code=500))

        results = manager.update_feeds()
        assert results["abuse.ch-ips"] is False
        assert results["phishtank-domains"] is False
        assert results["emergingthreats-ips"] is False

    def test_update_handles_request_error(self, tmp_path, monkeypatch):
        def raise_request_error(url, timeout=30):
            raise httpx.ConnectError("connection failed")

        manager = ThreatFeedsManager(config_dir=tmp_path)
        monkeypatch.setattr(httpx, "get", raise_request_error)

        results = manager.update_feeds()
        assert all(success is False for success in results.values())

    def test_update_sets_last_updated_on_success(self, tmp_path, monkeypatch):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        monkeypatch.setattr(httpx, "get", lambda url, timeout=30: FakeResponse("1.2.3.4\n"))

        manager.update_feeds()
        assert manager.feeds["abuse.ch-ips"].last_updated is not None


class TestBlockingChecks:
    """Test IP/domain blocking checks."""

    def test_is_ip_blocked(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        manager.ip_set.add("1.2.3.4")
        assert manager.is_ip_blocked("1.2.3.4") is True
        assert manager.is_ip_blocked("9.9.9.9") is False

    def test_is_domain_blocked_normalizes_case(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        manager.domain_set.add("evil.com")
        assert manager.is_domain_blocked("EVIL.com") is True
        assert manager.is_domain_blocked(" evil.com ") is True

    def test_add_custom_ip(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager.add_custom_ip("10.0.0.1") is True
        assert manager.is_ip_blocked("10.0.0.1") is True

    def test_add_custom_ip_rejects_invalid(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager.add_custom_ip("not-an-ip") is False

    def test_add_custom_domain(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager.add_custom_domain("Evil.COM") is True
        assert manager.is_domain_blocked("evil.com") is True

    def test_add_custom_domain_rejects_invalid(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager.add_custom_domain("nodothere") is False


class TestGetStats:
    """Test stats reporting."""

    def test_get_stats_initial(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        stats = manager.get_stats()
        assert stats["total_feeds"] == 3
        assert stats["enabled_feeds"] == 3
        assert stats["blocked_ips"] == 0
        assert stats["last_update"] == "never"

    def test_get_stats_after_blocking(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        manager.add_custom_ip("1.2.3.4")
        manager.add_custom_domain("evil.com")
        stats = manager.get_stats()
        assert stats["blocked_ips"] == 1
        assert stats["blocked_domains"] == 1


class TestIpFeedParsing:
    """Test IP feed parsing."""

    def test_parses_plain_ip_list(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        content = "1.2.3.4\n5.6.7.8\n# comment\n\n9.10.11.12"
        count = manager._parse_ip_feed(content, "test-feed")
        assert count == 3
        assert "1.2.3.4" in manager.ip_set
        assert "9.10.11.12" in manager.ip_set

    def test_strips_cidr_suffix(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        count = manager._parse_ip_feed("1.2.3.0/24", "test-feed")
        assert count == 1
        assert "1.2.3.0" in manager.ip_set

    def test_ignores_invalid_ips(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        count = manager._parse_ip_feed("not-an-ip\n999.999.999.999", "test-feed")
        assert count == 0


class TestDomainFeedParsing:
    """Test domain feed parsing (JSON and plain-text formats)."""

    def test_parses_json_list_of_dicts(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        content = json.dumps([{"url": "http://evil.com/phish"}, {"url": "http://bad.net/x"}])
        count = manager._parse_domain_feed(content, "phishtank")
        assert count == 2
        assert "evil.com" in manager.domain_set
        assert "bad.net" in manager.domain_set

    def test_parses_json_list_of_strings(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        content = json.dumps(["evil.com", "bad.net"])
        count = manager._parse_domain_feed(content, "phishtank")
        assert count == 2

    def test_parses_plain_text_domains(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        content = "evil.com\nbad.net\n# comment\n\ngood.org"
        count = manager._parse_domain_feed(content, "test-feed")
        assert count == 3

    def test_falls_back_on_invalid_json(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        content = "[not valid json"
        count = manager._parse_domain_feed(content, "test-feed")
        assert count == 0


class TestExtractDomain:
    """Test domain extraction from URLs."""

    def test_extracts_from_url(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager._extract_domain("http://evil.com/path") == "evil.com"

    def test_returns_bare_domain(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager._extract_domain("evil.com") == "evil.com"

    def test_returns_none_for_invalid(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager._extract_domain("nodothere") is None


class TestValidation:
    """Test IP and domain validation helpers."""

    def test_validate_ip_valid(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager._validate_ip("192.168.1.1") is True

    def test_validate_ip_invalid_range(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager._validate_ip("999.1.1.1") is False

    def test_validate_ip_wrong_parts(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager._validate_ip("1.2.3") is False

    def test_validate_domain_valid(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager._validate_domain("example.com") is True

    def test_validate_domain_no_dot(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager._validate_domain("example") is False

    def test_validate_domain_too_long(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager._validate_domain("a" * 256) is False


class TestPersistence:
    """Test load/save persistence for blocked lists."""

    def test_blocked_lists_persist_across_instances(self, tmp_path):
        manager1 = ThreatFeedsManager(config_dir=tmp_path)
        manager1.add_custom_ip("1.2.3.4")
        manager1.add_custom_domain("evil.com")

        manager2 = ThreatFeedsManager(config_dir=tmp_path)
        assert manager2.is_ip_blocked("1.2.3.4") is True
        assert manager2.is_domain_blocked("evil.com") is True

    def test_ignores_corrupt_blocked_files(self, tmp_path):
        (tmp_path).mkdir(parents=True, exist_ok=True)
        blocked_ips = tmp_path / "blocked_ips.json"
        blocked_ips.write_text("not valid json")

        manager = ThreatFeedsManager(config_dir=tmp_path)
        assert manager.ip_set == set()

    def test_replaces_delisted_feed_indicators(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        feed = manager.feeds["phishtank-domains"]
        manager._feed_indicators[feed.name] = {
            "ips": set(),
            "domains": {"old.example"},
        }
        manager._rebuild_indicator_sets()
        manager._save_blocked()

        manager._feed_indicators[feed.name] = {
            "ips": set(),
            "domains": {"new.example"},
        }
        manager._rebuild_indicator_sets()
        manager._save_blocked()
        restored = ThreatFeedsManager(config_dir=tmp_path)

        assert restored.is_domain_blocked("old.example") is False
        assert restored.is_domain_blocked("new.example") is True

    def test_ignores_structurally_invalid_feed_configuration(self, tmp_path):
        (tmp_path / "feeds.json").write_text(json.dumps([{}, None, {"name": "bad"}]))

        manager = ThreatFeedsManager(config_dir=tmp_path)

        assert {feed.name for feed in manager.list_feeds()} == {
            "abuse.ch-ips",
            "phishtank-domains",
            "emergingthreats-ips",
        }


class TestClearAll:
    """Test clearing all threat data."""

    def test_clear_all(self, tmp_path):
        manager = ThreatFeedsManager(config_dir=tmp_path)
        manager.add_custom_ip("1.2.3.4")
        manager.add_custom_domain("evil.com")

        manager.clear_all()
        assert manager.ip_set == set()
        assert manager.domain_set == set()
        assert manager.feeds == {}
