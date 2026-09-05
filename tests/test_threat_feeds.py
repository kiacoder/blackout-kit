import json
import httpx
from blackoutkit.threat_feeds import (
    ThreatFeedManager,
    add_threat_feed,
    list_threat_feeds,
    remove_threat_feed,
    update_threat_feeds,
    get_active_blocked_indicators,
)

def test_threat_feed_manager_crud(tmp_path):
    feeds_file = tmp_path / "feeds.json"
    blocked_file = tmp_path / "blocked.json"
    mgr = ThreatFeedManager(feeds_file=feeds_file, blocked_file=blocked_file)

    # Initial feeds
    feeds = mgr.get_feeds()
    assert len(feeds) >= 3

    # Add feed
    new_feed = mgr.add_feed("test_feed", "Test Feed", "https://example.com/feed.txt", feed_type="ip")
    assert new_feed["id"] == "test_feed"

    # Remove feed
    removed = mgr.remove_feed("test_feed")
    assert removed is True
    assert mgr.remove_feed("nonexistent") is False

def test_feed_parsing(tmp_path):
    mgr = ThreatFeedManager(feeds_file=tmp_path / "f.json", blocked_file=tmp_path / "b.json")
    content = """
# Header comment
1.1.1.1
2.2.2.2 # comment
127.0.0.1 bad-domain.com
0.0.0.0 malware.org
    """
    parsed = mgr.parse_feed_content(content, feed_type="domain")
    expected_indicators = {"1.1.1.1", "2.2.2.2", "bad-domain.com", "malware.org"}
    assert parsed == expected_indicators

def test_feed_fetch_and_update(tmp_path):
    feeds_file = tmp_path / "feeds.json"
    blocked_file = tmp_path / "blocked.json"
    mgr = ThreatFeedManager(feeds_file=feeds_file, blocked_file=blocked_file)

    # Mock HTTP transport
    def custom_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="185.220.101.5\nmalicious-site.net\n")

    transport = httpx.MockTransport(custom_handler)
    client = httpx.Client(transport=transport)

    stats = mgr.fetch_and_update_all(client=client)
    assert stats["feeds_processed"] >= 1

    blocked = mgr.get_blocked_indicators()
    assert len(blocked["blocked_ips"]) > 0 or len(blocked["blocked_domains"]) > 0

def test_threat_feed_helpers():
    feeds = list_threat_feeds()
    assert isinstance(feeds, list)
    added = add_threat_feed("helper_feed", "Helper Feed", "https://example.com/h.txt")
    assert added["id"] == "helper_feed"
    removed = remove_threat_feed("helper_feed")
    assert removed is True
