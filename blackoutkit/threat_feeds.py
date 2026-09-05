"""
Blackout Kit - Threat Intelligence Feeds Engine.
Fetches, parses, and automatically blocks malicious IPs and domains
from security intelligence providers (abuse.ch, PhishTank, URLhaus, C2 infrastructure lists).
Integrates directly with DNS Sinkhole (adblock) and firewall rule engine.
"""
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import httpx

from blackoutkit import APP_DATA_DIR

_log = logging.getLogger(__name__)

THREAT_FEEDS_DIR = APP_DATA_DIR / "threat_feeds"
FEEDS_CONFIG_FILE = THREAT_FEEDS_DIR / "feeds.json"
BLOCKED_INDICATORS_FILE = THREAT_FEEDS_DIR / "blocked_indicators.json"


DEFAULT_FEEDS = [
    {
        "id": "abusech_ipblocklist",
        "name": "Abuse.ch SSL IP Blacklist",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip",
        "enabled": True,
    },
    {
        "id": "urlhaus_malware_domains",
        "name": "URLhaus Malware Domains",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "type": "domain",
        "enabled": True,
    },
    {
        "id": "feodotracker_c2",
        "name": "Feodo Tracker Botnet C2 IP Blocklist",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "ip",
        "enabled": True,
    },
]


class ThreatFeedManager:
    """Manages threat intelligence feed fetching, parsing, and auto-blocking."""

    def __init__(self, feeds_file: Path = FEEDS_CONFIG_FILE, blocked_file: Path = BLOCKED_INDICATORS_FILE):
        self.feeds_file = feeds_file
        self.blocked_file = blocked_file
        self.feeds_file.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_default_feeds()

    def _ensure_default_feeds(self) -> None:
        if not self.feeds_file.exists():
            self._save_feeds(DEFAULT_FEEDS)

    def get_feeds(self) -> List[Dict[str, Any]]:
        if not self.feeds_file.exists():
            return DEFAULT_FEEDS
        try:
            with open(self.feeds_file, "r") as f:
                return json.load(f)
        except Exception as e:
            _log.error("Failed to read feeds file: %s", e)
            return DEFAULT_FEEDS

    def _save_feeds(self, feeds: List[Dict[str, Any]]) -> None:
        try:
            with open(self.feeds_file, "w") as f:
                json.dump(feeds, f, indent=2)
        except Exception as e:
            _log.error("Failed to save feeds file: %s", e)

    def add_feed(self, feed_id: str, name: str, url: str, feed_type: str = "domain") -> Dict[str, Any]:
        feeds = self.get_feeds()
        for f in feeds:
            if f["id"] == feed_id:
                f["name"] = name
                f["url"] = url
                f["type"] = feed_type
                f["enabled"] = True
                self._save_feeds(feeds)
                return f
        new_feed = {"id": feed_id, "name": name, "url": url, "type": feed_type, "enabled": True}
        feeds.append(new_feed)
        self._save_feeds(feeds)
        return new_feed

    def remove_feed(self, feed_id: str) -> bool:
        feeds = self.get_feeds()
        filtered = [f for f in feeds if f["id"] != feed_id]
        if len(filtered) < len(feeds):
            self._save_feeds(filtered)
            return True
        return False

    def parse_feed_content(self, content: str, feed_type: str) -> Set[str]:
        """Parse raw text content from feed into a set of indicators (IPs or domains)."""
        indicators = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            # Handle hosts format (e.g., 127.0.0.1 malicious.com)
            parts = line.split()
            if len(parts) >= 2 and parts[0] in {"127.0.0.1", "0.0.0.0"}:
                indicator = parts[1].strip().lower()
            else:
                indicator = parts[0].strip().lower()
            if indicator:
                indicators.add(indicator)
        return indicators

    def fetch_and_update_all(self, client: Optional[httpx.Client] = None) -> Dict[str, Any]:
        """Fetch all enabled feeds and compile active blocklist."""
        feeds = self.get_feeds()
        blocked_ips: Set[str] = set()
        blocked_domains: Set[str] = set()
        stats = {"feeds_processed": 0, "ips_blocked": 0, "domains_blocked": 0, "errors": []}

        should_close = False
        if client is None:
            client = httpx.Client(timeout=10.0, follow_redirects=True)
            should_close = True

        try:
            for feed in feeds:
                if not feed.get("enabled", True):
                    continue
                try:
                    resp = client.get(feed["url"])
                    if resp.status_code == 200:
                        parsed = self.parse_feed_content(resp.text, feed.get("type", "domain"))
                        if feed.get("type") == "ip":
                            blocked_ips.update(parsed)
                        else:
                            blocked_domains.update(parsed)
                        stats["feeds_processed"] += 1
                    else:
                        stats["errors"].append(f"Feed {feed['id']} returned HTTP {resp.status_code}")
                except Exception as e:
                    stats["errors"].append(f"Feed {feed['id']} fetch error: {str(e)}")
        finally:
            if should_close:
                client.close()

        # Save blocked indicators
        blocked_data = {
            "last_updated": time.time(),
            "blocked_ips": sorted(list(blocked_ips)),
            "blocked_domains": sorted(list(blocked_domains)),
        }
        try:
            with open(self.blocked_file, "w") as f:
                json.dump(blocked_data, f, indent=2)
        except Exception as e:
            _log.error("Failed to write blocked indicators: %s", e)

        stats["ips_blocked"] = len(blocked_ips)
        stats["domains_blocked"] = len(blocked_domains)
        return stats

    def get_blocked_indicators(self) -> Dict[str, Any]:
        if not self.blocked_file.exists():
            return {"last_updated": 0, "blocked_ips": [], "blocked_domains": []}
        try:
            with open(self.blocked_file, "r") as f:
                return json.load(f)
        except Exception:
            return {"last_updated": 0, "blocked_ips": [], "blocked_domains": []}


_feed_manager = ThreatFeedManager()


def add_threat_feed(feed_id: str, name: str, url: str, feed_type: str = "domain") -> Dict[str, Any]:
    return _feed_manager.add_feed(feed_id, name, url, feed_type)


def list_threat_feeds() -> List[Dict[str, Any]]:
    return _feed_manager.get_feeds()


def remove_threat_feed(feed_id: str) -> bool:
    return _feed_manager.remove_feed(feed_id)


def update_threat_feeds(client: Optional[httpx.Client] = None) -> Dict[str, Any]:
    return _feed_manager.fetch_and_update_all(client=client)


def get_active_blocked_indicators() -> Dict[str, Any]:
    return _feed_manager.get_blocked_indicators()
