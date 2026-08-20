"""
Blackout Kit - Network-Level Ad & Tracker Blocking (Pi-hole-lite).
Manage blocklists, check domains, and log DNS queries.

Core features:
  - Download and parse blocklists (hosts file format)
  - Fast domain matching (suffix-based + exact match)
  - Whitelist/custom block rules
  - DNS query audit trail
  - Blocklist update tracking
"""
import json
import logging
import os
import tempfile
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, tuple

_log = logging.getLogger(__name__)

from .. import APP_DATA_DIR

ADBLOCK_RULES_FILE = APP_DATA_DIR / "adblock_rules.json"
ADBLOCK_CACHE_DIR = APP_DATA_DIR / "adblock_cache"
DNS_QUERY_LOG = APP_DATA_DIR / "dns_queries.jsonl"


# ──────────────────────────── Blocklist Management ──────────────────────────

def _ensure_adblock_dirs() -> None:
    """Ensure adblock directories exist."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    ADBLOCK_CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _load_adblock_config() -> dict:
    """Load adblock configuration."""
    _ensure_adblock_dirs()
    if not ADBLOCK_RULES_FILE.exists():
        return {"sources": [], "custom_blocks": [], "whitelist": [], "stats": {"total_rules": 0, "queries_blocked_today": 0}}
    try:
        return json.loads(ADBLOCK_RULES_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {"sources": [], "custom_blocks": [], "whitelist": [], "stats": {"total_rules": 0, "queries_blocked_today": 0}}


def _save_adblock_config(config: dict) -> None:
    """Save adblock configuration atomically."""
    _ensure_adblock_dirs()
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".json", dir=APP_DATA_DIR, text=True)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(config, f, indent=2)
            os.replace(tmp_path, ADBLOCK_RULES_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            raise
    except Exception:
        pass  # Silently fail


def add_blocklist_source(name: str, url: str) -> bool:
    """
    Add a new blocklist source.
    Returns True if added, False if already exists.
    """
    config = _load_adblock_config()

    # Check if already exists
    for source in config.get('sources', []):
        if source['name'].lower() == name.lower():
            return False

    config['sources'].append({
        'name': name,
        'url': url,
        'last_update': None,
        'enabled': True,
        'rule_count': 0
    })

    _save_adblock_config(config)
    return True


def remove_blocklist_source(name: str) -> bool:
    """Remove a blocklist source."""
    config = _load_adblock_config()
    original_len = len(config.get('sources', []))

    config['sources'] = [s for s in config.get('sources', []) if s['name'].lower() != name.lower()]

    if len(config['sources']) < original_len:
        _save_adblock_config(config)
        return True
    return False


def get_blocklist_sources() -> list[dict]:
    """Get all blocklist sources."""
    config = _load_adblock_config()
    return config.get('sources', [])


def download_blocklist(name: str, url: str) -> tuple[bool, int, str]:
    """
    Download and parse a blocklist (hosts file format).
    Returns: (success, rule_count, error_msg)
    """
    try:
        cache_file = ADBLOCK_CACHE_DIR / f"{name}.txt"

        # Download with timeout
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')
        except urllib.error.URLError as e:
            return False, 0, f"Download failed: {e}"
        except Exception as e:
            return False, 0, f"Network error: {e}"

        # Parse hosts file format (skip comments and empty lines)
        rules = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Standard hosts format: IP domain [domain2 ...]
            parts = line.split()
            if len(parts) >= 2:
                # Skip the first part (usually 0.0.0.0 or 127.0.0.1)
                for domain in parts[1:]:
                    if domain and '.' in domain:
                        rules.add(domain.lower())

        # Cache the blocklist
        cache_file.write_text('\n'.join(sorted(rules)))

        # Update config
        config = _load_adblock_config()
        for source in config.get('sources', []):
            if source['name'].lower() == name.lower():
                source['last_update'] = datetime.now(timezone.utc).isoformat()
                source['rule_count'] = len(rules)
                break

        _recompute_total_rules(config)
        _save_adblock_config(config)

        return True, len(rules), ""
    except Exception as e:
        return False, 0, str(e)


def update_all_blocklists() -> dict:
    """
    Update all enabled blocklists.
    Returns: {name: (success, rule_count, error)}
    """
    results = {}
    config = _load_adblock_config()

    for source in config.get('sources', []):
        if not source.get('enabled', True):
            continue

        success, rule_count, error = download_blocklist(source['name'], source['url'])
        results[source['name']] = (success, rule_count, error)

    return results


def _recompute_total_rules(config: dict) -> None:
    """Recompute total rule count."""
    total = sum(s.get('rule_count', 0) for s in config.get('sources', []))
    total += len(config.get('custom_blocks', []))
    config['stats']['total_rules'] = total


def add_custom_block(domain: str) -> bool:
    """Add a custom block rule."""
    config = _load_adblock_config()
    domain = domain.lower()

    if domain in config.get('custom_blocks', []):
        return False

    config['custom_blocks'].append(domain)
    _recompute_total_rules(config)
    _save_adblock_config(config)
    return True


def remove_custom_block(domain: str) -> bool:
    """Remove a custom block rule."""
    config = _load_adblock_config()
    domain = domain.lower()

    if domain in config.get('custom_blocks', []):
        config['custom_blocks'].remove(domain)
        _recompute_total_rules(config)
        _save_adblock_config(config)
        return True
    return False


def add_whitelist(domain: str) -> bool:
    """Add a domain to the whitelist (bypass all blocklists)."""
    config = _load_adblock_config()
    domain = domain.lower()

    if domain in config.get('whitelist', []):
        return False

    config['whitelist'].append(domain)
    _save_adblock_config(config)
    return True


def remove_whitelist(domain: str) -> bool:
    """Remove domain from whitelist."""
    config = _load_adblock_config()
    domain = domain.lower()

    if domain in config.get('whitelist', []):
        config['whitelist'].remove(domain)
        _save_adblock_config(config)
        return True
    return False


# ──────────────────────────── Domain Matching ──────────────────────────

def _load_all_rules() -> set[str]:
    """Load all blocklist rules from cache files."""
    rules = set()

    # Load from cache files
    if ADBLOCK_CACHE_DIR.exists():
        for cache_file in ADBLOCK_CACHE_DIR.glob("*.txt"):
            try:
                with open(cache_file, 'r') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain:
                            rules.add(domain)
            except Exception:
                continue

    # Add custom blocks
    config = _load_adblock_config()
    rules.update(d.lower() for d in config.get('custom_blocks', []))

    return rules


def check_domain_blocked(fqdn: str) -> tuple[bool, str]:
    """
    Check if domain is blocked.
    Returns: (is_blocked, matched_rule)
    """
    config = _load_adblock_config()
    fqdn_lower = fqdn.lower()

    # Check whitelist first (bypass all blocks)
    whitelist = config.get('whitelist', [])
    for wl_domain in whitelist:
        if fqdn_lower.endswith('.' + wl_domain) or fqdn_lower == wl_domain:
            return False, ""  # Whitelisted

    # Load all rules
    rules = _load_all_rules()

    # Check exact match first
    if fqdn_lower in rules:
        return True, fqdn_lower

    # Check suffix match (e.g., ads.example.com matches .ads.example.com)
    for rule in rules:
        if fqdn_lower.endswith('.' + rule) or fqdn_lower == rule:
            return True, rule

    return False, ""


def log_dns_query(domain: str, blocked: bool, response_ip: str = "0.0.0.0") -> None:
    """Log a DNS query."""
    _ensure_adblock_dirs()

    entry = {
        'ts': datetime.now(timezone.utc).timestamp(),
        'domain': domain,
        'blocked': blocked,
        'response_ip': response_ip,
    }

    try:
        with open(DNS_QUERY_LOG, 'a') as f:
            f.write(json.dumps(entry, separators=(',', ':')) + '\n')
    except Exception:
        pass

    # Update stats
    config = _load_adblock_config()
    if blocked:
        today = datetime.now(timezone.utc).date().isoformat()
        stats = config.get('stats', {})
        if stats.get('blocked_today_date') == today:
            stats['queries_blocked_today'] += 1
        else:
            stats['blocked_today_date'] = today
            stats['queries_blocked_today'] = 1
        config['stats'] = stats
        _save_adblock_config(config)


def get_adblock_stats() -> dict:
    """Get blocking statistics."""
    config = _load_adblock_config()
    stats = config.get('stats', {})

    # Count top blocked domains
    top_blocked = {}
    if DNS_QUERY_LOG.exists():
        try:
            with open(DNS_QUERY_LOG, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if entry.get('blocked'):
                            domain = entry.get('domain', 'unknown')
                            top_blocked[domain] = top_blocked.get(domain, 0) + 1
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

    # Sort by count
    top_10 = sorted(top_blocked.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        'total_rules': stats.get('total_rules', 0),
        'queries_blocked_today': stats.get('queries_blocked_today', 0),
        'top_blocked_domains': [{'domain': d, 'count': c} for d, c in top_10],
        'sources_enabled': sum(1 for s in config.get('sources', []) if s.get('enabled', True)),
        'sources_total': len(config.get('sources', [])),
    }


def get_dns_query_log(blocked_only: bool = False, hours: int = 24, limit: int = 100) -> list[dict]:
    """Get DNS query log."""
    if not DNS_QUERY_LOG.exists():
        return []

    cutoff_ts = (datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp()
    entries = []

    try:
        with open(DNS_QUERY_LOG, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if entry.get('ts', 0) >= cutoff_ts:
                        if not blocked_only or entry.get('blocked'):
                            entries.append(entry)
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass

    # Return newest first
    entries.sort(key=lambda e: e.get('ts', 0), reverse=True)
    return entries[:limit]


def get_adblock_status() -> dict:
    """Get comprehensive adblock status."""
    config = _load_adblock_config()
    return {
        'enabled': True,  # Based on settings
        'total_sources': len(config.get('sources', [])),
        'enabled_sources': sum(1 for s in config.get('sources', []) if s.get('enabled', True)),
        'total_rules': config.get('stats', {}).get('total_rules', 0),
        'custom_blocks': len(config.get('custom_blocks', [])),
        'whitelisted': len(config.get('whitelist', [])),
        'queries_blocked_today': config.get('stats', {}).get('queries_blocked_today', 0),
    }
