"""
Blackout Kit - DNS Query Interceptor & Ad Blocker Daemon.
Intercepts DNS queries and blocks requests to ad/tracker domains.
"""
import logging
import threading
import time
from typing import Optional

_log = logging.getLogger(__name__)


class DNSInterceptor:
    """
    Background thread that monitors and intercepts DNS queries.
    Call start() to spawn thread, stop() to terminate.

    MVP implementation: Integrates with system proxy DNS resolution
    checking against blocklists and logging queries.
    """

    def __init__(self):
        self.running = False
        self.thread = None
        self._query_buffer = []
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the DNS interceptor thread."""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._interceptor_loop, daemon=True)
        self.thread.start()
        _log.debug("DNSInterceptor started")

    def stop(self) -> None:
        """Stop the DNS interceptor thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        _log.debug("DNSInterceptor stopped")

    def _interceptor_loop(self) -> None:
        """Background loop that periodically processes queued DNS queries."""
        from ..tools.adblock import check_domain_blocked, log_dns_query

        while self.running:
            try:
                # Process query buffer
                with self._lock:
                    if self._query_buffer:
                        queries = self._query_buffer[:]
                        self._query_buffer.clear()
                    else:
                        queries = []

                for query in queries:
                    domain = query.get('domain', '')
                    if not domain:
                        continue

                    # Check if blocked
                    is_blocked, matched_rule = check_domain_blocked(domain)

                    # Log the query
                    response_ip = "0.0.0.0" if is_blocked else "original"
                    log_dns_query(domain, is_blocked, response_ip)

                    if is_blocked:
                        _log.debug(f"DNS blocked: {domain} (matched: {matched_rule})")

                time.sleep(0.5)
            except Exception as e:
                _log.error(f"DNSInterceptor error: {e}", exc_info=False)
                time.sleep(0.5)

    def queue_query(self, domain: str) -> None:
        """Queue a DNS query for processing."""
        with self._lock:
            self._query_buffer.append({'domain': domain})

    def get_query_queue_size(self) -> int:
        """Get number of queued queries."""
        with self._lock:
            return len(self._query_buffer)
