"""
Blackout Kit - DNS Query Interceptor & Ad Blocker Daemon.
Intercepts DNS queries and blocks requests to ad/tracker domains.
"""
import logging
import threading
from collections import deque

_log = logging.getLogger(__name__)
MAX_QUERY_BUFFER = 1_000


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
        self._query_buffer = deque()
        self._dropped_queries = 0
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the DNS interceptor thread."""
        if self.thread and self.thread.is_alive():
            return

        self._stop_event.clear()
        self.running = True
        self.thread = threading.Thread(target=self._interceptor_loop, daemon=True)
        self.thread.start()
        _log.debug("DNSInterceptor started")

    def stop(self) -> None:
        """Stop the DNS interceptor thread."""
        thread = self.thread
        self._stop_event.set()
        if thread and thread is not threading.current_thread():
            thread.join(timeout=5)
        if thread and thread.is_alive():
            _log.warning("DNSInterceptor did not stop within 5 seconds")
            return
        self.running = False
        self.thread = None
        _log.debug("DNSInterceptor stopped")

    def is_running(self) -> bool:
        """Return whether the interceptor has an active live worker thread."""
        return self.running and self.thread is not None and self.thread.is_alive()

    def _interceptor_loop(self) -> None:
        """Background loop that periodically processes queued DNS queries."""
        from ..tools.adblock import check_domain_blocked, log_dns_query

        try:
            while not self._stop_event.is_set():
                try:
                    with self._lock:
                        queries = list(self._query_buffer)
                        self._query_buffer.clear()

                    for query in queries:
                        domain = query.get('domain', '')
                        if not domain:
                            continue

                        is_blocked, matched_rule = check_domain_blocked(domain)
                        response_ip = "0.0.0.0" if is_blocked else "original"
                        log_dns_query(domain, is_blocked, response_ip)

                        if is_blocked:
                            _log.debug("DNS blocked: %s (matched: %s)", domain, matched_rule)
                except Exception as exc:
                    _log.error("DNSInterceptor error: %s", exc, exc_info=False)
                if self._stop_event.wait(0.5):
                    break
        finally:
            self.running = False

    def queue_query(self, domain: str) -> None:
        """Queue a DNS query for processing, evicting the oldest item when full."""
        with self._lock:
            if len(self._query_buffer) >= MAX_QUERY_BUFFER:
                self._query_buffer.popleft()
                self._dropped_queries += 1
                if self._dropped_queries == 1 or self._dropped_queries % 100 == 0:
                    _log.warning("DNS query buffer full; dropped %d oldest queued queries", self._dropped_queries)
            self._query_buffer.append({'domain': domain})

    def get_query_queue_size(self) -> int:
        """Get number of queued queries."""
        with self._lock:
            return len(self._query_buffer)

    def get_dropped_query_count(self) -> int:
        """Get the number of oldest queued queries evicted under buffer pressure."""
        with self._lock:
            return self._dropped_queries
