"""Webhook registry and delivery (Roadmap Phase 8 — REST API v2).

Register HTTP endpoints that Blackout POSTs events to. Each delivery is
optional-HMAC-signed (``X-Blackout-Signature: sha256=<hex>`` over the exact
request body), so a receiver can verify the payload came from this process.

Network egress happens only in :func:`deliver` and only to URLs the operator
explicitly registered.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import tempfile
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

_log = logging.getLogger(__name__)

DEFAULT_WEBHOOK_FILE = Path.home() / ".blackout-kit" / "webhooks.json"
_MASKED_SECRET = "***"

__all__ = [
    "Webhook",
    "WebhookRegistry",
    "deliver",
    "sign_payload",
    "make_webhook_observer",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Webhook:
    """A registered delivery target."""

    url: str
    event_prefixes: tuple[str, ...] = ()
    enabled: bool = True
    secret: Optional[str] = None
    created_at: str = ""

    def matches(self, event_type: str) -> bool:
        """Whether this webhook wants ``event_type`` (empty prefixes = all)."""
        if not self.enabled:
            return False
        if not self.event_prefixes:
            return True
        return any(str(event_type).startswith(p) for p in self.event_prefixes)

    def to_dict(self, *, reveal_secret: bool = False) -> dict[str, Any]:
        data = asdict(self)
        data["event_prefixes"] = list(self.event_prefixes)
        if not reveal_secret and self.secret:
            data["secret"] = _MASKED_SECRET
        return data


def sign_payload(secret: str, body: bytes) -> str:
    """Return the ``sha256=<hex>`` HMAC signature for a request body."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


class WebhookRegistry:
    """Persisted set of webhooks (one per URL)."""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path or os.environ.get("BLACKOUT_WEBHOOK_FILE") or DEFAULT_WEBHOOK_FILE)
        self._hooks: dict[str, Webhook] = {}
        self._load()

    # ── persistence ─────────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        items = raw.get("webhooks", raw) if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict) or not item.get("url"):
                continue
            hook = Webhook(
                url=str(item["url"]),
                event_prefixes=tuple(str(p) for p in item.get("event_prefixes", []) if p),
                enabled=bool(item.get("enabled", True)),
                secret=(str(item["secret"]) if item.get("secret") else None),
                created_at=str(item.get("created_at") or _now()),
            )
            self._hooks[hook.url] = hook

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"webhooks": [h.to_dict(reveal_secret=True) for h in self._hooks.values()]}
        descriptor, temporary = tempfile.mkstemp(prefix=".webhooks-", suffix=".json", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
            os.replace(temporary, self.path)
        except OSError:
            try:
                os.unlink(temporary)
            except OSError:
                pass

    # ── mutation ────────────────────────────────────────────────────────────

    def add(self, webhook: Webhook) -> bool:
        """Add or replace a webhook by URL. Returns ``False`` for a blank URL."""
        if not webhook.url:
            return False
        if not webhook.created_at:
            webhook = Webhook(
                url=webhook.url,
                event_prefixes=tuple(webhook.event_prefixes),
                enabled=webhook.enabled,
                secret=webhook.secret,
                created_at=_now(),
            )
        self._hooks[webhook.url] = webhook
        self._save()
        return True

    def remove(self, url: str) -> bool:
        if url in self._hooks:
            del self._hooks[url]
            self._save()
            return True
        return False

    # ── read ────────────────────────────────────────────────────────────────

    def list(self) -> list[Webhook]:
        return list(self._hooks.values())

    def matching(self, event_type: str) -> list[Webhook]:
        return [h for h in self._hooks.values() if h.matches(event_type)]


def deliver(
    event: dict[str, Any],
    webhooks: list[Webhook],
    *,
    poster: Optional[Callable[[str, bytes, dict[str, str]], int]] = None,
) -> list[dict[str, Any]]:
    """POST ``event`` to each webhook. Returns one result dict per delivery.

    ``poster`` is injectable for tests: ``(url, body, headers) -> status_code``.
    """
    body = json.dumps(event, separators=(",", ":")).encode("utf-8")
    send = poster or _post
    results: list[dict[str, Any]] = []
    for hook in webhooks:
        headers = {"Content-Type": "application/json", "User-Agent": "blackout-kit"}
        if hook.secret:
            headers["X-Blackout-Signature"] = sign_payload(hook.secret, body)
        try:
            status = int(send(hook.url, body, headers))
        except Exception as exc:
            _log.warning("Webhook delivery to %s failed: %s", hook.url, exc)
            results.append({"url": hook.url, "ok": False, "error": type(exc).__name__})
            continue
        results.append({"url": hook.url, "ok": 200 <= status < 300, "status": status})
    return results


def _post(url: str, body: bytes, headers: dict[str, str]) -> int:
    try:
        import httpx
    except Exception as exc:  # pragma: no cover - httpx is a hard dependency
        raise RuntimeError(f"httpx unavailable: {exc}") from exc
    response = httpx.post(url, content=body, headers=headers, timeout=10.0, follow_redirects=False)
    return int(response.status_code)


def make_webhook_observer(registry: "WebhookRegistry") -> Callable[[Any], None]:
    """Return an event-bus observer that POSTs matching events to the webhooks.

    The bus dispatches observers synchronously on the publisher's thread, so
    delivery is handed to a daemon thread: a slow or unreachable webhook must
    never stall engine or recovery code. A webhook that raises is swallowed by
    the bus's own observer isolation.
    """

    def observer(event: Any) -> None:
        try:
            event_type = getattr(event, "type", None) or (event.get("type") if isinstance(event, dict) else None)
            if not event_type:
                return
            hooks = registry.matching(str(event_type))
            if not hooks:
                return
            payload = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        except Exception:  # never let observer bookkeeping break publishing
            return
        threading.Thread(
            target=deliver,
            args=(payload, hooks),
            daemon=True,
            name="blackout-webhook",
        ).start()

    return observer
