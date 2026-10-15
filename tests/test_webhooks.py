"""Phase 8 — webhooks (blackoutkit.webhooks)."""
from __future__ import annotations

import hashlib
import hmac
import json

from blackoutkit.webhooks import Webhook, WebhookRegistry, deliver, sign_payload


# ── signing ──────────────────────────────────────────────────────────────────

def test_sign_payload_matches_hmac():
    body = b'{"a":1}'
    expected = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert sign_payload("secret", body) == expected


# ── matching ─────────────────────────────────────────────────────────────────

def test_webhook_matches_prefixes():
    assert Webhook(url="u").matches("engine.started") is True          # no prefixes = all
    assert Webhook(url="u", event_prefixes=("engine",)).matches("engine.started") is True
    assert Webhook(url="u", event_prefixes=("engine",)).matches("config.saved") is False
    assert Webhook(url="u", event_prefixes=("a",), enabled=False).matches("a.x") is False


# ── registry ─────────────────────────────────────────────────────────────────

def test_registry_add_list_remove(tmp_path):
    reg = WebhookRegistry(tmp_path / "wh.json")
    assert reg.add(Webhook(url="https://a.test")) is True
    assert reg.add(Webhook(url="https://a.test")) is True  # replace by url
    assert reg.add(Webhook(url="")) is False
    assert [h.url for h in reg.list()] == ["https://a.test"]
    assert reg.remove("https://a.test") is True
    assert reg.remove("https://a.test") is False


def test_registry_persists_and_roundtrips(tmp_path):
    path = tmp_path / "wh.json"
    reg = WebhookRegistry(path)
    reg.add(Webhook(url="https://a.test", event_prefixes=("engine",), secret="s3cr3t"))

    reloaded = WebhookRegistry(path)
    hook = reloaded.list()[0]
    assert hook.url == "https://a.test"
    assert hook.event_prefixes == ("engine",)
    assert hook.secret == "s3cr3t"  # secret persisted (needed to sign deliveries)


def test_to_dict_masks_secret():
    hook = Webhook(url="u", secret="s3cr3t")
    assert hook.to_dict()["secret"] == "***"
    assert hook.to_dict(reveal_secret=True)["secret"] == "s3cr3t"


def test_registry_matching(tmp_path):
    reg = WebhookRegistry(tmp_path / "wh.json")
    reg.add(Webhook(url="all"))
    reg.add(Webhook(url="engine-only", event_prefixes=("engine",)))
    urls = {h.url for h in reg.matching("engine.started")}
    assert urls == {"all", "engine-only"}
    assert {h.url for h in reg.matching("config.saved")} == {"all"}


# ── delivery ─────────────────────────────────────────────────────────────────

def test_deliver_posts_signed_payload():
    captured = {}

    def poster(url, body, headers):
        captured["url"] = url
        captured["body"] = body
        captured["headers"] = headers
        return 204

    hook = Webhook(url="https://a.test", secret="k")
    results = deliver({"type": "engine.started"}, [hook], poster=poster)

    assert results == [{"url": "https://a.test", "ok": True, "status": 204}]
    assert json.loads(captured["body"]) == {"type": "engine.started"}
    assert captured["headers"]["X-Blackout-Signature"] == sign_payload("k", captured["body"])


def test_deliver_without_secret_has_no_signature():
    def poster(url, body, headers):
        assert "X-Blackout-Signature" not in headers
        return 200

    deliver({"type": "x"}, [Webhook(url="u")], poster=poster)


def test_deliver_reports_failures():
    def poster(url, body, headers):
        raise ConnectionError("refused")

    results = deliver({"type": "x"}, [Webhook(url="https://down.test")], poster=poster)
    assert results[0]["ok"] is False
    assert results[0]["error"] == "ConnectionError"


def test_deliver_marks_non_2xx_as_not_ok():
    results = deliver({"type": "x"}, [Webhook(url="u")], poster=lambda *a: 500)
    assert results[0] == {"url": "u", "ok": False, "status": 500}
