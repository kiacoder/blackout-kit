import io
from unittest.mock import Mock, patch

import pytest

from blackoutkit.config import manager


class FakeResponse:
    def __init__(self, body: bytes, content_length=None):
        self._body = body
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit=-1):
        return self._body if limit < 0 else self._body[:limit]


class FakeOpener:
    def __init__(self, response):
        self.response = response

    def open(self, *_args, **_kwargs):
        return self.response


class FakeContextOpener:
    def __init__(self, response):
        self.response = response

    def open(self, *_args, **_kwargs):
        return self.response

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_subscription_requires_https():
    with pytest.raises(manager.SubscriptionError, match="HTTPS"):
        manager.import_from_subscription("http://example.com/sub")


def test_subscription_rejects_embedded_credentials():
    with pytest.raises(manager.SubscriptionError, match="credentials"):
        manager.import_from_subscription("https://user:pass@example.com/sub")


def test_subscription_rejects_local_hosts():
    for host in ("localhost", "127.0.0.1", "192.168.1.2", "service.local"):
        with pytest.raises(manager.SubscriptionError, match="not allowed"):
            manager.import_from_subscription(f"https://{host}/sub")


def test_subscription_rejects_oversized_content_length():
    opener = Mock()
    opener.open.return_value = FakeResponse(b"", manager.SUBSCRIPTION_MAX_BYTES + 1)
    with patch("blackoutkit.config.manager.urllib.request.build_opener", return_value=opener):
        with pytest.raises(manager.SubscriptionError, match="size limit"):
            manager.import_from_subscription("https://example.com/sub")


def test_subscription_rejects_oversized_body():
    body = b"x" * (manager.SUBSCRIPTION_MAX_BYTES + 1)
    opener = Mock()
    opener.open.return_value = FakeResponse(body)
    with patch("blackoutkit.config.manager.urllib.request.build_opener", return_value=opener):
        with pytest.raises(manager.SubscriptionError, match="size limit"):
            manager.import_from_subscription("https://example.com/sub")


def test_subscription_redirect_handler_revalidates_destination():
    handler = manager._ValidatedRedirectHandler()
    request = Mock()
    response = Mock()
    with pytest.raises(Exception, match="not allowed"):
        handler.redirect_request(request, response, 302, "Found", {}, "https://localhost/sub")


def test_subscription_fetch_failure_is_explicit():
    opener = Mock()
    opener.open.side_effect = OSError("offline")
    with patch("blackoutkit.config.manager.urllib.request.build_opener", return_value=opener):
        with pytest.raises(manager.SubscriptionError, match="could not be fetched"):
            manager.import_from_subscription("https://example.com/sub")


def test_import_and_merge_does_not_write_when_fetch_fails(monkeypatch):
    save = Mock()
    monkeypatch.setattr(manager, "save_configs", save)
    monkeypatch.setattr(manager, "import_from_subscription", Mock(side_effect=manager.SubscriptionError("offline")))

    with pytest.raises(manager.SubscriptionError):
        manager.import_and_merge("https://example.com/sub")

    save.assert_not_called()
