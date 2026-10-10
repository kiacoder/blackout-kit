"""Regression tests for configurable HTTPS DoH bootstrap resolvers."""
import json
import urllib.error
import urllib.request
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

from blackoutkit import tools


_DEFAULT_RESOLVERS = (
    "https://1.1.1.1/dns-query",
    "https://9.9.9.9/dns-query",
    "https://8.8.8.8/dns-query",
)


class _TestOpener:
    def __init__(self, open_request):
        self.open_request = open_request

    def open(self, request, timeout=None):
        return self.open_request(request, timeout)


def _patch_doh_opener(open_request):
    return patch(
        "blackoutkit.tools.urllib.request.build_opener",
        return_value=_TestOpener(open_request),
    )


class _DoHResponse:
    def __init__(self, body, status=200):
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        self.status = status

    def read(self):
        return self._body

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def _answer(address, record_type=1):
    return {"name": "example.com.", "type": record_type, "TTL": 60, "data": address}


def test_resolve_doh_url_encodes_name_and_returns_only_ipv4_a_answer(monkeypatch):
    monkeypatch.delenv("BLACKOUT_DOH_RESOLVER", raising=False)
    requested = []
    payload = {
        "Status": 0,
        "Answer": [
            _answer("2001:db8::1"),
            _answer("203.0.113.7", record_type=28),
            _answer("203.0.113.8"),
        ],
    }

    def fake_urlopen(request, timeout):
        requested.append((request, timeout))
        return _DoHResponse(payload)

    with _patch_doh_opener(fake_urlopen):
        result = tools.resolve_doh("example.com/path?x=1 &y=2", timeout=2.5)

    assert result == "203.0.113.8"
    assert len(requested) == 1
    request, timeout = requested[0]
    parsed = urlsplit(request.full_url)
    assert parsed.scheme == "https"
    assert parsed.netloc == "1.1.1.1"
    assert parse_qs(parsed.query) == {
        "name": ["example.com/path?x=1 &y=2"],
        "type": ["A"],
    }
    assert request.get_header("Accept") == "application/dns-json"
    assert timeout == 2.5


def test_resolve_doh_uses_configured_allowed_endpoint_alone(monkeypatch):
    configured = "https://9.9.9.9/dns-query"
    monkeypatch.setenv("BLACKOUT_DOH_RESOLVER", configured)
    requested = []

    def fake_urlopen(request, timeout):
        requested.append(request.full_url)
        return _DoHResponse({"Status": 0, "Answer": [_answer("198.51.100.4")]})

    with _patch_doh_opener(fake_urlopen):
        result = tools.resolve_doh("example.com")

    assert result == "198.51.100.4"
    assert requested == [f"{configured}?name=example.com&type=A"]


def test_resolve_doh_rejects_configured_query_and_uses_default_resolvers(monkeypatch):
    monkeypatch.setenv(
        "BLACKOUT_DOH_RESOLVER",
        "https://9.9.9.9/dns-query?name=other.example&type=A",
    )
    requested = []

    def fake_urlopen(request, timeout):
        requested.append(request.full_url)
        if len(requested) == 1:
            raise OSError("try next default resolver")
        return _DoHResponse({"Status": 0, "Answer": [_answer("198.51.100.9")]})

    with _patch_doh_opener(fake_urlopen):
        result = tools.resolve_doh("requested.example")

    assert result == "198.51.100.9"
    assert [urlsplit(url).netloc for url in requested] == ["1.1.1.1", "9.9.9.9"]
    assert [parse_qs(urlsplit(url).query) for url in requested] == [
        {"name": ["requested.example"], "type": ["A"]},
        {"name": ["requested.example"], "type": ["A"]},
    ]


@pytest.mark.parametrize(
    "configured",
    [
        "https://9.9.9.9/dns-query?",
        "https://9.9.9.9/dns-query#",
    ],
    ids=["empty-query", "empty-fragment"],
)
def test_resolve_doh_rejects_existing_empty_query_or_fragment(monkeypatch, configured):
    monkeypatch.setenv("BLACKOUT_DOH_RESOLVER", configured)
    requested = []

    def fake_urlopen(request, timeout):
        requested.append(request.full_url)
        return _DoHResponse({"Status": 0, "Answer": [_answer("198.51.100.5")]})

    with _patch_doh_opener(fake_urlopen):
        result = tools.resolve_doh("example.com")

    assert result == "198.51.100.5"
    assert requested == [f"{_DEFAULT_RESOLVERS[0]}?name=example.com&type=A"]


def test_resolve_doh_ignores_invalid_configured_endpoint(monkeypatch):
    monkeypatch.setenv("BLACKOUT_DOH_RESOLVER", "https://resolver.example/dns-query")
    requested = []

    def fake_urlopen(request, timeout):
        requested.append(request.full_url)
        return _DoHResponse({"Status": 0, "Answer": [_answer("198.51.100.5")]})

    with _patch_doh_opener(fake_urlopen):
        result = tools.resolve_doh("example.com")

    assert result == "198.51.100.5"
    assert requested == [f"{_DEFAULT_RESOLVERS[0]}?name=example.com&type=A"]


def test_resolve_doh_falls_back_in_order_after_network_and_dns_status_errors(monkeypatch):
    monkeypatch.delenv("BLACKOUT_DOH_RESOLVER", raising=False)
    requested = []
    responses = [
        OSError("network unavailable"),
        _DoHResponse({"Status": 2, "Answer": [_answer("198.51.100.6")]}),
        _DoHResponse({"Status": 0, "Answer": [_answer("198.51.100.7")]}),
    ]

    def fake_urlopen(request, timeout):
        requested.append((request.full_url, timeout))
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    with _patch_doh_opener(fake_urlopen):
        result = tools.resolve_doh("example.com", timeout=1.25)

    assert result == "198.51.100.7"
    assert [urlsplit(url).netloc for url, _timeout in requested] == ["1.1.1.1", "9.9.9.9", "8.8.8.8"]
    assert [timeout for _url, timeout in requested] == [1.25, 1.25, 1.25]


@pytest.mark.parametrize(
    "redirect_url",
    [
        "https://untrusted.example/dns-query?name=redirected&type=A",
        "http://9.9.9.9/dns-query?name=redirected&type=A",
    ],
    ids=["off-host-https", "http-downgrade"],
)
def test_resolve_doh_refuses_redirects_and_falls_back_to_next_resolver(
    monkeypatch, redirect_url
):
    monkeypatch.delenv("BLACKOUT_DOH_RESOLVER", raising=False)
    requested = []
    response_count = 0

    class FakeOpener:
        def __init__(self, handlers):
            self.redirect_handler = next(
                handler for handler in handlers
                if isinstance(handler, urllib.request.HTTPRedirectHandler)
            )

        def open(self, request, timeout=None):
            nonlocal response_count
            assert timeout == 3.0
            requested.append(request.full_url)
            response_count += 1
            if response_count == 1:
                with pytest.raises(urllib.error.HTTPError):
                    self.redirect_handler.redirect_request(
                        request,
                        None,
                        302,
                        "redirect",
                        {"Location": redirect_url},
                        redirect_url,
                    )
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "redirect",
                    {"Location": redirect_url},
                    None,
                )
            return _DoHResponse({"Status": 0, "Answer": [_answer("198.51.100.10")]})

    with (
        patch(
            "blackoutkit.tools.urllib.request.build_opener",
            side_effect=lambda *handlers: FakeOpener(handlers),
        ),
        patch(
            "blackoutkit.tools.urllib.request.urlopen",
            side_effect=AssertionError("DoH must use the configured opener"),
        ),
    ):
        result = tools.resolve_doh("requested.example", timeout=3.0)

    assert result == "198.51.100.10"
    assert [urlsplit(url).netloc for url in requested] == ["1.1.1.1", "9.9.9.9"]
    assert redirect_url not in requested
    assert response_count == 2


def test_resolve_doh_retries_http_json_and_no_a_failures_then_returns_none(monkeypatch):
    monkeypatch.delenv("BLACKOUT_DOH_RESOLVER", raising=False)
    requested = []
    responses = [
        urllib.error.HTTPError(_DEFAULT_RESOLVERS[0], 503, "unavailable", {}, None),
        _DoHResponse(b"not json"),
        _DoHResponse({"Status": 0, "Answer": [_answer("2001:db8::1")]}),
    ]

    def fake_urlopen(request, timeout):
        requested.append(request.full_url)
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    with _patch_doh_opener(fake_urlopen):
        result = tools.resolve_doh("example.com")

    assert result is None
    assert [urlsplit(url).netloc for url in requested] == ["1.1.1.1", "9.9.9.9", "8.8.8.8"]


def test_resolve_doh_returns_ipv4_literal_without_network(monkeypatch):
    monkeypatch.setenv("BLACKOUT_DOH_RESOLVER", "http://untrusted.example/dns-query")

    with patch("blackoutkit.tools.urllib.request.urlopen") as urlopen:
        assert tools.resolve_doh("192.0.2.9") == "192.0.2.9"

    urlopen.assert_not_called()
