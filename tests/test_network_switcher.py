"""Tests for best-effort ISP detection over HTTPS."""
import json
import urllib.error
from unittest.mock import patch

import pytest

from blackoutkit import network_switcher


def _response(payload):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(payload).encode("utf-8")

    return FakeResponse()


def _http_error(url, status):
    return urllib.error.HTTPError(url, status, "HTTP error", {}, None)


def _request_urls(urlopen):
    return [args[0][0].full_url for args in urlopen.call_args_list]


def test_get_isp_info_uses_https_ipapi_primary_and_parses_provider_fields():
    with patch("blackoutkit.network_switcher.urllib.request.urlopen") as urlopen:
        urlopen.return_value = _response({
            "asn": "AS44244",
            "org": "MTN Irancell",
            "city": "Tehran",
            "country_name": "Iran",
            "country_code": "IR",
        })

        result = network_switcher.get_isp_info(timeout=4.25)

    assert result == network_switcher.IspInfo(
        isp="MTN Irancell",
        isp_short="Irancell (MTN)",
        asn="AS44244",
        city="Tehran",
        country="Iran",
        country_code="IR",
    )
    assert _request_urls(urlopen) == ["https://ipapi.co/json/"]
    assert urlopen.call_args.kwargs == {"timeout": 4.25}


@pytest.mark.parametrize("status", [429, 503])
def test_get_isp_info_falls_back_to_ipinfo_after_primary_http_error(status):
    with patch("blackoutkit.network_switcher.urllib.request.urlopen") as urlopen:
        urlopen.side_effect = [
            _http_error("https://ipapi.co/json/", status),
            _response({
                "org": "AS44244 MTN Irancell",
                "city": "Tehran",
                "country": "IR",
            }),
        ]

        result = network_switcher.get_isp_info(timeout=3.5)

    assert result == network_switcher.IspInfo(
        isp="MTN Irancell",
        isp_short="Irancell (MTN)",
        asn="AS44244",
        city="Tehran",
        country="IR",
        country_code="IR",
    )
    assert _request_urls(urlopen) == [
        "https://ipapi.co/json/",
        "https://ipinfo.io/json",
    ]
    assert [entry.kwargs["timeout"] for entry in urlopen.call_args_list] == [3.5, 3.5]


def test_get_isp_info_falls_back_after_invalid_primary_json():
    class InvalidJsonResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b"not-json"

    with patch("blackoutkit.network_switcher.urllib.request.urlopen") as urlopen:
        urlopen.side_effect = [
            InvalidJsonResponse(),
            _response({"org": "AS197207 MCI", "city": "Tehran", "country": "IR"}),
        ]

        result = network_switcher.get_isp_info()

    assert result == network_switcher.IspInfo(
        isp="MCI",
        isp_short="Mokhaberat (MCI)",
        asn="AS197207",
        city="Tehran",
        country="IR",
        country_code="IR",
    )
    assert _request_urls(urlopen) == [
        "https://ipapi.co/json/",
        "https://ipinfo.io/json",
    ]


def test_get_isp_info_falls_back_when_primary_json_has_invalid_schema():
    with patch("blackoutkit.network_switcher.urllib.request.urlopen") as urlopen:
        urlopen.side_effect = [
            _response({"asn": 44244, "org": "MTN Irancell"}),
            _response({"org": "AS197207 MCI", "city": "Tehran", "country": "IR"}),
        ]

        result = network_switcher.get_isp_info()

    assert result == network_switcher.IspInfo(
        isp="MCI",
        isp_short="Mokhaberat (MCI)",
        asn="AS197207",
        city="Tehran",
        country="IR",
        country_code="IR",
    )
    assert _request_urls(urlopen) == [
        "https://ipapi.co/json/",
        "https://ipinfo.io/json",
    ]


def test_get_isp_info_returns_none_when_both_providers_fail():
    with patch("blackoutkit.network_switcher.urllib.request.urlopen") as urlopen:
        urlopen.side_effect = [
            urllib.error.URLError("offline"),
            _http_error("https://ipinfo.io/json", 429),
        ]

        result = network_switcher.get_isp_info()

    assert result is None
    assert _request_urls(urlopen) == [
        "https://ipapi.co/json/",
        "https://ipinfo.io/json",
    ]


@pytest.mark.parametrize(
    "url",
    [
        "http://ipapi.co/json/",
        "http://ipinfo.io/json",
        "https://ip-api.com/json",
    ],
)
def test_lookup_url_rejects_non_https_or_unlisted_hosts(url):
    with pytest.raises(ValueError, match="unexpected ISP lookup endpoint"):
        network_switcher._validated_lookup_url(url)
