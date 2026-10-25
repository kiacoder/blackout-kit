# tests/test_tui_state.py
"""ConsoleState must bridge existing services and fail soft."""
from types import SimpleNamespace

from blackoutkit.tui.state import ConsoleState


def _fake_state() -> ConsoleState:
    caps = (
        SimpleNamespace(name="xray", state="ready", detail="ok"),
        SimpleNamespace(name="tun", state="blocked", detail="no runtime"),
        SimpleNamespace(name="tor", state="unsupported", detail="platform"),
    )
    return ConsoleState(
        snapshot_fn=lambda: {"pid": 123, "active_engine": "xray"},
        capabilities_fn=lambda *, include_local=False: caps,
        load_configs_fn=lambda: [],
        add_config_fn=lambda uri: (_ for _ in ()).throw(ValueError("bad uri")),
        import_subscription_fn=lambda url: [],
        settings_load_fn=lambda: {"xray_socks_port": 10808},
        settings_groups_fn=lambda: [("Proxy", ["xray_socks_port"])],
        settings_choices_fn=lambda key: None,
        settings_display_fn=lambda key, value: str(value),
        settings_validate_fn=lambda key, value: (False, "invalid"),
        settings_set_fn=lambda key, value: None,
    )


def test_snapshot_returns_dict():
    s = _fake_state()
    snap = s.snapshot()
    assert snap["pid"] == 123 and snap["active_engine"] == "xray"


def test_snapshot_fail_soft():
    def boom():
        raise RuntimeError("daemon dead")

    s = _fake_state()
    s.snapshot_fn = boom
    snap = s.snapshot()
    assert snap["error"] == "daemon dead"


def test_engine_rows_shape():
    rows = _fake_state().engine_rows()
    assert rows[0] == {"name": "xray", "state": "ready", "detail": "ok"}
    assert all(r["state"] in {"ready", "blocked", "unsupported", "unknown"} for r in rows)


def test_engine_rows_fail_soft():
    s = _fake_state()

    def boom(**kwargs):
        raise RuntimeError("no catalog")

    s.capabilities_fn = boom
    assert s.engine_rows() == []


def test_add_config_uri_reports_failure():
    ok, msg = _fake_state().add_config_uri("vmess://junk")
    assert ok is False and "bad uri" in msg


def test_save_setting_validates_before_write():
    s = _fake_state()
    writes = []
    s.settings_set_fn = lambda k, v: writes.append((k, v))
    ok, msg = s.save_setting("xray_socks_port", "not-a-port")
    assert ok is False and writes == []
