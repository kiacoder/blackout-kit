# blackoutkit/tui/state.py
"""Bridge between the Console UI and existing, tested Blackout Kit functions.

Every method delegates to a function that already exists in the codebase.
Callables are injectable so tests can fake the service layer without a real
daemon. All methods fail soft: UI screens must never crash on service errors.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


def _cap_field(cap: Any, name: str, default: str = "") -> str:
    value = getattr(cap, name, default)
    return default if value is None else str(value)


@dataclass
class ConsoleState:
    snapshot_fn: Callable[[], dict]
    capabilities_fn: Callable[..., tuple]
    load_configs_fn: Callable[[], list]
    add_config_fn: Callable[[str], Any]
    import_subscription_fn: Callable[[str], list]
    settings_load_fn: Callable[[], dict]
    settings_groups_fn: Callable[[], list]
    settings_choices_fn: Callable[[str], tuple | None]
    settings_display_fn: Callable[[str, Any], Any]
    settings_validate_fn: Callable[[str, Any], tuple[bool, str]]
    settings_set_fn: Callable[[str, Any], None]
    doctor_fn: Callable[[], Any] | None = None
    fix_preview_fn: Callable[[], Any] | None = None

    @classmethod
    def default(cls) -> "ConsoleState":
        from blackoutkit import capabilities as _caps
        from blackoutkit import settings as _settings
        from blackoutkit.cli import _status_snapshot
        from blackoutkit.config import (
            add_config,
            import_from_subscription,
            load_configs,
        )

        return cls(
            snapshot_fn=_status_snapshot,
            capabilities_fn=_caps.all_capabilities,
            load_configs_fn=load_configs,
            add_config_fn=add_config,
            import_subscription_fn=import_from_subscription,
            settings_load_fn=_settings.load,
            settings_groups_fn=_settings.iter_setting_groups,
            settings_choices_fn=_settings.setting_choices,
            settings_display_fn=_settings.display_value,
            settings_validate_fn=_settings.validate,
            settings_set_fn=_settings.set_value,
        )

    # -- status -----------------------------------------------------------
    def snapshot(self) -> dict:
        try:
            data = self.snapshot_fn()
            return data if isinstance(data, dict) else {"error": "unexpected status shape"}
        except Exception as exc:
            return {"error": str(exc)}

    # -- engines ----------------------------------------------------------
    def engine_rows(self) -> list[dict]:
        try:
            caps = self.capabilities_fn(include_local=True)
        except Exception:
            return []
        rows = []
        for cap in caps or ():
            rows.append(
                {
                    "name": _cap_field(cap, "name", "?"),
                    "state": _cap_field(cap, "state", "unknown").lower(),
                    "detail": _cap_field(cap, "detail") or _cap_field(cap, "reason"),
                }
            )
        return rows

    # -- configs ----------------------------------------------------------
    def config_summaries(self) -> list[str]:
        try:
            configs = self.load_configs_fn() or []
        except Exception:
            return []
        lines = []
        for index, cfg in enumerate(configs, start=1):
            protocol = _cap_field(cfg, "protocol", "?")
            address = _cap_field(cfg, "address", "?")
            port = _cap_field(cfg, "port", "?")
            name = _cap_field(cfg, "name") or "(unnamed)"
            lines.append(f"{index}. [{protocol}] {name} — {address}:{port}")
        return lines

    def add_config_uri(self, uri: str) -> tuple[bool, str]:
        try:
            self.add_config_fn(uri)
            return True, "Config added."
        except Exception as exc:
            return False, str(exc)

    def import_subscription(self, url: str) -> tuple[int, str]:
        try:
            found = self.import_subscription_fn(url) or []
            return len(found), f"Imported {len(found)} configs."
        except Exception as exc:
            return 0, str(exc)

    # -- settings ---------------------------------------------------------
    def setting_groups(self) -> list[tuple[str, list[str]]]:
        try:
            return self.settings_groups_fn() or []
        except Exception:
            return []

    def setting_detail(self, key: str) -> str:
        try:
            value = self.settings_load_fn().get(key)
            return f"{key} = {self.settings_display_fn(key, value)}"
        except Exception as exc:
            return f"{key} = <error: {exc}>"

    def setting_choices(self, key: str) -> tuple[str, ...] | None:
        try:
            return self.settings_choices_fn(key)
        except Exception:
            return None

    def validate_setting(self, key: str, value: Any) -> tuple[bool, str]:
        try:
            return self.settings_validate_fn(key, value)
        except Exception as exc:
            return False, str(exc)

    def save_setting(self, key: str, value: Any) -> tuple[bool, str]:
        ok, reason = self.validate_setting(key, value)
        if not ok:
            return False, reason or f"Invalid value for {key}"
        try:
            self.settings_set_fn(key, value)
            return True, f"Saved {key}."
        except Exception as exc:
            return False, str(exc)
