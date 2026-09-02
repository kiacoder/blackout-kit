from __future__ import annotations

import json
import os
import re
import secrets
import sys
import tempfile
import time
from pathlib import Path

from .. import APP_DATA_DIR
from .. import settings as cfg
from .. import tools as net_tools

MAC_STATE_FILE = APP_DATA_DIR / "mac_privacy_state.json"
MAC_STATE_VERSION = 1
_CLASS_GUID = "{4d36e972-e325-11ce-bfc1-08002be10318}"
_MAC_RE = re.compile(r"^[0-9A-F]{12}$")
_GUID_RE = re.compile(r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
_WIFI_MEDIUM_VALUES = frozenset({1, 9})
_WIFI_MEDIUM_NAMES = frozenset({"wirelesslan", "native80211", "80211", "wifi", "wlan"})
_VIRTUAL_IDENTITY_MARKERS = (
    "blackoutkit-tun",
    "loopback",
    "virtual",
    "hyper-v",
    "vmware",
    "vbox",
    "wintun",
    "tap-windows",
)

_DISCOVER_SCRIPT = rf"""
$ErrorActionPreference = 'Stop'
$classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{_CLASS_GUID}'
$cimAdapters = @(Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop)
$registryByGuid = @{{}}
Get-ChildItem -Path $classKey -ErrorAction Stop | ForEach-Object {{
    $entry = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
    $entryGuid = [string]$entry.NetCfgInstanceId
    if (-not [string]::IsNullOrWhiteSpace($entryGuid)) {{
        $normalizedGuid = $entryGuid.Replace('{{', '').Replace('}}', '').ToUpperInvariant()
        $networkAddressProperty = $entry.PSObject.Properties['NetworkAddress']
        $registryByGuid[$normalizedGuid] = [PSCustomObject]@{{
            Present = ($null -ne $networkAddressProperty)
            Value = if ($null -ne $networkAddressProperty) {{ [string]$networkAddressProperty.Value }} else {{ $null }}
        }}
    }}
}}
$records = foreach ($adapter in @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)) {{
    $guid = ([string]$adapter.InterfaceGuid).Replace('{{', '').Replace('}}', '').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($guid)) {{ continue }}
    $native = $cimAdapters | Where-Object {{ ([string]$_.GUID).Replace('{{', '').Replace('}}', '').ToUpperInvariant() -eq $guid }} | Select-Object -First 1
    $mediumValue = $null
    if ($null -ne $adapter.NdisPhysicalMedium) {{
        try {{ $mediumValue = [int]$adapter.NdisPhysicalMedium }} catch {{}}
    }}
    $registry = $registryByGuid[$guid]
    [PSCustomObject]@{{
        Name = [string]$adapter.Name
        InterfaceAlias = [string]$adapter.InterfaceAlias
        InterfaceGuid = $guid
        InterfaceIndex = [int]$adapter.ifIndex
        Status = [string]$adapter.Status
        HardwareInterface = [bool]$adapter.HardwareInterface
        NdisPhysicalMedium = [string]$adapter.NdisPhysicalMedium
        NdisPhysicalMediumValue = $mediumValue
        EffectiveMac = [string]$adapter.MacAddress
        PhysicalAdapter = if ($null -ne $native) {{ [bool]$native.PhysicalAdapter }} else {{ $false }}
        NetConnectionStatus = if ($null -ne $native) {{ $native.NetConnectionStatus }} else {{ $null }}
        PnpDeviceId = if ($null -ne $native) {{ [string]$native.PNPDeviceID }} else {{ '' }}
        RegistryMapped = ($null -ne $registry)
        NetworkAddressPresent = if ($null -ne $registry) {{ [bool]$registry.Present }} else {{ $false }}
        NetworkAddress = if ($null -ne $registry -and $registry.Present) {{ $registry.Value }} else {{ $null }}
    }}
}}
@($records) | ConvertTo-Json -Compress
"""


def _result(status: str, **details) -> dict:
    return {"status": status, **details}


def _normalized_guid(value: object) -> str:
    normalized = str(value or "").strip().strip("{}").upper()
    return normalized if _GUID_RE.fullmatch(normalized) else ""


def _normalized_pnp(value: object) -> str:
    return str(value or "").strip().upper()


def normalize_mac(value: object) -> str:
    compact = str(value or "").replace(":", "").replace("-", "").strip().upper()
    if not _MAC_RE.fullmatch(compact):
        raise ValueError("MAC address must contain exactly 12 hexadecimal digits.")
    return compact


def format_mac(value: object) -> str:
    compact = normalize_mac(value)
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def validate_private_mac(value: object) -> str:
    compact = normalize_mac(value)
    if (int(compact[:2], 16) & 0x03) != 0x02:
        raise ValueError("MAC address must be locally administered and unicast.")
    return compact


def validate_randomization_prefix(value: object) -> str:
    prefix = str(value or "").strip().upper()
    if not re.fullmatch(r"[0-9A-F]{2}", prefix):
        raise ValueError("MAC prefix must be one hexadecimal octet, such as 02.")
    if (int(prefix, 16) & 0x03) != 0x02:
        raise ValueError("MAC prefix must be locally administered and unicast.")
    return prefix


def generate_private_mac(prefix: object = "02") -> str:
    return validate_randomization_prefix(prefix) + secrets.token_bytes(5).hex().upper()


def _generate_private_mac_different_from(prefix: object, current_mac: object) -> str:
    try:
        current = normalize_mac(current_mac)
    except ValueError:
        current = ""
    for _ in range(16):
        candidate = generate_private_mac(prefix)
        if candidate != current:
            return candidate
    raise ValueError("Could not generate a new MAC address distinct from the current adapter MAC.")


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _as_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalized_medium(value: object) -> str:
    return "".join(character for character in str(value or "").lower() if character.isalnum())


def _is_wifi_medium(adapter: dict) -> bool:
    medium_value = _as_int(adapter.get("ndis_physical_medium_value"))
    if medium_value in _WIFI_MEDIUM_VALUES:
        return True
    return _normalized_medium(adapter.get("ndis_physical_medium")) in _WIFI_MEDIUM_NAMES


def _is_virtual_identity(adapter: dict) -> bool:
    identity = " ".join(
        str(adapter.get(key, ""))
        for key in ("name", "interface_alias", "pnp_device_id")
    ).lower()
    return any(marker in identity for marker in _VIRTUAL_IDENTITY_MARKERS)


def _normalize_adapter(raw: dict) -> dict | None:
    interface_guid = _normalized_guid(raw.get("InterfaceGuid"))
    pnp_device_id = _normalized_pnp(raw.get("PnpDeviceId"))
    name = str(raw.get("Name") or "").strip()
    if not interface_guid or not pnp_device_id or not name:
        return None
    effective_mac = str(raw.get("EffectiveMac") or "").strip()
    try:
        effective_mac = normalize_mac(effective_mac)
    except ValueError:
        effective_mac = ""
    return {
        "name": name,
        "interface_alias": str(raw.get("InterfaceAlias") or "").strip(),
        "interface_guid": interface_guid,
        "interface_index": _as_int(raw.get("InterfaceIndex")),
        "status": str(raw.get("Status") or "").strip().lower(),
        "hardware_interface": _as_bool(raw.get("HardwareInterface")),
        "physical_adapter": _as_bool(raw.get("PhysicalAdapter")),
        "net_connection_status": _as_int(raw.get("NetConnectionStatus")),
        "ndis_physical_medium": str(raw.get("NdisPhysicalMedium") or "").strip(),
        "ndis_physical_medium_value": _as_int(raw.get("NdisPhysicalMediumValue")),
        "pnp_device_id": pnp_device_id,
        "effective_mac": effective_mac,
        "registry_mapped": _as_bool(raw.get("RegistryMapped")),
        "network_address_present": _as_bool(raw.get("NetworkAddressPresent")),
        "network_address": (
            str(raw.get("NetworkAddress"))
            if raw.get("NetworkAddress") is not None
            else None
        ),
    }


def _is_active_physical_wifi(adapter: dict) -> bool:
    if adapter.get("status") != "up":
        return False
    if adapter.get("net_connection_status") != 2:
        return False
    if not adapter.get("hardware_interface") or not adapter.get("physical_adapter"):
        return False
    if not adapter.get("registry_mapped") or _is_virtual_identity(adapter):
        return False
    return _is_wifi_medium(adapter)


def discover_adapters() -> list[dict]:
    if sys.platform != "win32":
        return []
    return [
        adapter
        for raw in net_tools._run_powershell_json(_DISCOVER_SCRIPT)
        if (adapter := _normalize_adapter(raw)) is not None
    ]


def _select_adapter(
    adapter_name: str | None = None,
    settings: dict | None = None,
) -> tuple[dict | None, str | None]:
    if sys.platform != "win32":
        return None, "unsupported-platform"
    adapters = [adapter for adapter in discover_adapters() if _is_active_physical_wifi(adapter)]
    if adapter_name:
        matches = [adapter for adapter in adapters if adapter["name"].casefold() == adapter_name.casefold()]
        if len(matches) == 1:
            return matches[0], None
        return None, "invalid-adapter"
    preferred = str((settings or {}).get("mac_preferred_adapter") or "").strip()
    if preferred:
        matches = [adapter for adapter in adapters if adapter["name"].casefold() == preferred.casefold()]
        if len(matches) == 1:
            return matches[0], None
    if not adapters:
        return None, "no-wifi-adapter"
    if len(adapters) > 1:
        return None, "ambiguous-adapter"
    return adapters[0], None


def _safe_adapter(adapter: dict) -> dict:
    return {
        "name": adapter["name"],
        "interface_guid": adapter["interface_guid"],
        "effective_mac": adapter["effective_mac"],
        "network_address_present": adapter["network_address_present"],
        "network_address": adapter["network_address"],
    }


def _load_state() -> tuple[dict | None, str | None]:
    if not MAC_STATE_FILE.exists():
        return {"version": MAC_STATE_VERSION, "adapters": {}}, None
    try:
        state = json.loads(MAC_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)
    if (
        not isinstance(state, dict)
        or state.get("version") != MAC_STATE_VERSION
        or not isinstance(state.get("adapters"), dict)
    ):
        return None, "The MAC recovery state is malformed."
    return state, None


def _write_state(state: dict) -> None:
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(dir=APP_DATA_DIR, prefix=".tmp_mac_state_")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary_name, MAC_STATE_FILE)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _record_for(state: dict, adapter: dict) -> dict | None:
    candidate = state["adapters"].get(adapter["interface_guid"])
    return candidate if isinstance(candidate, dict) else None


def _record_matches_adapter(record: dict, adapter: dict) -> bool:
    return _normalized_pnp(record.get("pnp_device_id")) == adapter["pnp_device_id"]


def _save_baseline_if_needed(adapter: dict) -> tuple[dict | None, str | None]:
    state, error = _load_state()
    if state is None:
        return None, error
    record = _record_for(state, adapter)
    if record is not None:
        if not _record_matches_adapter(record, adapter):
            return None, "The saved recovery record does not match this Wi-Fi adapter."
        return state, None
    state["adapters"][adapter["interface_guid"]] = {
        "adapter_name": adapter["name"],
        "pnp_device_id": adapter["pnp_device_id"],
        "network_address_present": adapter["network_address_present"],
        "network_address": adapter["network_address"],
        "captured_at": int(time.time()),
        "last_generated_mac": None,
        "last_changed_at": None,
    }
    try:
        _write_state(state)
    except OSError as exc:
        return None, str(exc)
    return state, None


def _current_settings(settings: dict | None) -> dict:
    return settings if settings is not None else cfg.load()


def _selection_result(adapter_name: str | None, settings: dict | None) -> dict:
    adapter, error = _select_adapter(adapter_name, _current_settings(settings))
    if adapter is not None:
        return _result("ready", adapter=adapter)
    details = {
        "unsupported-platform": "Wi-Fi MAC privacy controls are available only on Windows.",
        "invalid-adapter": "The requested adapter is not an active physical Wi-Fi adapter.",
        "no-wifi-adapter": "No active physical Wi-Fi adapter was found.",
        "ambiguous-adapter": "More than one active physical Wi-Fi adapter was found; use --adapter.",
    }
    return _result(error or "selection-failed", detail=details.get(error, "Could not select a Wi-Fi adapter."))


def plan_status(adapter_name: str | None = None, settings: dict | None = None) -> dict:
    selection = _selection_result(adapter_name, settings)
    if selection["status"] != "ready":
        return selection
    adapter = selection["adapter"]
    state, error = _load_state()
    if state is None:
        return _result("state-error", adapter=_safe_adapter(adapter), detail=error)
    record = _record_for(state, adapter)
    if record is not None and not _record_matches_adapter(record, adapter):
        return _result(
            "recovery-state-mismatch",
            adapter=_safe_adapter(adapter),
            detail="A saved recovery record belongs to a different device identity.",
        )
    return _result(
        "ready",
        adapter=_safe_adapter(adapter),
        recovery_available=record is not None,
        restore_target=(
            "prior-network-address"
            if record and record.get("network_address_present")
            else "hardware-default"
            if record
            else None
        ),
    )


def plan_randomize(adapter_name: str | None = None, settings: dict | None = None) -> dict:
    effective_settings = _current_settings(settings)
    selection = _selection_result(adapter_name, effective_settings)
    if selection["status"] != "ready":
        return selection
    custom_mac = str(effective_settings.get("mac_custom_private_address") or "").strip()
    try:
        if custom_mac:
            target_mac = validate_private_mac(custom_mac)
            source = "custom"
        else:
            target_mac = _generate_private_mac_different_from(
                effective_settings.get("mac_randomization_prefix", "02"),
                selection["adapter"].get("effective_mac"),
            )
            source = "random"
    except ValueError as exc:
        return _result("invalid-configuration", detail=str(exc))
    return _result(
        "ready",
        operation="randomize",
        adapter=selection["adapter"],
        target_mac=target_mac,
        source=source,
    )


def plan_restore(adapter_name: str | None = None, settings: dict | None = None) -> dict:
    selection = _selection_result(adapter_name, settings)
    if selection["status"] != "ready":
        return selection
    adapter = selection["adapter"]
    state, error = _load_state()
    if state is None:
        return _result("state-error", detail=error)
    record = _record_for(state, adapter)
    if record is None:
        return _result("no-recovery-state", detail="No Blackout Kit MAC recovery record exists for this adapter.")
    if not _record_matches_adapter(record, adapter):
        return _result(
            "recovery-state-mismatch",
            detail="The saved recovery record does not match this Wi-Fi adapter.",
        )
    present = record.get("network_address_present") is True
    prior_value = record.get("network_address") if present else None
    if present and not isinstance(prior_value, str):
        return _result("invalid-recovery-state", detail="The saved prior NetworkAddress value is invalid.")
    return _result(
        "ready",
        operation="restore",
        adapter=adapter,
        network_address_present=present,
        target_network_address=prior_value,
        restore_target="prior-network-address" if present else "hardware-default",
    )


def _ps_literal(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _build_mutation_script(adapter: dict, target_network_address: str | None) -> str:
    interface_guid = _normalized_guid(adapter.get("interface_guid"))
    pnp_device_id = _normalized_pnp(adapter.get("pnp_device_id"))
    if not interface_guid or not pnp_device_id:
        raise ValueError("Adapter identity is incomplete.")
    if target_network_address is not None:
        target_network_address = str(target_network_address)
    target_statement = (
        "New-ItemProperty -LiteralPath $registry.PSPath -Name 'NetworkAddress' -PropertyType String "
        f"-Value {_ps_literal(target_network_address)} -Force -ErrorAction Stop | Out-Null"
        if target_network_address is not None
        else "Remove-ItemProperty -LiteralPath $registry.PSPath -Name 'NetworkAddress' -ErrorAction SilentlyContinue"
    )
    return rf"""
$ErrorActionPreference = 'Stop'
$guid = {_ps_literal(interface_guid)}
$expectedPnp = {_ps_literal(pnp_device_id)}
$classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{_CLASS_GUID}'
$adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {{ ([string]$_.InterfaceGuid).Replace('{{', '').Replace('}}', '').ToUpperInvariant() -eq $guid }}) | Select-Object -First 1
if ($null -eq $adapter) {{ throw 'Selected Wi-Fi adapter was not found.' }}
$native = @(Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop | Where-Object {{ ([string]$_.GUID).Replace('{{', '').Replace('}}', '').ToUpperInvariant() -eq $guid }}) | Select-Object -First 1
if ($null -eq $native -or -not [bool]$adapter.HardwareInterface -or -not [bool]$native.PhysicalAdapter) {{ throw 'Selected adapter is not a physical Wi-Fi adapter.' }}
if ([string]$adapter.Status -ne 'Up' -or [int]$native.NetConnectionStatus -ne 2) {{ throw 'Selected Wi-Fi adapter is not connected.' }}
if ([string]$native.PNPDeviceID -ine $expectedPnp) {{ throw 'Selected adapter identity changed.' }}
$mediumValue = $null
if ($null -ne $adapter.NdisPhysicalMedium) {{ try {{ $mediumValue = [int]$adapter.NdisPhysicalMedium }} catch {{}} }}
$mediumName = ([string]$adapter.NdisPhysicalMedium).ToLowerInvariant().Replace(' ', '').Replace('-', '').Replace('_', '')
if (($mediumValue -notin @(1, 9)) -and ($mediumName -notin @('wirelesslan', 'native80211', '80211', 'wifi', 'wlan'))) {{ throw 'Selected adapter is not Wi-Fi.' }}
$registry = Get-ChildItem -Path $classKey -ErrorAction Stop | ForEach-Object {{
    $candidate = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
    if (([string]$candidate.NetCfgInstanceId).Replace('{{', '').Replace('}}', '').ToUpperInvariant() -eq $guid) {{ $candidate }}
}} | Select-Object -First 1
if ($null -eq $registry) {{ throw 'The selected adapter has no writable driver registry mapping.' }}
{target_statement}
$restartAttempted = $false
$enableError = $null
try {{
    $restartAttempted = $true
    Disable-NetAdapter -InterfaceIndex ([int]$adapter.ifIndex) -Confirm:$false -ErrorAction Stop
}} finally {{
    if ($restartAttempted) {{
        try {{ Enable-NetAdapter -InterfaceIndex ([int]$adapter.ifIndex) -Confirm:$false -ErrorAction Stop }}
        catch {{ $enableError = $_.Exception.Message }}
    }}
}}
if ($null -ne $enableError) {{ throw "Wi-Fi adapter could not be re-enabled: $enableError" }}
""".strip()


def _same_identity(left: dict, right: dict) -> bool:
    return (
        _normalized_guid(left.get("interface_guid")) == _normalized_guid(right.get("interface_guid"))
        and _normalized_pnp(left.get("pnp_device_id")) == _normalized_pnp(right.get("pnp_device_id"))
    )


def _current_adapter_for(adapter: dict) -> dict | None:
    for candidate in discover_adapters():
        if _same_identity(candidate, adapter):
            return candidate
    return None


def _verify_randomize(adapter: dict, target_mac: str) -> bool:
    current = _current_adapter_for(adapter)
    return bool(
        current
        and _is_active_physical_wifi(current)
        and current.get("network_address_present")
        and current.get("network_address") == target_mac
        and current.get("effective_mac") == target_mac
    )


def _verify_restore(adapter: dict, record: dict) -> bool:
    current = _current_adapter_for(adapter)
    if not current or not _is_active_physical_wifi(current):
        return False
    if record.get("network_address_present") is not True:
        return not current.get("network_address_present")
    target = record.get("network_address")
    if not isinstance(target, str) or current.get("network_address") != target:
        return False
    try:
        return current.get("effective_mac") == normalize_mac(target)
    except ValueError:
        return True


def execute(plan: dict) -> dict:
    if sys.platform != "win32":
        return _result("unsupported-platform", detail="Wi-Fi MAC privacy controls are available only on Windows.")
    if plan.get("status") != "ready" or plan.get("operation") not in {"randomize", "restore"}:
        return _result("invalid-plan", detail="MAC operation was not planned successfully.")
    requested_adapter = plan.get("adapter")
    if not isinstance(requested_adapter, dict):
        return _result("invalid-plan", detail="MAC operation has no adapter identity.")
    adapter = _current_adapter_for(requested_adapter)
    if adapter is None or not _is_active_physical_wifi(adapter):
        return _result(
            "invalid-adapter",
            detail="The selected adapter is no longer an active physical Wi-Fi adapter.",
        )
    if plan["operation"] == "randomize":
        target_mac = str(plan.get("target_mac") or "")
        try:
            target_mac = validate_private_mac(target_mac)
        except ValueError as exc:
            return _result("invalid-plan", detail=str(exc))
        state, error = _save_baseline_if_needed(adapter)
        if state is None:
            return _result("state-error", detail=error or "Could not save MAC recovery state.")
        script = _build_mutation_script(adapter, target_mac)
        if not net_tools._run_recovery_script(script, timeout_ms=60000):
            return _result(
                "mutation-failed",
                adapter=_safe_adapter(adapter),
                detail="The elevated operation failed or UAC was declined. Recovery state was retained.",
            )
        if not _verify_randomize(adapter, target_mac):
            return _result(
                "verification-uncertain",
                adapter=_safe_adapter(adapter),
                target_mac=target_mac,
                detail="The adapter change could not be verified. Recovery state was retained.",
            )
        record = _record_for(state, adapter)
        if record is not None:
            record["last_generated_mac"] = target_mac
            record["last_changed_at"] = int(time.time())
            try:
                _write_state(state)
            except OSError:
                pass
        return _result("randomized", adapter=_safe_adapter(adapter), target_mac=target_mac)

    state, error = _load_state()
    if state is None:
        return _result("state-error", detail=error)
    record = _record_for(state, adapter)
    if record is None or not _record_matches_adapter(record, adapter):
        return _result("invalid-recovery-state", detail="The recovery record is unavailable or does not match this adapter.")
    target_network_address = record.get("network_address") if record.get("network_address_present") is True else None
    if record.get("network_address_present") is True and not isinstance(target_network_address, str):
        return _result("invalid-recovery-state", detail="The saved prior NetworkAddress value is invalid.")
    script = _build_mutation_script(adapter, target_network_address)
    if not net_tools._run_recovery_script(script, timeout_ms=60000):
        return _result(
            "mutation-failed",
            adapter=_safe_adapter(adapter),
            detail="The elevated restore failed or UAC was declined. Recovery state was retained.",
        )
    if not _verify_restore(adapter, record):
        return _result(
            "verification-uncertain",
            adapter=_safe_adapter(adapter),
            detail="The restore could not be verified. Recovery state was retained.",
        )
    del state["adapters"][adapter["interface_guid"]]
    try:
        _write_state(state)
    except OSError:
        return _result(
            "restored-state-retained",
            adapter=_safe_adapter(adapter),
            detail="The prior MAC setting was restored, but the local recovery record could not be cleared.",
        )
    return _result("restored", adapter=_safe_adapter(adapter))
