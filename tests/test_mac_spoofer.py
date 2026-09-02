import json
from unittest.mock import Mock

import pytest

from blackoutkit.tools import mac_spoofer


GUID_ONE = "11111111-2222-3333-4444-555555555555"
GUID_TWO = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
PNP_ONE = "PCI\\VEN_8086&DEV_1234"


def _raw_adapter(
    *,
    name="Wi-Fi",
    guid=GUID_ONE,
    pnp=PNP_ONE,
    effective_mac="10-20-30-40-50-60",
    network_address=None,
    present=False,
    medium="Native802_11",
    medium_value=9,
    status="Up",
    connection_status=2,
    hardware=True,
    physical=True,
    registry_mapped=True,
):
    return {
        "Name": name,
        "InterfaceAlias": name,
        "InterfaceGuid": guid,
        "InterfaceIndex": 7,
        "Status": status,
        "HardwareInterface": hardware,
        "NdisPhysicalMedium": medium,
        "NdisPhysicalMediumValue": medium_value,
        "EffectiveMac": effective_mac,
        "PhysicalAdapter": physical,
        "NetConnectionStatus": connection_status,
        "PnpDeviceId": pnp,
        "RegistryMapped": registry_mapped,
        "NetworkAddressPresent": present,
        "NetworkAddress": network_address,
    }


def _configured_windows(monkeypatch, tmp_path, records):
    monkeypatch.setattr(mac_spoofer.sys, "platform", "win32")
    monkeypatch.setattr(mac_spoofer, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(mac_spoofer, "MAC_STATE_FILE", tmp_path / "mac_privacy_state.json")
    monkeypatch.setattr(mac_spoofer.net_tools, "_run_powershell_json", lambda _script: records)


def _adapter(raw=None):
    return mac_spoofer._normalize_adapter(raw or _raw_adapter())


def test_mac_normalization_and_private_address_boundary():
    assert mac_spoofer.normalize_mac("02:aa-bb:cc-dd-ee") == "02AABBCCDDEE"
    assert mac_spoofer.format_mac("02aabbccddee") == "02:AA:BB:CC:DD:EE"
    assert mac_spoofer.validate_private_mac("02aabbccddee") == "02AABBCCDDEE"

    for invalid in ("001122334455", "031122334455", "not-a-mac", "0211223344"):
        with pytest.raises(ValueError):
            mac_spoofer.validate_private_mac(invalid)


def test_random_generator_always_returns_fresh_private_unicast_addresses():
    generated = {mac_spoofer.generate_private_mac("06") for _ in range(20)}

    assert len(generated) > 1
    assert all(mac.startswith("06") for mac in generated)
    assert all(mac_spoofer.validate_private_mac(mac) == mac for mac in generated)


def test_invalid_prefix_is_rejected():
    for invalid in ("", "0", "03", "00", "GG"):
        with pytest.raises(ValueError):
            mac_spoofer.validate_randomization_prefix(invalid)


def test_mac_settings_reject_vendor_and_multicast_values():
    from blackoutkit import settings

    assert settings.validate("mac_randomization_prefix", "02") == (True, "")
    assert settings.validate("mac_randomization_prefix", "03")[0] is False
    assert settings.validate("mac_custom_private_address", "02:AA:BB:CC:DD:EE") == (True, "")
    assert settings.validate("mac_custom_private_address", "00:11:22:33:44:55")[0] is False
    assert settings.validate("mac_custom_private_address", "03:11:22:33:44:55")[0] is False


def test_non_windows_status_does_not_run_powershell(monkeypatch):
    monkeypatch.setattr(mac_spoofer.sys, "platform", "linux")
    query = Mock()
    monkeypatch.setattr(mac_spoofer.net_tools, "_run_powershell_json", query)

    result = mac_spoofer.plan_status()

    assert result["status"] == "unsupported-platform"
    query.assert_not_called()


def test_discovery_rejects_ethernet_virtual_and_disconnected_adapters(monkeypatch, tmp_path):
    records = [
        _raw_adapter(name="Ethernet", medium="Unspecified", medium_value=0),
        _raw_adapter(name="BlackoutKit-TUN", medium="Native802_11", medium_value=9),
        _raw_adapter(name="Offline Wi-Fi", status="Disconnected", connection_status=7),
    ]
    _configured_windows(monkeypatch, tmp_path, records)

    result = mac_spoofer.plan_status()

    assert result["status"] == "no-wifi-adapter"


def test_ambiguous_active_wifi_requires_explicit_adapter(monkeypatch, tmp_path):
    records = [
        _raw_adapter(name="Wi-Fi One"),
        _raw_adapter(name="Wi-Fi Two", guid=GUID_TWO, pnp="PCI\\VEN_8086&DEV_5678"),
    ]
    _configured_windows(monkeypatch, tmp_path, records)

    assert mac_spoofer.plan_status()["status"] == "ambiguous-adapter"
    assert mac_spoofer.plan_status("Wi-Fi Two")["adapter"]["name"] == "Wi-Fi Two"
    assert mac_spoofer.plan_status("Ethernet")["status"] == "invalid-adapter"


def test_randomize_uses_custom_private_mac_or_validated_prefix(monkeypatch, tmp_path):
    _configured_windows(monkeypatch, tmp_path, [_raw_adapter()])

    custom = mac_spoofer.plan_randomize(settings={
        "mac_custom_private_address": "06:AA:BB:CC:DD:EE",
        "mac_randomization_prefix": "02",
    })
    assert custom["status"] == "ready"
    assert custom["target_mac"] == "06AABBCCDDEE"
    assert custom["source"] == "custom"

    generated = mac_spoofer.plan_randomize(settings={
        "mac_custom_private_address": "",
        "mac_randomization_prefix": "0A",
    })
    assert generated["target_mac"].startswith("0A")
    assert generated["source"] == "random"

    invalid = mac_spoofer.plan_randomize(settings={
        "mac_custom_private_address": "001122334455",
        "mac_randomization_prefix": "02",
    })
    assert invalid["status"] == "invalid-configuration"


def test_randomize_retries_when_a_generated_address_matches_current_mac(monkeypatch, tmp_path):
    current_mac = "02AABBCCDDEE"
    _configured_windows(monkeypatch, tmp_path, [_raw_adapter(effective_mac=current_mac)])
    generated = iter((current_mac, "02AABBCCDDEF"))
    monkeypatch.setattr(mac_spoofer, "generate_private_mac", lambda _prefix: next(generated))

    plan = mac_spoofer.plan_randomize(settings={
        "mac_custom_private_address": "",
        "mac_randomization_prefix": "02",
    })

    assert plan["status"] == "ready"
    assert plan["target_mac"] == "02AABBCCDDEF"
    assert plan["target_mac"] != current_mac


def test_first_baseline_is_preserved_across_later_randomizations(monkeypatch, tmp_path):
    initial = _raw_adapter(network_address="0A1122334455", present=True)
    _configured_windows(monkeypatch, tmp_path, [initial])
    adapter = _adapter(initial)

    state, error = mac_spoofer._save_baseline_if_needed(adapter)
    assert error is None
    assert state["adapters"][GUID_ONE]["network_address"] == "0A1122334455"

    updated = _adapter(_raw_adapter(network_address="02AABBCCDDEE", present=True))
    state, error = mac_spoofer._save_baseline_if_needed(updated)

    assert error is None
    assert state["adapters"][GUID_ONE]["network_address"] == "0A1122334455"


def test_restore_plan_distinguishes_prior_override_and_hardware_default(monkeypatch, tmp_path):
    raw = _raw_adapter(network_address="02AABBCCDDEE", present=True)
    _configured_windows(monkeypatch, tmp_path, [raw])
    adapter = _adapter(raw)

    mac_spoofer._write_state({
        "version": mac_spoofer.MAC_STATE_VERSION,
        "adapters": {
            GUID_ONE: {
                "adapter_name": "Wi-Fi",
                "pnp_device_id": PNP_ONE,
                "network_address_present": True,
                "network_address": "0A1122334455",
            },
        },
    })
    override_plan = mac_spoofer.plan_restore()
    assert override_plan["target_network_address"] == "0A1122334455"
    assert override_plan["restore_target"] == "prior-network-address"

    mac_spoofer._write_state({
        "version": mac_spoofer.MAC_STATE_VERSION,
        "adapters": {
            GUID_ONE: {
                "adapter_name": "Wi-Fi",
                "pnp_device_id": adapter["pnp_device_id"],
                "network_address_present": False,
                "network_address": None,
            },
        },
    })
    default_plan = mac_spoofer.plan_restore()
    assert default_plan["target_network_address"] is None
    assert default_plan["restore_target"] == "hardware-default"


def test_mutation_script_is_adapter_scoped_and_reenables_in_finally():
    script = mac_spoofer._build_mutation_script(_adapter(), "02AABBCCDDEE")

    assert "NetworkAddress" in script
    assert "Disable-NetAdapter -InterfaceIndex" in script
    assert "Enable-NetAdapter -InterfaceIndex" in script
    assert "finally" in script
    assert ".Trim(" not in script
    assert ".Replace('{', '').Replace('}', '').ToUpperInvariant()" in script
    assert ".Replace('{', '').Replace('}', '').ToUpperInvariant()" in mac_spoofer._DISCOVER_SCRIPT
    assert "Set-DnsClientServerAddress" not in script
    assert "New-NetRoute" not in script
    assert "Set-NetFirewallProfile" not in script
    assert "BlackoutKit-TUN" not in script


def test_randomize_failure_retains_original_recovery_state(monkeypatch, tmp_path):
    raw = _raw_adapter(network_address=None, present=False)
    _configured_windows(monkeypatch, tmp_path, [raw])
    plan = mac_spoofer.plan_randomize(settings={
        "mac_custom_private_address": "02AABBCCDDEE",
        "mac_randomization_prefix": "02",
    })
    script_runner = Mock(return_value=False)
    monkeypatch.setattr(mac_spoofer.net_tools, "_run_recovery_script", script_runner)

    result = mac_spoofer.execute(plan)

    assert result["status"] == "mutation-failed"
    stored = json.loads(mac_spoofer.MAC_STATE_FILE.read_text(encoding="utf-8"))
    assert stored["adapters"][GUID_ONE]["network_address_present"] is False
    assert "NetworkAddress" in script_runner.call_args.args[0]


def test_randomize_verification_uncertainty_retains_recovery_state(monkeypatch, tmp_path):
    raw = _raw_adapter(network_address=None, present=False)
    _configured_windows(monkeypatch, tmp_path, [raw])
    plan = mac_spoofer.plan_randomize(settings={
        "mac_custom_private_address": "02AABBCCDDEE",
        "mac_randomization_prefix": "02",
    })
    monkeypatch.setattr(mac_spoofer.net_tools, "_run_recovery_script", Mock(return_value=True))

    result = mac_spoofer.execute(plan)

    assert result["status"] == "verification-uncertain"
    assert mac_spoofer.MAC_STATE_FILE.exists()


def test_randomize_verified_updates_existing_baseline_without_replacing_it(monkeypatch, tmp_path):
    before = _adapter(_raw_adapter(network_address="0A1122334455", present=True))
    after = _adapter(_raw_adapter(
        effective_mac="02AABBCCDDEE",
        network_address="02AABBCCDDEE",
        present=True,
    ))
    _configured_windows(monkeypatch, tmp_path, [])
    calls = iter([[before], [before], [after]])
    monkeypatch.setattr(mac_spoofer, "discover_adapters", lambda: next(calls))
    monkeypatch.setattr(mac_spoofer.net_tools, "_run_recovery_script", Mock(return_value=True))
    plan = mac_spoofer.plan_randomize(settings={
        "mac_custom_private_address": "02AABBCCDDEE",
        "mac_randomization_prefix": "02",
    })

    result = mac_spoofer.execute(plan)

    assert result["status"] == "randomized"
    stored = json.loads(mac_spoofer.MAC_STATE_FILE.read_text(encoding="utf-8"))
    record = stored["adapters"][GUID_ONE]
    assert record["network_address"] == "0A1122334455"
    assert record["last_generated_mac"] == "02AABBCCDDEE"


def test_restore_absent_override_removes_value_and_clears_state_after_verification(monkeypatch, tmp_path):
    before = _adapter(_raw_adapter(
        effective_mac="02AABBCCDDEE",
        network_address="02AABBCCDDEE",
        present=True,
    ))
    restored = _adapter(_raw_adapter(
        effective_mac="102030405060",
        network_address=None,
        present=False,
    ))
    _configured_windows(monkeypatch, tmp_path, [])
    mac_spoofer._write_state({
        "version": mac_spoofer.MAC_STATE_VERSION,
        "adapters": {
            GUID_ONE: {
                "adapter_name": "Wi-Fi",
                "pnp_device_id": PNP_ONE,
                "network_address_present": False,
                "network_address": None,
            },
        },
    })
    calls = iter([[before], [before], [restored]])
    monkeypatch.setattr(mac_spoofer, "discover_adapters", lambda: next(calls))
    runner = Mock(return_value=True)
    monkeypatch.setattr(mac_spoofer.net_tools, "_run_recovery_script", runner)
    plan = mac_spoofer.plan_restore()

    result = mac_spoofer.execute(plan)

    assert result["status"] == "restored"
    assert not mac_spoofer.MAC_STATE_FILE.exists() or not json.loads(mac_spoofer.MAC_STATE_FILE.read_text())["adapters"]
    assert "Remove-ItemProperty" in runner.call_args.args[0]


def test_restore_prior_override_reinstates_exact_value(monkeypatch, tmp_path):
    before = _adapter(_raw_adapter(
        effective_mac="02AABBCCDDEE",
        network_address="02AABBCCDDEE",
        present=True,
    ))
    restored = _adapter(_raw_adapter(
        effective_mac="0A1122334455",
        network_address="0A1122334455",
        present=True,
    ))
    _configured_windows(monkeypatch, tmp_path, [])
    mac_spoofer._write_state({
        "version": mac_spoofer.MAC_STATE_VERSION,
        "adapters": {
            GUID_ONE: {
                "adapter_name": "Wi-Fi",
                "pnp_device_id": PNP_ONE,
                "network_address_present": True,
                "network_address": "0A1122334455",
            },
        },
    })
    calls = iter([[before], [before], [restored]])
    monkeypatch.setattr(mac_spoofer, "discover_adapters", lambda: next(calls))
    runner = Mock(return_value=True)
    monkeypatch.setattr(mac_spoofer.net_tools, "_run_recovery_script", runner)
    plan = mac_spoofer.plan_restore()

    assert mac_spoofer.execute(plan)["status"] == "restored"
    assert "-Value '0A1122334455'" in runner.call_args.args[0]


def test_execute_rechecks_platform_and_adapter_before_mutating(monkeypatch):
    monkeypatch.setattr(mac_spoofer.sys, "platform", "linux")
    runner = Mock()
    monkeypatch.setattr(mac_spoofer.net_tools, "_run_recovery_script", runner)

    result = mac_spoofer.execute({"status": "ready", "operation": "randomize", "adapter": _adapter()})

    assert result["status"] == "unsupported-platform"
    runner.assert_not_called()
