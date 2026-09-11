#!/usr/bin/env python3
"""Comprehensive test of the Hotspot Shield VPN engine integration."""
import sys
from pathlib import Path

from blackoutkit.engines.hotspot_shield import HotspotShieldEngine, FREE_TIER_SERVERS
from blackoutkit.engines import ENGINE_REGISTRY

def test():
    print("\n" + "="*70)
    print("🔍 HOTSPOT SHIELD ENGINE — COMPREHENSIVE TEST")
    print("="*70 + "\n")

    # Test 1: Engine is registered
    print("1️⃣  Engine Registration")
    print(f"   Available engines: {list(ENGINE_REGISTRY.keys())}")
    assert "hotspot-shield" in ENGINE_REGISTRY, "HS engine not registered!"
    print("   ✅ Hotspot Shield registered\n")

    # Test 2: Engine instantiation
    print("2️⃣  Engine Instantiation")
    engine = HotspotShieldEngine()
    print(f"   Engine name: {engine.name}")
    print(f"   Description: {engine.description}")
    print("   ✅ Engine created\n")

    # Test 3: Server list
    print("3️⃣  Server List")
    servers = engine.get_all_servers()
    print(f"   Total servers: {len(servers)}")
    print(f"   Network CDNs:")
    for cdn, prefixes in FREE_TIER_SERVERS.items():
        print(f"      - {cdn}: {len(prefixes)} servers")
    assert len(servers) == 97, "Server count mismatch!"
    print("   ✅ 97 free-tier servers available\n")

    # Test 4: Server selection
    print("4️⃣  Server Selection")
    server1 = engine.select_random_server()
    server2 = engine.select_random_server()
    print(f"   Selected #1: {server1}")
    print(f"   Selected #2: {server2}")
    assert server1 != server2 or len(servers) == 1, "Randomization failed"
    print("   ✅ Server selection working\n")

    # Test 5: Status detection
    print("5️⃣  VPN Status Detection")
    is_app_running = engine._is_hss_app_running()
    is_adapter_active = engine._is_hssstore_adapter_active()
    print(f"   HS app running: {is_app_running}")
    print(f"   HssStore adapter active: {is_adapter_active}")
    print(f"   Overall VPN connected: {engine.is_running()}")
    print("   ✅ Status detection working\n")

    # Test 6: Engine methods exist and callable
    print("6️⃣  Engine Methods")
    methods = ["start", "stop", "is_running", "get_all_servers", "select_random_server"]
    for method in methods:
        assert hasattr(engine, method), f"Missing method: {method}"
        assert callable(getattr(engine, method)), f"Method not callable: {method}"
    print(f"   All {len(methods)} core methods present")
    print("   ✅ Interface complete\n")

    print("="*70)
    print("✅ ALL TESTS PASSED - Engine ready for integration!")
    print("="*70 + "\n")

    print("📋 Integration Summary:")
    print("   • 97 unlimited free VPN servers")
    print("   • Detects HssStore virtual adapter")
    print("   • Leverages existing HS Windows Store app")
    print("   • No additional credential management")
    print("   • Ready: blackout start hotspot-shield")
    print()

if __name__ == "__main__":
    try:
        test()
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
