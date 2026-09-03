import re

with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

panic_code = '''

# ─────────────────────────── Global Panic Button ───────────────────

def trigger_panic(restore: bool = False) -> list[dict]:
    """
    🚨 Global Panic Button:
    Instantly kills daemon/engines, clears system proxy, disables kill switch,
    flushes DNS and ARP, resets network adapters/routes to secure or restore networking.
    """
    results = []

    # 1. Stop background daemon & all bypass engines
    try:
        from . import daemon
        daemon.stop()
        results.append({"step": "Stop Daemon & Bypass Engines", "ok": True, "detail": "Stopped daemon and killed child process trees"})
    except Exception as exc:
        results.append({"step": "Stop Daemon & Bypass Engines", "ok": False, "detail": str(exc)})

    # 2. Clear System Proxy
    try:
        from .proxy_manager import clear_system_proxy
        clear_system_proxy()
        results.append({"step": "Clear System Proxy", "ok": True, "detail": "System proxy setting cleared"})
    except Exception as exc:
        results.append({"step": "Clear System Proxy", "ok": False, "detail": str(exc)})

    # 3. Disable Kill Switch / Remove Firewall Blocks
    try:
        from . import security as sec
        from . import settings as cfg
        sec.disable_kill_switch()
        cfg.set_value("kill_switch", False)
        results.append({"step": "Disable Kill Switch", "ok": True, "detail": "Blackout-owned firewall block rules removed"})
    except Exception as exc:
        results.append({"step": "Disable Kill Switch", "ok": False, "detail": str(exc)})

    # 4. Flush DNS Resolver Cache
    try:
        ok = flush_dns()
        results.append({"step": "Flush DNS Cache", "ok": ok, "detail": "Resolver cache flushed" if ok else "Failed to flush DNS"})
    except Exception as exc:
        results.append({"step": "Flush DNS Cache", "ok": False, "detail": str(exc)})

    # 5. Flush ARP Cache
    try:
        ok, msg = flush_arp_cache()
        results.append({"step": "Flush ARP Cache", "ok": ok, "detail": msg})
    except Exception as exc:
        results.append({"step": "Flush ARP Cache", "ok": False, "detail": str(exc)})

    # 6. Run Targeted Network Recovery (or restore network stack)
    try:
        rec_results = run_network_recovery(full_route_reset=restore, full_stack_reset=restore, audit_source="panic")
        results.append({"step": "Targeted Network Recovery", "ok": True, "detail": f"Executed {len(rec_results)} recovery repairs"})
    except Exception as exc:
        results.append({"step": "Targeted Network Recovery", "ok": False, "detail": str(exc)})

    return results
'''

if "def trigger_panic" not in code:
    code += panic_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added trigger_panic to blackoutkit/tools.py")
