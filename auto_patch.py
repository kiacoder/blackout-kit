with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

auto_code = '''

# ─────────────────────────── Event Automation Engine ───────────────────

AUTOMATION_RULES_FILE = APP_DATA_DIR / "automation_rules.json"

def save_automation_rule(name: str, event: str, action: str, enabled: bool = True) -> bool:
    """Save an event automation rule (event trigger -> action)."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        rules = json.loads(AUTOMATION_RULES_FILE.read_text()) if AUTOMATION_RULES_FILE.exists() else {}
    except Exception:
        rules = {}

    rules[name] = {
        "name": name,
        "event": event,
        "action": action,
        "enabled": enabled,
        "created_at": time.time()
    }

    try:
        AUTOMATION_RULES_FILE.write_text(json.dumps(rules, indent=2))
        return True
    except Exception as exc:
        _log.error("Failed to save automation rule %s: %s", name, exc)
        return False

def list_automation_rules() -> list[dict]:
    """List all configured event automation rules."""
    try:
        if not AUTOMATION_RULES_FILE.exists():
            return []
        rules = json.loads(AUTOMATION_RULES_FILE.read_text())
        return sorted(list(rules.values()), key=lambda r: r["name"])
    except Exception:
        return []

def remove_automation_rule(name: str) -> bool:
    """Remove an automation rule by name."""
    try:
        if not AUTOMATION_RULES_FILE.exists():
            return False
        rules = json.loads(AUTOMATION_RULES_FILE.read_text())
        if name in rules:
            del rules[name]
            AUTOMATION_RULES_FILE.write_text(json.dumps(rules, indent=2))
            return True
        return False
    except Exception:
        return False

def trigger_automation_event(event_name: str) -> list[dict]:
    """
    Trigger rules matching `event_name` and execute their configured actions.
    Actions supported: 'panic', 'flush_dns', 'flush_arp', 'audit', 'recovery'.
    """
    triggered_results = []
    rules = [r for r in list_automation_rules() if r.get("enabled") and r.get("event") == event_name]

    for rule in rules:
        action = rule.get("action")
        res = {"rule": rule["name"], "event": event_name, "action": action, "ok": True, "detail": "Action executed"}
        try:
            if action == "panic":
                trigger_panic()
                res["detail"] = "Triggered Panic Button"
            elif action == "flush_dns":
                ok = flush_dns()
                res["ok"] = ok
                res["detail"] = "Flushed DNS" if ok else "Failed to flush DNS"
            elif action == "flush_arp":
                ok, msg = flush_arp_cache()
                res["ok"] = ok
                res["detail"] = msg
            elif action == "audit":
                audit = run_network_audit()
                res["detail"] = f"Network Audit Score: {audit.get('score')}/100"
            elif action == "recovery":
                rec = run_network_recovery(audit_source="automation")
                res["detail"] = f"Executed {len(rec)} recovery repairs"
            else:
                res["ok"] = False
                res["detail"] = f"Unknown action '{action}'"
        except Exception as exc:
            res["ok"] = False
            res["detail"] = str(exc)

        triggered_results.append(res)

    return triggered_results
'''

if "def save_automation_rule" not in code:
    code += auto_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added Event Automation Engine to blackoutkit/tools.py")
