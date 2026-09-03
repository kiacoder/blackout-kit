with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

explain_code = '''

# ─────────────────────────── AI Network Explainer ───────────────────

def explain_network_state() -> dict:
    """
    🤖 AI Network Explainer:
    Aggregates active network connections, process sockets, DNS integrity,
    and firewall posture into an anomaly diagnostic summary for AI agents / Claude.
    """
    audit = run_network_audit()
    procs = monitor_process_network()
    dns = inspect_dns()

    anomalies = []

    # Check for processes with excessive sockets
    for p in procs:
        if p.get("socket_count", 0) > 20:
            anomalies.append(f"Process '{p['process']}' (PID {p['pid']}) has unusually high socket count: {p['socket_count']} sockets")

    # Check for DNS tampering
    for chk in dns.get("checks", []):
        if chk.get("suspect"):
            anomalies.append(f"DNS Poisoning Suspect: {chk['domain']} resolved to {chk['system_ip']} vs DoH {chk['trusted_ip']}")

    # Check audit issues
    for f in audit.get("findings", []):
        if not f.get("ok"):
            anomalies.append(f"Security Finding ({f['severity']}): {f['summary']}")

    return {
        "security_score": audit.get("score"),
        "grade": audit.get("grade"),
        "active_processes_count": len(procs),
        "total_anomalies_detected": len(anomalies),
        "anomalies": anomalies,
        "raw_audit_summary": [f['summary'] for f in audit.get("findings", [])]
    }
'''

if "def explain_network_state" not in code:
    code += explain_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added explain_network_state to blackoutkit/tools.py")
