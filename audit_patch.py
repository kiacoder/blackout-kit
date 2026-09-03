with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

audit_code = '''

# ─────────────────────────── Network Hardening Audit ───────────────────

def run_network_audit() -> dict:
    """
    🛡️ Network Hardening Audit:
    Inspects listening ports, unencrypted services, DNS servers, firewall status, and local exposures.
    Returns audit details and a overall Security Score (0-100%).
    """
    findings = []
    score = 100

    # 1. Inspect listening ports & unencrypted protocols
    try:
        connections = get_active_connections(established_only=False)
        listening = [c for c in connections if c.get("status") == "LISTEN" or c.get("protocol") == "UDP"]
        insecure_ports = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP", 445: "SMB", 3389: "RDP", 5900: "VNC"}
        exposed_insecure = []

        for conn in listening:
            port = conn.get("local_port")
            if port in insecure_ports:
                proc = conn.get("process", "unknown")
                service = insecure_ports[port]
                exposed_insecure.append(f"{service} ({port}/TCP) used by {proc}")

        if exposed_insecure:
            penalty = min(30, len(exposed_insecure) * 10)
            score -= penalty
            findings.append({
                "category": "Exposed Ports & Insecure Protocols",
                "severity": "HIGH",
                "ok": False,
                "summary": f"Found {len(exposed_insecure)} unencrypted/sensitive service(s) listening locally",
                "details": exposed_insecure,
                "recommendation": "Disable plaintext services (Telnet/FTP/HTTP) or bind them to 127.0.0.1"
            })
        else:
            findings.append({
                "category": "Exposed Ports & Insecure Protocols",
                "severity": "INFO",
                "ok": True,
                "summary": "No common unencrypted cleartext protocols listening publicly",
                "details": [],
                "recommendation": "Maintain strict listening port bounds"
            })
    except Exception as exc:
        findings.append({
            "category": "Exposed Ports & Insecure Protocols",
            "severity": "WARNING",
            "ok": False,
            "summary": f"Could not inspect listening sockets: {exc}",
            "details": [],
            "recommendation": "Run as privileged user to inspect process ports"
        })

    # 2. DNS Inspector & Poisoning Check
    try:
        dns_res = inspect_dns()
        servers = dns_res.get("servers", [])
        suspects = [check for check in dns_res.get("checks", []) if check.get("suspect")]

        if suspects:
            score -= 25
            findings.append({
                "category": "DNS Resolver Integrity",
                "severity": "CRITICAL",
                "ok": False,
                "summary": f"Detected potential DNS tampering/poisoning on {len(suspects)} domain(s)",
                "details": [f"{s['domain']} resolved to {s['system_ip']} vs DoH {s['trusted_ip']}" for s in suspects],
                "recommendation": "Switch system DNS to DoH / DoT or trusted resolvers (1.1.1.1 / 9.9.9.9)"
            })
        else:
            findings.append({
                "category": "DNS Resolver Integrity",
                "severity": "INFO",
                "ok": True,
                "summary": f"System DNS ({', '.join(servers) or 'default'}) matches trusted DoH baseline",
                "details": [],
                "recommendation": "Consider enabling DoH for encrypted DNS queries"
            })
    except Exception as exc:
        findings.append({
            "category": "DNS Resolver Integrity",
            "severity": "WARNING",
            "ok": False,
            "summary": f"DNS integrity check failed: {exc}",
            "details": [],
            "recommendation": "Verify network connectivity"
        })

    # 3. System Proxy & VPN Leak Checks
    try:
        from .proxy_manager import get_proxy_status
        proxy_stat = get_proxy_status()
        if proxy_stat.get("enabled"):
            server = proxy_stat.get("server", "")
            if not _is_blackout_proxy_server(server):
                score -= 10
                findings.append({
                    "category": "Proxy Configuration",
                    "severity": "MEDIUM",
                    "ok": False,
                    "summary": f"External system proxy configured: {server}",
                    "details": [f"Server: {server}"],
                    "recommendation": "Ensure external proxy server is trusted and encrypted"
                })
            else:
                findings.append({
                    "category": "Proxy Configuration",
                    "severity": "INFO",
                    "ok": True,
                    "summary": "Blackout Kit local proxy active",
                    "details": [],
                    "recommendation": "Proxy traffic is managed locally"
                })
        else:
            findings.append({
                "category": "Proxy Configuration",
                "severity": "INFO",
                "ok": True,
                "summary": "No active system proxy override",
                "details": [],
                "recommendation": "Direct system traffic"
            })
    except Exception as exc:
        pass

    # 4. Firewall & Kill Switch State
    try:
        from . import settings as cfg
        ks_enabled = cfg.load().get("kill_switch", False)
        if not ks_enabled:
            score -= 10
            findings.append({
                "category": "Kill Switch Protection",
                "severity": "LOW",
                "ok": False,
                "summary": "Kill switch firewall enforcement is disabled",
                "details": [],
                "recommendation": "Enable kill switch via `blackout settings set kill_switch true` or `blackout killswitch on`"
            })
        else:
            findings.append({
                "category": "Kill Switch Protection",
                "severity": "INFO",
                "ok": True,
                "summary": "Kill switch enforcement enabled",
                "details": [],
                "recommendation": "Leak protection active"
            })
    except Exception:
        pass

    score = max(0, min(100, score))
    return {
        "score": score,
        "grade": "A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 70 else "C" if score >= 60 else "F",
        "findings": findings
    }
'''

if "def run_network_audit" not in code:
    code += audit_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added run_network_audit to blackoutkit/tools.py")
