with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

arpguard_code = '''

# ─────────────────────────── Subnet ARP Guard & Spoofing Monitor ───────────────────

def detect_arp_spoofing() -> dict:
    """
    🌐 Subnet ARP Guard & Anti-Spoofing Monitor:
    Inspects local ARP table for duplicate MAC addresses across different IP addresses (MITM signal).
    """
    table = _arp_table()
    mac_to_ips: dict[str, list[str]] = {}

    for ip, mac in table.items():
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "-"):
            continue
        mac_to_ips.setdefault(mac, []).append(ip)

    spoof_suspects = []
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            spoof_suspects.append({"mac": mac, "ips": ips})

    return {
        "ok": len(spoof_suspects) == 0,
        "total_hosts": len(table),
        "spoof_suspects": spoof_suspects
    }
'''

if "def detect_arp_spoofing" not in code:
    code += arpguard_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added detect_arp_spoofing to blackoutkit/tools.py")
