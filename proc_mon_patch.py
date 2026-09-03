with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

proc_mon_code = '''

# ─────────────────────────── Process Network Monitor ───────────────────

def monitor_process_network() -> list[dict]:
    """
    👁️ Live Process Network Monitor:
    Inspects all active network connections and attributes bandwidth & sockets to process names.
    Returns sorted list of {pid, process, local_endpoint, remote_endpoint, status, protocol, socket_count}.
    """
    import psutil

    connections = get_active_connections(established_only=False)
    proc_summary: dict[int, dict] = {}

    for conn in connections:
        pid = conn.get("pid", 0)
        proc_name = conn.get("process", "unknown")
        local_endpoint = f"{conn.get('local_addr')}:{conn.get('local_port')}"
        remote_ip = conn.get("remote_addr")
        remote_port = conn.get("remote_port")
        remote_endpoint = f"{remote_ip}:{remote_port}" if remote_ip else "-"
        status = conn.get("status", "-")
        protocol = conn.get("protocol", "TCP")

        if pid not in proc_summary:
            proc_summary[pid] = {
                "pid": pid,
                "process": proc_name,
                "socket_count": 0,
                "established_count": 0,
                "protocols": set(),
                "sample_remote": remote_endpoint if remote_endpoint != "-" else None
            }

        proc_summary[pid]["socket_count"] += 1
        if status == "ESTABLISHED":
            proc_summary[pid]["established_count"] += 1
        proc_summary[pid]["protocols"].add(protocol)
        if remote_endpoint != "-" and not proc_summary[pid]["sample_remote"]:
            proc_summary[pid]["sample_remote"] = remote_endpoint

    results = []
    for pid, data in proc_summary.items():
        results.append({
            "pid": pid,
            "process": data["process"],
            "socket_count": data["socket_count"],
            "established_count": data["established_count"],
            "protocols": ", ".join(sorted(data["protocols"])),
            "remote_sample": data["sample_remote"] or "-"
        })

    results.sort(key=lambda item: item["socket_count"], reverse=True)
    return results
'''

if "def monitor_process_network" not in code:
    code += proc_mon_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added monitor_process_network to blackoutkit/tools.py")
