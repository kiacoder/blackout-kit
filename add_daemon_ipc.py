with open("blackoutkit/daemon.py", "r") as f:
    code = f.read()

ipc_func = '''
def stream_daemon_ipc_metrics() -> dict:
    """⚡ High-Performance Daemon IPC Metrics Stream."""
    pid = get_pid()
    state = get_state()
    active = is_running()
    return {
        "pid": pid,
        "active": active,
        "engine": state.get("engine") if state else None,
        "started_at": state.get("started_at") if state else None,
        "uptime": time.time() - state["started_at"] if (state and "started_at" in state) else 0.0,
        "memory_mb": 0.0,
    }
'''

if "def stream_daemon_ipc_metrics" not in code:
    code += ipc_func
    with open("blackoutkit/daemon.py", "w") as f:
        f.write(code)

with open("blackoutkit/daemon/__init__.py", "r") as f:
    init_code = f.read()

if "stream_daemon_ipc_metrics" not in init_code:
    init_code += "\nfrom ..daemon import stream_daemon_ipc_metrics\n"
    with open("blackoutkit/daemon/__init__.py", "w") as f:
        f.write(init_code)

print("Updated daemon package exports")
