with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

sim_code = '''

# ─────────────────────────── Network Simulation & Latency Injector ───────────────────

def simulate_network_conditions(host: str = "8.8.8.8", added_latency_ms: float = 100.0, simulated_loss_pct: float = 10.0, samples: int = 5) -> dict:
    """
    ⚡ Network Simulation & Latency/Loss Injector:
    Simulates high-latency / lossy network conditions on ping probes for DevOps & QA testing.
    """
    import random

    raw_pings = ping(host, count=samples)
    simulated_pings = []

    for p in raw_pings:
        # Simulate packet loss
        if random.uniform(0, 100) < simulated_loss_pct:
            simulated_pings.append(None)
        elif p is not None:
            simulated_pings.append(p + added_latency_ms)
        else:
            simulated_pings.append(None)

    stats = ping_stats(simulated_pings)
    return {
        "host": host,
        "added_latency_ms": added_latency_ms,
        "simulated_loss_pct": simulated_loss_pct,
        "stats": stats
    }
'''

if "def simulate_network_conditions" not in code:
    code += sim_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added simulate_network_conditions to blackoutkit/tools.py")
