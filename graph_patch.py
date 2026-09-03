with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

graph_code = '''

# ─────────────────────────── Visual Traffic Bar Graph ───────────────────

def generate_ascii_bandwidth_chart(rx_bps: float, tx_bps: float, max_bps: float = 10_000_000.0, bar_width: int = 30) -> str:
    """
    📊 Visual ASCII Bandwidth Bar Graph:
    Generates colorful ASCII visual bars for rx/tx download/upload speeds.
    """
    rx_mbps = rx_bps / 1_000_000.0
    tx_mbps = tx_bps / 1_000_000.0

    rx_ratio = min(1.0, rx_bps / max_bps)
    tx_ratio = min(1.0, tx_bps / max_bps)

    rx_bar = "█" * int(rx_ratio * bar_width)
    tx_bar = "█" * int(tx_ratio * bar_width)

    return f"Download: {rx_mbps:6.2f} Mbps [{rx_bar:<{bar_width}}]\nUpload:   {tx_mbps:6.2f} Mbps [{tx_bar:<{bar_width}}]"
'''

if "def generate_ascii_bandwidth_chart" not in code:
    code += graph_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added generate_ascii_bandwidth_chart to blackoutkit/tools.py")
