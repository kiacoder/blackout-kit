with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

graph_cmd = '''
@tools_app.command("traffic-graph")
def tools_traffic_graph(
    samples: int = typer.Option(5, "--samples", "-s", help="Number of samples to record"),
    interval: float = typer.Option(1.0, "--interval", "-i", help="Interval between samples in seconds"),
):
    """📊 Live Visual Traffic Graph (displays real-time bandwidth bars)."""
    from .tools import get_interface_io_counters, compute_bandwidth_rates, generate_ascii_bandwidth_chart
    console.print(f"[bold cyan]📊 Live Traffic Visual Bar Graph ({samples} samples)...[/bold cyan]\\n")

    prev = get_interface_io_counters()
    for _ in range(samples):
        time.sleep(interval)
        curr = get_interface_io_counters()
        rates = compute_bandwidth_rates(prev, curr, interval)
        prev = curr

        tot_rx = sum(r["rx_bps"] for r in rates.values())
        tot_tx = sum(r["tx_bps"] for r in rates.values())

        chart = generate_ascii_bandwidth_chart(tot_rx, tot_tx)
        console.print(chart + "\\n")
'''

if 'def tools_traffic_graph(' not in code:
    code += "\n" + graph_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added tools_traffic_graph to blackoutkit/typer_cli.py")
