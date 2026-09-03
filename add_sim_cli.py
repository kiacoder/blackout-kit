with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

sim_cmd = '''
@tools_app.command("simulate")
def tools_simulate(
    host: str = typer.Argument("8.8.8.8", help="Target host to probe"),
    latency: float = typer.Option(100.0, "--latency", "-l", help="Added latency in ms"),
    loss: float = typer.Option(10.0, "--loss", help="Simulated packet loss percentage (0-100)"),
):
    """⚡ Network Simulation (simulate high latency and packet loss for DevOps/QA testing)."""
    from .tools import simulate_network_conditions
    res = simulate_network_conditions(host=host, added_latency_ms=latency, simulated_loss_pct=loss)
    st = res["stats"]
    console.print(f"[bold cyan]⚡ Network Simulation to {host}[/bold cyan] (+{latency}ms latency, {loss}% loss):\\n")
    console.print(f"Avg Latency: {st['avg']:.1f}ms | Loss Rate: {st['loss_pct']:.1f}%")
'''

if 'def tools_simulate(' not in code:
    code += "\n" + sim_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added tools_simulate to blackoutkit/typer_cli.py")
