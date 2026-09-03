with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

bench_cmd = '''
@config_app.command("benchmark")
def cfg_benchmark():
    """📜 Interactive Proxy Config Benchmark (test all saved proxy records concurrently)."""
    from .config.manager import load_configs
    from .scanner.proxy_tester import test_tcp_port
    configs = load_configs()
    if not configs:
        console.print("[muted]No saved configs to benchmark.[/muted]")
        return
    console.print(f"[bold cyan]📜 Benchmarking {len(configs)} saved proxy configs...[/bold cyan]\\n")
    table = make_table(
        "Config Benchmark Results",
        [("#", "dim"), ("Protocol", "cyan"), ("Transport", "yellow"), ("Server Endpoint", "bold white"), ("Latency", "green")],
        [],
    )
    for idx, cfg in enumerate(configs, 1):
        parsed = cfg.parsed_dict if hasattr(cfg, "parsed_dict") else {}
        server = parsed.get("add") or parsed.get("host") or "unknown"
        port = int(parsed.get("port") or 443)
        lat = test_tcp_port(server, port)
        lat_str = f"{int(lat)} ms" if lat is not None else "[red]Timeout[/red]"
        table.add_row(str(idx), cfg.protocol, cfg.transport_label(), f"{server}:{port}", lat_str)
    console.print(table)
'''

if 'def cfg_benchmark():' not in code:
    code += "\n" + bench_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added cfg_benchmark to blackoutkit/typer_cli.py")
