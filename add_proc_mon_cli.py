with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

proc_mon_cmd = '''
@tools_app.command("process-monitor")
def tools_process_monitor():
    """👁️ Live Process Network Monitor (attributes active sockets to local processes)."""
    from .tools import monitor_process_network

    console.print("[bold cyan]👁️ Process Network Connection Summary...[/bold cyan]\\n")
    procs = monitor_process_network()

    table = make_table(
        "Process Network Summary",
        [("PID", "dim"), ("Process Name", "bold white"), ("Total Sockets", "cyan"), ("Established", "green"), ("Protocols", "yellow"), ("Sample Remote Endpoint", "dim")],
        [],
    )

    for p in procs[:30]:  # Top 30 process talkers
        table.add_row(
            str(p["pid"]),
            p["process"],
            str(p["socket_count"]),
            str(p["established_count"]),
            p["protocols"],
            p["remote_sample"]
        )

    console.print(table)
'''

if 'def tools_process_monitor():' not in code:
    code += "\n" + proc_mon_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added tools_process_monitor to blackoutkit/typer_cli.py")
