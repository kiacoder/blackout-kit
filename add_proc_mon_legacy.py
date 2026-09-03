with open("blackoutkit/cli.py", "r") as f:
    code = f.read()

proc_legacy = '''
    elif cmd == "process-monitor":
        from .tools import monitor_process_network
        procs = monitor_process_network()
        table = make_table(
            "Process Network Summary",
            [("PID", "dim"), ("Process Name", "bold white"), ("Total Sockets", "cyan"), ("Established", "green"), ("Protocols", "yellow"), ("Sample Remote Endpoint", "dim")],
            [],
        )
        for p in procs[:30]:
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

if 'elif cmd == "process-monitor":' not in code:
    code = code.replace('    elif cmd == "audit":', proc_legacy + '\n    elif cmd == "audit":')
    with open("blackoutkit/cli.py", "w") as f:
        f.write(code)
    print("Updated cmd_tools in blackoutkit/cli.py with process-monitor")
