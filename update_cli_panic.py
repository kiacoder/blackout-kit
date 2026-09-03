with open("blackoutkit/cli.py", "r") as f:
    code = f.read()

old_func = """def cmd_panic(args):
    \"\"\"Instantly kills all connections, flushes DNS, clears proxies, and resets killswitch.\"\"\"
    console.print("[bold red]🚨 PANIC BUTTON ACTIVATED 🚨[/bold red]")
    console.print("[muted]Executing emergency disconnect and trace flush...[/muted]\\n")

    # 1. Stop daemon
    console.print("[dim]→ Stopping daemon & all engines...[/dim]")
    from . import daemon
    daemon.stop()

    # 2. Clear System Proxy
    console.print("[dim]→ Clearing Windows system proxy...[/dim]")
    from .proxy_manager import clear_system_proxy
    clear_system_proxy()

    # 3. Disable Kill Switch
    console.print("[dim]→ Disabling kill switch firewall rules...[/dim]")
    from . import security as sec
    sec.disable_kill_switch()
    cfg.set_value("kill_switch", False)

    # 4. Flush DNS
    console.print("[dim]→ Flushing DNS cache...[/dim]")
    from .tools import flush_dns
    flush_dns()

    console.print("\\n[bold green]✓ SYSTEM SECURED. YOU ARE OFFLINE.[/bold green]")"""

new_func = """def cmd_panic(args):
    \"\"\"🚨 Emergency network killswitch & trace cleanup.\"\"\"
    restore = getattr(args, "restore", False)
    console.print("[bold red]🚨 GLOBAL PANIC BUTTON ACTIVATED 🚨[/bold red]")
    console.print("[muted]Executing emergency isolation, process kill, and network recovery...[/muted]\\n")

    from .tools import trigger_panic
    results = trigger_panic(restore=restore)

    table = make_table(
        "Panic Protocol Results",
        [("Step", "bold white"), ("Status", ""), ("Details", "dim")],
        [],
    )
    for res in results:
        status_str = "[success]✓ OK[/success]" if res["ok"] else "[error]✗ Failed[/error]"
        table.add_row(res["step"], status_str, res["detail"])

    console.print(table)
    console.print("\\n[bold green]✓ EMERGENCY PANIC ACTION COMPLETE. SYSTEM SECURED.[/bold green]")"""

if old_func in code:
    code = code.replace(old_func, new_func)
    with open("blackoutkit/cli.py", "w") as f:
        f.write(code)
    print("Updated cmd_panic in blackoutkit/cli.py")
else:
    print("Could not match exact old_func in blackoutkit/cli.py")
