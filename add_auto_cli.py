with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

auto_cli_code = '''
# ── AUTOMATION GROUP ──
automation_app = typer.Typer(help="Scriptable Event Automation (rules for network events)", no_args_is_help=False)
app.add_typer(automation_app, name="automation")

@automation_app.command("add")
def auto_add(
    name: str = typer.Argument(..., help="Automation rule name"),
    event: str = typer.Option(..., "--event", "-e", help="Event trigger name (e.g. on_network_disconnect, on_dns_tamper)"),
    action: str = typer.Option(..., "--action", "-a", help="Action to run: panic | flush_dns | flush_arp | audit | recovery"),
):
    """Add a scriptable event automation rule."""
    from .tools import save_automation_rule
    if save_automation_rule(name, event, action):
        console.print(f"[success]✓ Automation rule '{name}' saved![/success]")
    else:
        console.print(f"[error]Failed to save automation rule '{name}'[/error]")

@automation_app.command("list")
def auto_list():
    """List configured event automation rules."""
    from .tools import list_automation_rules
    rules = list_automation_rules()
    if not rules:
        console.print("[muted]No automation rules saved. Use `blackout automation add` to create one.[/muted]")
        return
    table = make_table(
        "Event Automation Rules",
        [("Rule Name", "bold cyan"), ("Event Trigger", "bold white"), ("Action", "yellow"), ("Status", "green")],
        [],
    )
    for r in rules:
        status = "Active" if r.get("enabled", True) else "Disabled"
        table.add_row(r["name"], r["event"], r["action"], status)
    console.print(table)

@automation_app.command("trigger")
def auto_trigger(
    event: str = typer.Argument(..., help="Event name to trigger (e.g. on_network_disconnect)"),
):
    """Manually trigger an event to run matching automation actions."""
    from .tools import trigger_automation_event
    results = trigger_automation_event(event)
    if not results:
        console.print(f"[muted]No active automation rules matched event '{event}'.[/muted]")
        return
    for res in results:
        status_str = "[success]✓ OK[/success]" if res["ok"] else "[error]✗ Failed[/error]"
        console.print(f"Rule [bold]{res['rule']}[/bold]: {status_str} -> {res['detail']}")

@automation_app.command("remove")
def auto_remove(
    name: str = typer.Argument(..., help="Automation rule name to remove"),
):
    """Remove an automation rule."""
    from .tools import remove_automation_rule
    if remove_automation_rule(name):
        console.print(f"[success]✓ Removed automation rule '{name}'.[/success]")
    else:
        console.print(f"[error]Automation rule '{name}' not found.[/error]")
'''

if 'automation_app = typer.Typer' not in code:
    code += "\n" + auto_cli_code
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added automation_app to blackoutkit/typer_cli.py")
