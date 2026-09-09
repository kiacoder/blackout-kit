# Professional CLI Menu System — Integration Guide

This guide shows how to integrate the new professional CLI navigation system into Blackout Kit's typer_cli.py.

## 📋 New Components

### 1. **cli_navigator.py** — Command discovery & help
- `CLINavigator`: Register commands and groups
- `get_navigator()`: Global navigator instance
- Features:
  - Typo suggestions with `suggest_command()`
  - Interactive command browser
  - Group-specific menus
  - Help system with examples

### 2. **cli_dispatch.py** — Error handling & dispatch
- `ProfessionalCLIGroup`: Error wrapper
- `create_professional_app()`: Enhanced Typer app
- `make_group_callback()`: Group menu callbacks
- Features:
  - User-friendly error messages
  - Command not found suggestions
  - Missing subcommand → interactive menu

### 3. **cli_enhancements.py** — Integration helpers
- `integrate_navigator_into_typer_app()`: Add help commands
- `add_group_callback()`: Setup group menus
- `enhance_typer_error_handling()`: Better errors
- Features:
  - `help` command (interactive or specific)
  - `commands` command (list all)
  - `quickstart` command
  - Typo-tolerant dispatch

---

## 🚀 Integration Steps

### Step 1: Initialize Navigator
In `typer_cli.py`, near the top after imports:

```python
from .cli_navigator import get_navigator
from .cli_dispatch import ProfessionalCLIGroup, create_professional_app
from .cli_enhancements import (
    integrate_navigator_into_typer_app,
    add_group_callback,
    enhance_typer_error_handling,
)

# Create the main app with professional features
app, dispatcher = create_professional_app(
    name="blackout",
    help="Blackout Kit — Universal VPN/proxy bypass utility"
)

# Enable error handling enhancements
enhance_typer_error_handling(app)

# Integrate help system
integrate_navigator_into_typer_app(app, dispatcher)
```

### Step 2: Register Commands
Register all commands with the navigator. Example:

```python
navigator = get_navigator()

# Register top-level commands
navigator.register_command(
    "connect",
    "Start a VPN connection",
    "Connection Management",
    aliases=["c", "start"],
    examples=[
        "blackout connect",
        "blackout connect sni",
        "blackout connect --iran",
    ],
)

navigator.register_command(
    "disconnect",
    "Stop the VPN connection",
    "Connection Management",
    aliases=["d", "stop"],
)

# Register groups with subcommands
navigator.register_group_commands(
    "config",
    "Manage proxy configurations",
    {
        "list": ("Show all configurations", ["blackout config list"]),
        "add": ("Add a new configuration", ["blackout config add"]),
        "remove": ("Remove a configuration", ["blackout config remove 1"]),
        "import": ("Import from subscription", ["blackout config import <url>"]),
    },
)
```

### Step 3: Update Group Callbacks
For each command group (config, tools, settings), update the callback:

**Before:**
```python
@config_app.callback(invoke_without_command=True)
def config_callback(ctx: typer.Context):
    if ctx.invoked_subcommand is not None:
        return
    # Just shows warning or does nothing
    console.print("[warning]Specify a subcommand[/warning]")
```

**After:**
```python
@config_app.callback(invoke_without_command=True)
def config_callback(ctx: typer.Context):
    if ctx.invoked_subcommand is not None:
        return
    
    # Show interactive menu for 'blackout config' with no args
    from .cli_dispatch import make_group_callback
    callback = make_group_callback("config", dispatcher)
    callback(ctx)
```

Or simpler using the helper:
```python
from .cli_enhancements import add_group_callback

add_group_callback(config_app, "config", dispatcher)
```

### Step 4: Enhanced Help Text
Use the SmartHelpFormatter for better help:

```python
from .cli_enhancements import SmartHelpFormatter

@config_app.command("add")
def config_add(
    ctx: typer.Context,
    uri: Optional[str] = typer.Argument(None),
):
    """
    Add a new proxy configuration.
    
    Supports V2Ray protocols: VLESS, VMess, Trojan, Hysteria2
    Can prompt for URI or read from argument/stdin.
    """
    # Implementation...
```

The help text will be auto-enhanced with:
- Related commands (other config subcommands)
- Examples from navigator
- Related groups

---

## ✨ User Experience Flow

### Before (Current)
```
$ blackout config
[warning] Specify a subcommand (list, add, remove, ...)
$ blackout cofig list  # typo
[error] no such command
$ blackout config list --help
(shows generic Typer help, hard to understand)
```

### After (Professional)
```
$ blackout config
  ┌─ Manage proxy configurations ─────────────────────────────┐
  │ add             Add a new proxy configuration              │
  │ list            Show all configurations                    │
  │ remove          Remove a configuration                     │
  │ import          Import from subscription URL               │
  └──────────────────────────────────────────────────────────┘
  
  [User selects "list"]
  ✓ → blackout config list

$ blackout cofig list  # typo
[red]✗ Unknown command: cofig[/red]

[yellow]Did you mean:[/yellow]
  [cyan]blackout config[/cyan]

[dim]Run[/dim] [cyan]blackout commands[/cyan] [dim]for command list[/dim]

$ blackout help config
Manage proxy configurations

Subcommands:
  add      Add a new proxy configuration
  list     Show all configurations
  ...
```

---

## 🎯 Features Implemented

### 1. **Interactive Command Browser**
```bash
$ blackout help
# Shows interactive menu of all commands

$ blackout commands
# Lists all commands by category
```

### 2. **Group Menus**
```bash
$ blackout config
# Opens interactive menu for config subcommands

$ blackout tools
# Opens interactive menu for tools subcommands
```

### 3. **Typo Suggestions**
```bash
$ blackout cofig list
[red]✗ Unknown command: cofig[/red]
[yellow]Did you mean:[/yellow] blackout config
```

### 4. **Comprehensive Help**
```bash
$ blackout help connect
# Shows:
# - Description
# - All examples
# - Related commands
# - Links to subcommands if applicable
```

### 5. **Better Errors**
```bash
$ blackout config add  # missing required args
[red]✗ Missing argument 'uri'[/red]

[yellow]Examples:[/yellow]
  $ blackout config add
  $ blackout config import <url>  # Alternative

[dim]Run[/dim] [cyan]blackout config add --help[/cyan] [dim]for details[/dim]
```

### 6. **Quick Start Guide**
```bash
$ blackout quickstart
# Shows beginner-friendly guide with common commands
```

---

## 📝 Migration Checklist

- [ ] Add imports in typer_cli.py
- [ ] Create professional app with `create_professional_app()`
- [ ] Register all commands with navigator
- [ ] Register all command groups
- [ ] Update group callbacks to use `make_group_callback()`
- [ ] Test interactive menus: `blackout config`
- [ ] Test typo suggestions: `blackout cofig`
- [ ] Test help system: `blackout help`, `blackout help config`
- [ ] Update error messages for common commands
- [ ] Test on Windows Terminal, PowerShell, WSL

---

## 🔧 Customization

### Add Custom Command Category
```python
navigator.register_command(
    "my-custom",
    "Custom command description",
    "Custom Category",
    examples=["blackout my-custom --option value"],
)
```

### Override Error Messages
In `cli_dispatch.py`, add to `HELPFUL_ERRORS`:
```python
HELPFUL_ERRORS = {
    "Your error pattern": "Helpful suggestion here",
}
```

### Customize Group Menu
```python
def custom_group_callback(ctx: typer.Context):
    if ctx.invoked_subcommand is not None:
        return
    
    chosen = dispatcher.navigator.show_group_browser("custom_group")
    if chosen:
        # Custom logic here
        pass
```

---

## 📊 Time Estimate

| Task | Time |
|------|------|
| Integrate navigator into typer_cli.py | 1 hour |
| Register all commands | 1.5 hours |
| Update group callbacks | 1 hour |
| Test on Windows + WSL | 1 hour |
| Polish error messages | 1 hour |
| **Total** | **~5.5 hours** |

---

## 🎉 Result

Your CLI will feel like a professional CLI tool with:
- ✅ Intuitive navigation
- ✅ Discoverable commands
- ✅ Helpful error messages
- ✅ Typo tolerance
- ✅ Interactive menus
- ✅ Comprehensive help system
- ✅ Windows compatible

This brings you to "Claude Code CLI level" 🚀
