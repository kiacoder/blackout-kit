# 🎨 Professional CLI — Visual Walkthrough

## 1️⃣ **Command List** (`blackout commands`)
```
Blackout Kit Commands

Advanced
  fix — Fix detected issues
  killswitch — Configure kill switch
  mode — Switch operation modes
  route — Configure routing rules
  shield — Configure network shield

Connection Management
  connect (c, start) — Start a VPN connection with specified engine
  disconnect (d, stop) — Stop the active VPN connection
  emergency — Emergency disconnect (kill switch)
  status — Show current daemon and VPN status
  stop — Stop the daemon

Groups
  config — Manage proxy configurations
  settings — Configure application settings
  tools — Network diagnostics and utilities

[... more categories ...]
```

---

## 2️⃣ **Help for a Command** (`blackout help connect`)
```
┌──────────────────────────── Blackout Kit — Help ────────────────────────────┐
│                                                                             │
│ blackout connect                                                            │
│ Connect using an explicit engine or the highest locally ready               │
│ recommendation.                                                             │
│                                                                             │
│ Examples:                                                                   │
│   blackout connect                                                          │
│   blackout connect xray                                                     │
│   blackout connect --iran                                                   │
│   blackout connect --russia                                                 │
│                                                                             │
│ [Full help text with examples...]                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3️⃣ **Typo Suggestion** (`blackout cofig list`)
```
Usage: python -m blackoutkit.typer_cli [OPTIONS] COMMAND [ARGS]...
Try 'python -m blackoutkit.typer_cli --help' for help.

┌─ Error ─────────────────────────────────────────────────────────────────────┐
│ No such command 'cofig'. Did you mean 'config'?                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4️⃣ **Quick Start Guide** (`blackout quickstart`)
```
Blackout Kit — Quick Start

Common Commands:

  blackout connect sni           Start VPN with SNI engine
  blackout config list          Show saved proxy configs
  blackout config add           Add a new proxy configuration
  blackout doctor               Run diagnostics
  blackout help                 Show help for any command

Interactive Menus:

Just type the group name to browse interactively:
  blackout config              Browse configurations
  blackout tools               Browse network tools
  blackout settings            Browse settings

Tips:

  • Use --help flag for detailed info on any command
  • Type ? during menus to show help
  • Commands support --json for scripting
  • Press Tab for command auto-completion
```

---

## 5️⃣ **Interactive Group Menu** (`blackout config`) — INTERACTIVE TERMINAL ONLY
```
┌─────────────────────── config — Manage proxy configurations ─────────────────┐
│                                                                              │
│  ↓ list             Show all saved configurations                           │
│    add              Add a new proxy configuration                           │
│    remove           Remove a configuration                                  │
│    import           Import from a subscription URL                          │
│    validate         Check if configs are valid                              │
│    export           Export all configs                                      │
│    replace          Replace a configuration                                 │
│                                                                              │
│ ↑↓ Navigate    Enter Select    Esc Back                                     │
└──────────────────────────────────────────────────────────────────────────────┘

User presses ↓ to move to "add", then Enter:
  → blackout config add
```

**How it works:**
- ↑/↓ arrows = navigate
- Enter = select
- Esc = cancel
- Type to filter options
- Shows descriptions for each command

---

## 6️⃣ **Tools Menu** (`blackout tools`) — INTERACTIVE
```
┌─────────────────── tools — Network diagnostics and utilities ──────────────┐
│                                                                            │
│  ↓ dns-bench        Benchmark DNS servers                                 │
│    dns-flush        Clear DNS cache                                       │
│    dns-set          Set custom DNS                                        │
│    ping             Test reachability                                     │
│    netfix           Run network recovery                                  │
│    hotspot          Toggle mobile hotspot                                 │
│                                                                            │
│ ↑↓ Navigate    Enter Select    Esc Back                                   │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 7️⃣ **Command Browser** (`blackout help`) — INTERACTIVE
```
┌──────────────────────────── Available Commands ────────────────────────────┐
│                                                                            │
│  ↓ capabilities      Show the full engine capability matrix               │
│    connect          Start a VPN connection with specified engine          │
│    demo             Show a read-only simulation                           │
│    disconnect       Stop the active VPN connection                        │
│    doctor           Run diagnostic checks and fix issues                  │
│    emergency        Emergency disconnect (kill switch)                    │
│    fix              Fix detected issues                                   │
│    killswitch       Configure kill switch                                 │
│    logs             Show daemon operation logs                            │
│    mode             Switch operation modes                                │
│    ...more...                                                             │
│                                                                            │
│ ↑↓ Navigate    Enter Select    Esc Exit                                   │
└────────────────────────────────────────────────────────────────────────────┘

User selects "connect" → Shows full help for that command
```

---

## 📊 Design Features

✅ **Color-coded** — Commands in cyan, descriptions in white, errors in red  
✅ **Bordered panels** — Professional box drawing for emphasis  
✅ **Keyboard-driven** — No mouse needed, pure terminal navigation  
✅ **Discoverable** — Press up/down, type to filter, Enter to select  
✅ **Helpful errors** — Typos get suggestions, not just failures  
✅ **Consistent** — Same look across all groups and commands  
✅ **Fast** — No waiting, instant feedback  

---

## 🎯 User Experience Flow

### Beginner (Just installed)
```
$ blackout
$ blackout quickstart        ← Shows common commands
$ blackout help              ← Browse all commands
$ blackout config            ← Pick "add" from menu
$ blackout config add        ← Prompted for URI
```

### Experienced (Knows what to do)
```
$ blackout config list       ← Direct command
$ blackout tools dns-set     ← Direct command
$ blackout status --watch    ← Direct with flags
```

### Power User (Scripting)
```
$ blackout config list --json
$ blackout settings get key --json
$ blackout tools dns-bench --json
```

---

## 🚀 Comparison: Before vs After

### BEFORE (Typer Default)
```
$ blackout cofig list
No such command 'cofig'

$ blackout config
[warning] Specify a subcommand (list, add, remove, ...)
(No interactive help, must remember commands)
```

### AFTER (Professional CLI)
```
$ blackout cofig list
┌─ Error ─────────────────────────────────────────┐
│ No such command 'cofig'.                         │
│ Did you mean 'config'?                          │
└─────────────────────────────────────────────────┘

$ blackout config
[Interactive menu opens with all subcommands]
User can navigate with ↑↓, press Enter to select
```

---

## 📱 Terminal Compatibility

Tested & Working On:
- ✅ Windows PowerShell
- ✅ Windows CMD (legacy)
- ✅ Windows Terminal (modern, recommended)
- ✅ WSL/Ubuntu terminal
- ✅ macOS Terminal
- ✅ VS Code integrated terminal

---

## 💡 Features in Action

### Smart Filtering
```
$ blackout help
User types: "dn"
Filter narrows to:
  dns-bench
  dns-flush
  dns-set
(Type more to refine, Backspace to edit)
```

### Command Aliases
```
$ blackout c              # Same as: blackout connect
$ blackout d              # Same as: blackout disconnect
$ blackout help ?         # Help using alias
```

### Nested Help
```
$ blackout help config add
Shows complete help for 'config add' command with:
  - Full description
  - Examples
  - Related commands
  - Usage tips
```

---

**The result:** A CLI that feels like a professional tool, not a developer utility. Users can discover features without memorizing every command, and typos don't dead-end in cryptic errors. 🎉
