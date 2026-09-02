# Blackout Kit User Guide

This guide is for people who want to **use** Blackout Kit safely and effectively.

If you want to contribute code, package releases, or maintain docs, read [../CONTRIBUTING.md](../CONTRIBUTING.md) instead.

---

## What Blackout Kit does

Blackout Kit is a **network security and bypass toolkit**.

It helps you:

- run locally available bypass engines
- manage saved proxy and VPN configurations
- inspect local readiness before connecting
- apply system-proxy settings for engines that expose a local proxy
- recover from crash leftovers without resetting your whole machine

It does **not** run the remote proxy or VPN servers for you.

That means Blackout Kit can help manage a tunnel path, but your safety still depends on:

- the engine you choose
- the upstream server you trust
- the network you are on
- your device security

---

## Before you start

### Pick the right install path

### Windows users

The easiest path is the packaged executable from the GitHub Releases page.

If you are comfortable with Python and want the source version, you can also clone the repo and run it directly.

### Linux users

Linux support is real, but intentionally narrower.

Blackout Kit on Linux currently supports only:

- `xray`
- `tun`
- `hysteria2`
- `tuic`

Linux does **not** support the Windows SNI path, GoodbyeDPI, the desktop GUI, or the Windows VPN paths.

---

## Installation

## Windows packaged app

1. Download `blackout.exe` from the Releases page.
2. Run it.
3. If Windows asks for permission for specific engines or maintenance actions, review the prompt and allow only what you intend.

## Windows source or package install

The core package installs the Typer CLI, local diagnostics, configuration management, and core runtime dependencies. GUI, packet capture, media, and torrent support are optional:

```cmd
git clone https://github.com/kiacoder/blackout-kit.git
cd blackout-kit
python -m pip install .
blackout version
```

Install only the features you need:

```cmd
python -m pip install .[gui]
python -m pip install .[capture]
python -m pip install .[media]
python -m pip install .[torrent]
python -m pip install .[all]
```

PyPI does not provide the native `python-libtorrent` package for Windows, so `[all]` skips that dependency on Windows; torrent commands remain unavailable until the package is installed in a supported Linux environment. `requirements.txt` is the portable all-feature development and executable-build environment.

The portable development requirements can be installed from any directory:

```cmd
python -m pip install -r C:\path\to\blackout-kit\requirements.txt
```


## Linux source or package install

```bash
python3 -m pip install .
mkdir -p bins
chmod +x bins/blackout-engine
blackout version
```

On Linux, the managed runtime asset must exist in `bins/blackout-engine`. Add `.[capture]` only when packet capture is required; Scapy also needs libpcap on the host.

The core install does not pull in the Windows GUI, Scapy, yt-dlp, or python-libtorrent.

## Optional feature matrix

| Extra | Enables | Additional prerequisite |
|---|---|---|
| `gui` | Windows desktop app and tray support | Windows desktop session |
| `capture` | `tools capture` through Scapy | Npcap on Windows or libpcap on Linux |
| `media` | queued media execution | `yt-dlp` executable from the extra |
| `torrent` | queued torrent execution | `python-libtorrent` and platform support |
| `all` | all optional Python features | platform prerequisites still apply |

A missing optional feature produces an actionable installation message instead of a raw import traceback.

On Linux, the managed runtime asset must exist in `bins/blackout-engine`.

---

## Machine-readable output and shell completion

Supported structured commands accept the global `--json` option:

```cmd
blackout --json version
blackout --json status
blackout --json config validate
blackout --json settings list
```

Successful output has the form `{"schema_version":1,"ok":true,"data":...}`. Errors use the same schema with `ok:false` and an `error` object. Output is compact one-line JSON, omits credentials and raw proxy URIs, and never contains terminal styling. Unsupported delegated commands reject `--json` before they run. Watch/streaming commands use one JSON object per line.

Typer completion is built in:

```cmd
blackout --install-completion
blackout --show-completion
```

The local startup benchmark uses fresh subprocesses and performs no network or system changes:

```cmd
python scripts/benchmark_startup.py --json
```

`blackout doctor` is core-only by default. Add `--include-optional` to inspect Scapy and Npcap/libpcap prerequisites:

```cmd
blackout doctor --include-optional
```

---

---

## First-run checklist

Run these in order.

### 1. Check local health

```cmd
python blackout.py doctor
```

### 2. Inspect runtime status

```cmd
python blackout.py bins
```

### 3. Download what Blackout Kit can install automatically

```cmd
python blackout.py bins download
```

### 4. Add or import a saved config if your engine needs one

```cmd
python blackout.py config add <uri>
```

or

```cmd
python blackout.py config import <url>
```

### 5. See what is locally ready

```cmd
python blackout.py route
```

### 6. Validate one engine without changing anything

```cmd
python blackout.py ready xray
```

### 7. Connect

```cmd
python blackout.py connect
```

---

## How to think about engines

Not every engine works the same way.

### Engines that expose a local proxy

These usually give you a local HTTP or SOCKS port and may set the Windows system proxy:

- `xray`
- `sni`
- `psiphon`
- `warp`
- `tor`
- `mhrv`
- `appsscript`
- `hysteria2`
- `tuic`
- `legend`

### Engines that act at the network level

These do not behave like a simple local HTTP proxy:

- `gdpi`
- `tun`
- `ikev2`
- `wireguard`
- `openvpn`
- `softether`

### Important naming note: `legend`

Blackout Kit uses the word `legend` in **two** places:

- `blackout mode legend` — sets the **security mode**
- `blackout connect legend` or `blackout start legend` — starts a **composite engine stack**

Those are related ideas, but they are not the same command.

---

## Picking an engine

### Use automatic recommendation first

```cmd
python blackout.py route
python blackout.py connect
```

`route` ranks engines using **local** evidence only, such as:

- platform support
- installed runtimes
- saved protocol types
- local health history
- pinned country profile
- current settings

That is useful, but it does **not** mean the remote server will work.

### Use a specific engine when you know what you want

Examples:

```cmd
python blackout.py connect xray
python blackout.py connect gdpi
python blackout.py connect warp
python blackout.py connect tun
```

### Background mode

```cmd
python blackout.py connect xray --background
python blackout.py emergency --background
```

---

## Country profiles

Blackout Kit includes country profiles for:

- Iran
- Russia
- China
- Iraq
- United Kingdom
- United States
- Europe

Use them as **local guidance**, not proof.

### Show current profile

```cmd
python blackout.py country
```

### Pin a profile manually

```cmd
python blackout.py country set IR
python blackout.py country set RU
python blackout.py country set CN
```

### Reset to auto-detection

```cmd
python blackout.py country reset
```

### Iran profile shortcut

```cmd
python blackout.py connect --iran
```

This applies temporary local overrides intended for Iran-specific conditions. It does not guarantee that a given ISP, time window, or upstream server will work.

### Russia transport preset

```cmd
python blackout.py connect --russia
python blackout.py start xray --russia
python blackout.py start hysteria2 --russia
```

This applies temporary local overrides for Russia-focused transport behavior:

- pins the RU country profile for recommendation and hinting
- keeps DNS-over-HTTPS enabled
- disables the Iran-only split-tunnel domain shortcuts
- clears Iran-specific TLS fragmentation overrides
- keeps the saved settings file unchanged, even when running in background mode

Use it when you want a cleaner Russia-oriented starting point for mixed VLESS, Trojan, Hysteria2, or TUIC paths.

---

## Config management

## Keyboard config manager

Run `blackout config` with no subcommand in an interactive terminal to open the keyboard-only config manager. It lets you list safe summaries, add or replace a URI, remove a saved config, import a subscription, export/import setup data, and encrypt or decrypt saved data.

- **↑ / ↓** move through the current menu; **Enter**, **Space**, or **→** select.
- **← / Esc** go back; **Ctrl+C** quits.
- Long config lists use a bounded keyboard viewport that follows the selected row.
- Mouse scrolling and mouse clicks do not select or move anything.
- Raw URIs and credentials are not shown in selectable config labels. Replacing a URI opens an empty editor rather than displaying the old URI.

```cmd
python blackout.py config
python blackout.py config edit
```

## List saved configs

```cmd
python blackout.py config list
```

The explicit command prints the existing safe summary table and does not open an editor.

## Replace one config

```cmd
python blackout.py config replace <number> <uri>
```

This validates the replacement before saving it and rejects duplicate URIs.

## Keyboard settings editor

Run `blackout settings` with no subcommand in an interactive terminal to browse settings by category and edit them with the keyboard. Boolean and enumerated values use menus; text, numbers, and lists use the keyboard editor. Values are validated before they are saved, and supported secret values remain masked.

```cmd
python blackout.py settings
python blackout.py settings edit
```

The explicit `list`, `get`, `set`, and `reset` commands remain available for scripts and automation. In a non-interactive terminal, bare `settings` and `config` print usage instead of waiting for input.

## List settings

```cmd
python blackout.py settings list
```

The explicit command prints all settings without opening an editor.

## Get or set one setting

```cmd
python blackout.py settings get <key>
python blackout.py settings set <key> <value>
```

These explicit forms use the same validation and persistence rules as the keyboard editor.

## Reset settings

```cmd
python blackout.py settings reset
```

Use the keyboard editor's **Reset all settings** action only after its confirmation prompt.

## Add one config

```cmd
python blackout.py config add <uri>
```

The keyboard manager's **Add URI** action uses the same parser and persistence boundary.

## Import a subscription

```cmd
python blackout.py config import <url>
```

The keyboard manager reports counts only and does not display imported credentials.

## Remove one config

```cmd
python blackout.py config remove <n>
```

The keyboard manager requires an explicit keyboard confirmation before removal.

## Protect saved config data

```cmd
python blackout.py config encrypt
python blackout.py config decrypt
```

The keyboard manager exposes these actions with confirmation and preserves the existing machine-bound vault behavior.

## Export or import setup

```cmd
python blackout.py config export
python blackout.py config import-setup <string>
```

The keyboard export screen warns that setup strings are not encrypted. Setup imports are decoded and validated before either configs or settings are written.

---

## Analyze configs locally

```cmd
python blackout.py test
```

`test` is useful for seeing:

- protocol
- transport
- compatibility shape
- saved name/label

It does **not** prove that the remote node is reachable.

---

## Protecting local secrets

Saved proxy URIs and supported VPN secrets can contain credentials.

### Encrypt local storage

```cmd
python blackout.py config encrypt
```

### Restore plaintext on the same machine for recovery

```cmd
python blackout.py config decrypt
```

Important:

- encryption is machine-bound
- it protects data at rest
- it is not a substitute for a clean device
- `decrypt` restores plaintext files, so re-encrypt when you are done

---

## Security modes

## Show current mode

```cmd
python blackout.py mode
```

## Set speed mode

```cmd
python blackout.py mode speed
```

## Set private mode

```cmd
python blackout.py mode private
```

## Set legend mode

```cmd
python blackout.py mode legend
```

### What the modes are for

- **speed** — compatibility-focused local settings
- **private** — randomized XRay fingerprint plus MUX
- **legend** — stricter handling for known-bad **normal TLS** certificates

### What the modes do not guarantee

The modes do **not** guarantee:

- anonymity
- bypass success
- remote trust
- traffic-analysis resistance

### REALITY note

If you use VLESS REALITY, that path uses XRay’s REALITY handshake and configured public key. It is separate from the normal TLS certificate probe logic.

---

## Status and readiness

## Local readiness

```cmd
python blackout.py ready xray
python blackout.py ready tun
```

`ready` checks local state only. It does not contact remote servers as proof of success.

## Status snapshot

```cmd
python blackout.py status
```

## Live watch

```cmd
python blackout.py status --watch
```

Status is useful for:

- daemon state
- active engine
- local port availability
- saved local health history
- system-proxy state

But again, it does not prove that your remote path is actually working end to end.

---

## Split tunnel

Blackout Kit’s `split-tunnel` feature is specifically about **Windows system-proxy bypass patterns**.

It is **not** per-process routing and not Linux route-table management.

### Add a bypass pattern

```cmd
python blackout.py split-tunnel add example.com
python blackout.py split-tunnel add 192.168.1.*
```

### List current patterns

```cmd
python blackout.py split-tunnel list
```

### Remove one pattern

```cmd
python blackout.py split-tunnel remove example.com
```

---

## Network tools

Common examples:

```cmd
python blackout.py tools ping 1.1.1.1
python blackout.py tools dns-bench
python blackout.py tools dns-set cloudflare
python blackout.py tools dns-flush
python blackout.py tools traceroute google.com
python blackout.py tools scan-file C:\\Downloads\\example.exe
python blackout.py tools file-hash C:\\Downloads\\example.exe
python blackout.py tools mac status
python blackout.py tools mac randomize
python blackout.py tools mac restore
python blackout.py tools cert-check example.com
```

These help you debug local conditions, but they are not a substitute for understanding your upstream tunnel path.

### Scan one local file on Windows

```cmd
python blackout.py tools scan-file C:\\Downloads\\example.exe
```

This command accepts one existing regular file and uses the already-installed Windows Defender scanner with remediation disabled. It does not scan folders, download signatures, install or update Defender, change Defender exclusions, or alter firewall, proxy, DNS, routing, or other system security settings. A result is shown as a detection only when Defender's captured output confirms it; otherwise an ambiguous native result stays indeterminate.

### Fingerprint one local file

```cmd
python blackout.py tools file-hash C:\\Downloads\\example.exe
```

This calculates a SHA-256 digest locally for one existing regular file. It reads in bounded chunks and withholds the digest when the file changes during the read. It does not scan for malware, upload the file or its hash, contact VirusTotal or another service, use an API key, or alter any system security or network setting.

### Use a private Wi-Fi MAC on public networks

This Windows-only tool changes a MAC only when you explicitly ask it to. It selects the active physical Wi-Fi adapter by default.

```cmd
python blackout.py tools mac status
python blackout.py tools mac randomize
python blackout.py tools mac restore
```

`randomize` makes a fresh locally administered, unicast address every time unless you set `mac_custom_private_address`. The command shows the adapter and target address, then asks for confirmation because Wi-Fi disconnects briefly while that one adapter restarts. In scripts or other non-interactive use, add `--force`; it skips only the confirmation, not safety checks.

```cmd
python blackout.py tools mac randomize --adapter "Wi-Fi" --force
python blackout.py settings set mac_randomization_prefix 06
python blackout.py settings set mac_custom_private_address 02:AA:BB:CC:DD:EE
```

`mac_preferred_adapter` can choose a default adapter when more than one physical Wi-Fi adapter is active. Prefixes and custom MACs must be locally administered and unicast, so the tool will not use a vendor identity or a multicast address.

Before the first change, Blackout Kit saves the prior `NetworkAddress` driver override. `restore` puts that exact setting back; if no override existed, it removes only the override so Windows returns to the adapter's hardware default. It does not automatically rotate addresses and never changes DNS, firewall, proxy, routes, VPNs, or another adapter. A driver that does not support software MAC overrides will be reported instead of treated as a success.

---

## Recovery after crashes

If Blackout Kit crashes and leaves your networking in a bad state, stop the daemon first and then run targeted repair.

```cmd
python blackout.py stop
python blackout.py fix
```

### Preview without changing anything

```cmd
python blackout.py fix --preview
```

### Show recovery history

```cmd
python blackout.py fix --history
```

### Explicit ARP flush

```cmd
python blackout.py fix --flush-arp
```

Use ARP flushing only when you mean it. It is intentionally not part of normal automatic recovery.

### Windows emergency-only resets

```cmd
python blackout.py fix --full-route-reset
python blackout.py fix --full-stack-reset
```

These are broader and more disruptive. Use them only after targeted repair fails.

---

## Kill switch

### Linux only

The supported kill switch is Linux-only.

```bash
sudo python3 blackout.py killswitch on
sudo python3 blackout.py killswitch off
sudo python3 blackout.py killswitch test
```

### Windows users

The old Windows Firewall kill-switch design is intentionally not supported. Blackout Kit removes those legacy rules instead of pretending they are safe.

---

## GUI and MCP

## Zero-argument terminal launcher

Running `blackout` with no arguments opens a keyboard-navigable terminal chooser: **Terminal CLI**, **Windows App**, or **Exit**.

- **↑ / ↓** move the selection; **Space**, **Enter**, or **→** select it; **←** or **Esc** go back; **Ctrl+C** quits.
- A control legend is always visible at the bottom of the menu.
- **Terminal CLI** opens the arrow-key-navigable action menu (Connect, Engine, Status, Tools, Settings, …). Backing out of it (Left/Escape) returns to this chooser rather than exiting.
- **Windows App** opens the desktop GUI described below; it is only offered on Windows.

## Start the GUI

```cmd
python blackout.py gui
```

The GUI is Windows-only. It is also reachable as the **Windows App** option in the zero-argument terminal chooser above.

## Start the MCP server

```cmd
python blackout.py mcp
```

The MCP server exposes a constrained set of local tools. It can still change local state depending on what the client asks it to do.

---

## Troubleshooting

## `connect` fails immediately

Run:

```cmd
python blackout.py doctor
python blackout.py ready <engine>
python blackout.py route
```

## A binary is missing

Run:

```cmd
python blackout.py bins
python blackout.py bins download
```

## System proxy seems stuck

Run:

```cmd
python blackout.py stop
python blackout.py status
python blackout.py fix
```

## Linux `tun` will not start

Check all of these:

- `sudo` permissions
- `bins/blackout-engine`
- `iproute2`
- nftables or iptables availability
- a compatible saved upstream config

## LEGEND mode rejects a certificate

Run:

```cmd
python blackout.py tools cert-check example.com
python blackout.py tools cert-check example.com --allow
```

This is for normal TLS certificate handling, not REALITY.

## Website opens but video playback fails with GoodbyeDPI

That can happen when the site shell works over TCP but the media stream prefers QUIC/UDP.

GoodbyeDPI is a TCP-oriented path, so browser-side QUIC can bypass it and hit the filtered network directly. If this happens, test with QUIC disabled in the browser.

---

## Best habits

- Run `doctor` after first install
- Run `route` before guessing
- Use `ready` when debugging a specific engine
- Encrypt saved configs when you are done editing them
- Treat upstream server trust as your responsibility
- Prefer targeted `fix` over broad resets
- Keep your claims realistic: a local green check is not the same thing as uncensored internet

---

## Where to go next

- High-level project overview: [../README.md](../README.md)
- Security posture: [../SECURITY.md](../SECURITY.md)
- Contributor and maintainer workflows: [../CONTRIBUTING.md](../CONTRIBUTING.md)
