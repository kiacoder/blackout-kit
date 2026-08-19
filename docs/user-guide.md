# Blackout Kit User Guide

This guide is for people who want to **use** Blackout Kit safely and effectively.

If you want to contribute code, package releases, or maintain docs, read [../CONTRIBUTING.md](../CONTRIBUTING.md) instead.

---

## What Blackout Kit does

Blackout Kit is a **local** censorship-circumvention toolkit.

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

## Windows source install

```cmd
git clone https://github.com/kiacoder/blackout-kit.git
cd blackout-kit
pip install -r requirements.txt
python blackout.py version
```

## Linux source install

```bash
python3 -m pip install -r requirements.txt
mkdir -p bins
chmod +x bins/blackout-engine
python3 blackout.py version
```

On Linux, the managed runtime asset must exist in `bins/blackout-engine`.

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

## List saved configs

```cmd
python blackout.py config list
```

## Add one config

```cmd
python blackout.py config add <uri>
```

## Import a subscription

```cmd
python blackout.py config import <url>
```

## Remove one config

```cmd
python blackout.py config remove <n>
```

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
python blackout.py tools cert-check example.com
```

These help you debug local conditions, but they are not a substitute for understanding your upstream tunnel path.

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

## Start the GUI

```cmd
python blackout.py gui
```

The GUI is Windows-only.

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
