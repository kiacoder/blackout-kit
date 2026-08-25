# Historical WinDivert Investigation — Superseded

**Recorded:** 2026-08-20
**Current status:** Superseded. This record describes an earlier local WinDivert investigation and is not current operating guidance.

---

## Current Supported QoS Boundary

The supported `blackout tools qos` interface is monitor-only local configuration and inspection:

- persisted app, protocol, port, and interface rule definitions;
- stored priority and optional rate-limit metadata;
- rule matching metadata;
- zero-value placeholder throughput statistics; and
- stored violation viewing.

Supported modes are `off` and `monitor` only.

Current QoS does not activate or use WinDivert, load a packet driver, modify or intercept packets, throttle traffic, apply rate limits, or make firewall, DNS, proxy, or routing changes.

---

## Historical Context

An earlier experiment placed WinDivert files in a local Windows installation and added dormant implementation code in `blackoutkit/daemon/qos_shaper.py`. Earlier notes also recorded that a DLL handle could be opened and closed in that environment.

That experiment is not part of the supported QoS path. The current CLI and QoS module do not start the dormant shaper, trigger driver installation, or provide a mode that enables live traffic control.

---

## Maintainer Note

Do not treat this document as setup, troubleshooting, or operational instructions. Any future packet-control work requires a separately reviewed design, implementation, tests, and explicit authorization.
