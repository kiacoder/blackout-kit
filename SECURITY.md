# Security Policy

Blackout Kit is a network security and bypass toolkit that can affect user privacy, device networking, and trust decisions about upstream servers. Its security model matters because incorrect claims or unsafe local behavior can put users at risk.

This document describes the **current** security posture of the shipped codebase.

---

## Supported versions

| Version line | Status |
|---|---|
| 1.1.x | Active support |
| 1.0.x | Security patches only |
| < 1.0 | Unsupported |

Only the latest minor release receives full updates. Critical fixes may be backported to the previous minor for a limited window.

---

## Scope of protection

Blackout Kit is a **local coordinator**. It orchestrates local runtimes, settings, recovery, and trust decisions around saved proxy or VPN configurations.

It is **not**:

- an anonymity system
- a hosted VPN service
- a guarantee against DPI, probing, or blocking
- a guarantee that a country profile or mode will work on a given network
- a replacement for endpoint security on a compromised machine

### What Blackout Kit does control

- local runtime startup and shutdown
- local port exposure for engines that provide HTTP or SOCKS listeners
- local settings validation
- local encrypted storage of saved proxy URIs and supported VPN secrets
- local readiness checks that avoid contacting remote hosts
- targeted cleanup of Blackout-owned network state after crashes
- Linux endpoint-scoped firewall protection when enabled and valid

### What Blackout Kit does not control

- remote VPN or proxy server integrity
- upstream operator trustworthiness
- destination-side tracking or fingerprinting
- network conditions outside the local machine
- traffic-analysis resistance
- physical or malware compromise of the device

---

## Threat model

Blackout Kit assumes adversaries can vary from ordinary ISP filtering to stronger national filtering systems.

| Adversary | Expected capability | Relevant Blackout Kit defenses |
|---|---|---|
| ISP / ordinary DPI | SNI filtering, destination blocking, DNS interference, simple protocol classification | Local engine selection, configured proxy transports, optional DoH bootstrap, targeted local recovery |
| National firewall | Active probing, IP blacklisting, transport classification, dynamic filtering | Compatible local XRay/TUN paths, compatible user-supplied upstream configuration, country-aware guidance |
| Local network admin | DNS poisoning, policy filtering, local throttling, basic monitoring | Encrypted upstream transports when configured, optional Linux kill switch, local system-proxy and TUN control |
| Passive eavesdropper | Metadata observation, timing observation, endpoint correlation | Only what the selected upstream transport actually provides |

### Explicitly out of scope

Blackout Kit does not claim protection against:

- physical access to the device
- keyloggers or local malware
- large-scale traffic-correlation attacks
- compromise of the upstream server operator
- legal coercion
- a privileged local adversary that can alter kernel or firewall behavior

---

## Platform security boundaries

### Windows

Windows is the broadest product surface, but some historical ideas are now intentionally retired.

Current Windows security facts:

- the Windows engine catalog is broad
- some engines or maintenance actions require elevation
- the system proxy is used only when an engine exposes a local proxy endpoint and `auto_set_proxy` is enabled
- the desktop GUI and Windows system-proxy bypass rules are Windows-only features
- the old Windows Firewall kill-switch approach is **not** treated as supported protection and its legacy rules are removed rather than documented as safe

### Linux

Linux has a smaller runtime surface but the **verified kill-switch implementation** lives here.

Current Linux security facts:

- supported engines are limited to `xray`, `tun`, `hysteria2`, and `tuic`
- TUN and firewall operations require `sudo`
- the supported kill switch is endpoint-scoped and Blackout-owned
- cleanup removes only Blackout-owned firewall, tunnel, and routing state rather than resetting the whole system

---

## Security modes

Blackout Kit exposes three local security modes:

- `speed`
- `private`
- `legend`

These are **local configuration presets**, not threat-model guarantees.

### What they actually change

The mode system currently adjusts local XRay and legacy-GDPI behavior, such as:

- XRay fingerprint selection
- XRay MUX enablement
- handling of known-bad **normal TLS** certificates
- legacy GDPI flags

### What they do not guarantee

The mode system does not guarantee:

- anonymity
- anti-fingerprinting success
- remote server trust
- multi-hop privacy
- that a blocked network will become reachable

### REALITY boundary

VLESS REALITY is handled by XRay’s configured REALITY handshake and public key validation. It does **not** use the normal TLS certificate probe and policy path used for ordinary TLS streams.

---

## Kill switch policy

### Supported implementation

The only supported kill switch is the **Linux endpoint-scoped firewall kill switch**.

It:

- uses a Blackout Kit-owned firewall table/rule set
- allows only loopback, LAN/DHCP, the managed tunnel path, and the validated upstream endpoint
- refuses activation if it cannot establish a safe endpoint allowlist
- cleans up only the Blackout-owned firewall objects

### Unsupported implementation

The old Windows kill-switch idea is intentionally **not** supported.

Reason: Windows Firewall block rules override the per-process allow rules the design would depend on. Rather than pretending that setup is protective, Blackout Kit removes the legacy rules and documents Windows kill-switch support as unavailable.

---

## Readiness and status boundaries

Blackout Kit includes local-only readiness and status features. These are useful, but their limits matter.

### `blackout ready`

`blackout ready` checks only local state such as:

- saved settings
- encrypted storage health
- platform support
- installed runtimes
- loopback port conflicts
- saved proxy protocol compatibility
- daemon ownership

It does **not**:

- resolve remote reachability as proof of success
- contact upstream nodes to validate the tunnel
- download runtimes
- mutate settings or networking
- guarantee that a later connection attempt will work

### `blackout status`

`blackout status` reads daemon state, local proxy state, local ports, and saved health history. It does not prove that the user’s internet traffic is successfully flowing through the selected upstream service.

---

## Recovery and repair boundaries

Blackout Kit intentionally distinguishes **targeted recovery** from **broad reset**.

### Default targeted recovery

The default `blackout fix` / `blackout tools netfix` path aims to repair only Blackout-owned or clearly stale local state.

Examples include:

- stale Blackout system-proxy settings
- stale Blackout-owned routes
- loopback-DNS leftovers on physical adapters
- unhealthy deterministic `BlackoutKit-TUN` state
- DNS cache flushes
- Linux removal of Blackout-owned firewall and tunnel objects

### Broader resets

Windows-only full reset flags remain explicit and opt-in because they can disrupt unrelated system networking.

That distinction is part of the security design: avoid destructive cleanup unless the user asks for it.

---

## Local encrypted storage

Blackout Kit supports machine-bound authenticated encrypted storage.

### What is protected

Current code protects:

- saved proxy configuration URIs
- supported IKEv2/L2TP secrets
- supported SoftEther secrets

### Important properties

- encryption is **machine-bound**
- it protects data **at rest** on the local machine
- it is not a substitute for host security
- it is not portable by default
- `blackout config decrypt` is a same-machine recovery action that restores plaintext files

### Not a promise of secrecy against compromise

If the device is already compromised, or if the user deliberately decrypts the stored data, local encrypted storage is no longer a meaningful protection boundary.

---

## Supply-chain and build security

### Repo-controlled artifacts

This repository builds and tests:

- the Python package
- the Windows packaged executable
- the Linux managed runtime artifact
- Go dependency graphs used in the managed native components

### Current CI signals

The current GitHub workflows perform:

- Python test runs
- wheel installation smoke tests
- Windows executable smoke tests
- Linux runtime build validation
- distro-level package smoke tests on Debian, Fedora, and Arch containers
- CodeQL analysis for Python and Go

### Important supply-chain limit

Blackout Kit does not build every third-party upstream project from source inside this repository. Some engine paths still depend on downloaded or externally supplied binaries, or on local runtime assets produced elsewhere in the release process.

That means users and maintainers should verify release provenance and runtime assets appropriate to their threat model.

---

## Vulnerability reporting

Do **not** open a public issue for an exploitable security problem in a circumvention tool.

### Preferred channel

Use GitHub private vulnerability reporting:

- [Private vulnerability reporting](https://github.com/kiacoder/blackout-kit/security/advisories/new)

If private reporting is unavailable, contact the maintainer through the GitHub account listed on the project page and avoid posting exploit details publicly.

### What to include

Please include:

- affected version
- platform and install method
- engine or command path involved
- minimal reproduction steps
- expected versus actual behavior
- whether the issue is local-only, remote-triggerable, or requires user interaction
- whether the issue affects trust, privacy, persistence, recovery, or arbitrary code execution

### Response goals

- acknowledgment within 48 hours
- regular status updates while triaging
- fix priority based on user-risk severity
- public disclosure only after a fix window or coordinated disclosure decision

---

## In-scope issue classes

Examples of security-relevant issues for this project include:

- proxy or VPN credential exposure
- broken vault or plaintext-restoration behavior
- kill-switch bypass within the claimed supported Linux scope
- unintended destructive network recovery beyond documented scope
- unsafe local file extraction or overwrite behavior
- trust-boundary failures around TLS or REALITY handling claims
- sensitive data exposure through terminal or MCP output
- supply-chain verification or runtime integrity failures within project-controlled logic

Examples that are usually **not** in scope for this repo include:

- theoretical bypass claims without a concrete repro
- upstream vulnerabilities in third-party engines that Blackout Kit does not own
- denial-of-service reports that do not create a meaningful privacy or trust failure
- generic “a blocked site is still blocked” reports without a product defect

---

## Guidance for maintainers and writers

When describing Blackout Kit publicly:

Do **not** claim that it is:

- universally safe
- anonymous
- undetectable
- more private than another product without current evidence
- guaranteed to work in a country because a profile exists

Do describe it as:

- a local coordinator for bypass engines and user-supplied upstream configurations
- a Windows-first toolkit with a narrower Linux support scope
- a product that distinguishes local readiness from actual remote reachability
- a tool with a documented, bounded Linux kill switch and targeted recovery model

---

## Hall of thanks

Responsible reporters who help improve user safety are appreciated. If a report leads to a confirmed fix and the reporter wants credit, they can be acknowledged in the related advisory.
