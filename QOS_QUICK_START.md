# QoS Monitor-Only Quick Start

**Status:** Supported local configuration and inspection.

---

## Supported Boundary

`blackout tools qos` persists and inspects local QoS rule metadata. It supports these rule types:

- **app** — process name metadata
- **protocol** — protocol metadata such as TCP or UDP
- **port** — port metadata
- **interface** — network-interface metadata

Each rule stores a priority from 0 to 100 and an optional rate-limit value in kbps. These values are stored metadata only: they do not prioritize, throttle, measure, or otherwise control live traffic.

Supported modes are:

- `off`
- `monitor`

The command does not activate WinDivert, install or load packet drivers, intercept or modify packets, enforce rates, or change firewall, DNS, proxy, routing, or other system settings.

---

## Create Stored Rules

### App metadata

```bash
blackout tools qos rules add --type app --target chrome.exe --priority 50 --rate-limit 1000 --name chrome_metadata
```

This stores a rule for `chrome.exe` with priority metadata of 50 and rate-limit metadata of 1000 kbps.

### Protocol metadata

```bash
blackout tools qos rules add --type protocol --target TCP --priority 80 --name tcp_metadata
```

### Port metadata

```bash
blackout tools qos rules add --type port --target "22,443" --priority 90 --name admin_ports
```

### Interface metadata

```bash
blackout tools qos rules add --type interface --target wlan0 --priority 40 --name wifi_metadata
```

A `--rate-limit` value of `0` means the rate field is unset.

---

## Inspect and Manage Rules

List stored rules:

```bash
blackout tools qos rules list
```

Disable or re-enable a stored rule:

```bash
blackout tools qos rules disable --id rule_001
```

```bash
blackout tools qos rules enable --id rule_001
```

Remove a stored rule:

```bash
blackout tools qos rules remove --id rule_001
```

---

## Select a Monitoring Mode

Show the current mode:

```bash
blackout tools qos mode
```

Set monitor mode:

```bash
blackout tools qos mode monitor
```

Turn monitor mode off:

```bash
blackout tools qos mode off
```

`monitor` records the selected local mode; it does not start live traffic monitoring or enforcement.

---

## Inspect Placeholder Statistics and Stored Violations

Inspect all stored-rule summaries:

```bash
blackout tools qos stats
```

Inspect one stored rule:

```bash
blackout tools qos stats --id rule_001
```

The RX and TX readings are intentional zero-value placeholders. They are not live throughput measurements and do not prove that a rule is controlling traffic.

View stored violation records:

```bash
blackout tools qos violations --hours 24
```

Violation records are persisted inspection data. They do not indicate packet interception, throttling, or automatic rate enforcement.

---

## Safety Boundary

Use QoS rules to retain and inspect local matching metadata. Do not use this command to validate traffic shaping, bandwidth control, or packet behavior: those capabilities are not part of the supported QoS implementation.

For historical context about an earlier WinDivert investigation, see [WINDIVER_INSTALLATION_LOG.md](WINDIVER_INSTALLATION_LOG.md). It is not setup or operational guidance.
