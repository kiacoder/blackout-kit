# 🚀 QoS with WinDivert — Quick Start Guide

**Status:** ✅ Production Ready

---

## What Was Just Set Up

1. **WinDivert Kernel Driver** — Installed at `C:\Program Files\WinDivert\`
2. **Python Bindings** — QosShaper daemon can now intercept & shape traffic
3. **CLI Fixed** — Commands now work intuitively (positional args, not flags)
4. **Auto-Installation** — Driver loads automatically on first QoS rule creation

---

## Try It Now! 🎯

### 1. Create a throttling rule for Chrome
```bash
blackout tools qos rules add --type app --target chrome.exe --priority 50 --rate-limit 1000
```
**What this does:** Limits Chrome to 1000 kbps (1 Mbps), priority 50 (neutral)

### 2. Create a gaming priority rule
```bash
blackout tools qos rules add --type app --target valorant.exe --priority 90
```
**What this does:** Gaming gets maximum priority (90/100) with no rate limit

### 3. List all rules
```bash
blackout tools qos rules list
```
**Shows:** Table of all QoS rules with their settings

### 4. Enable enforcement (activates kernel shaping!)
```bash
blackout tools qos mode enforce
```
**Effect:** WinDivert now intercepts and throttles packets in real-time

### 5. Watch stats in real-time
```bash
blackout tools qos stats
```
**Shows:** Current throughput for each rule, violations, priority queue

### 6. Check for violations
```bash
blackout tools qos violations --hours 1
```
**Shows:** Times when rules were exceeded (with enforcement enabled)

---

## Parameter Guide

### Rule Types
- **`--type app`** — Target by process name (chrome.exe, valorant.exe, etc.)
- **`--type protocol`** — Target by protocol (TCP, UDP, ICMP)
- **`--type port`** — Target by port number (80, 443, 22, etc.)
- **`--type interface`** — Target by network interface (eth0, wlan0, etc.)

### Priority Scale
- **0-30** — Background services (Dropbox, Windows Update, Torrent)
- **40-60** — Normal traffic (Web browsing, email)
- **70-90** — Interactive (SSH, RDP, gaming, video calls)
- **100** — Critical (only for emergency protocols)

### Rate Limiting
- **0** (default) — No limit (as much bandwidth as available)
- **100-500** — Heavily throttled (mobile hotspot speed)
- **1000-5000** — Moderate throttle (good for background sync)
- **10000+** — Minimal restriction (fast protocols like SSH)

---

## Real-World Examples

### 📚 Student studying (block YouTube)
```bash
# YouTube only gets 500 kbps (blocks watching, but search still works)
blackout tools qos rules add --type app --target chrome.exe --rate-limit 500 --priority 30 --name "youtube_study_mode"

# SSH/IDE gets priority
blackout tools qos rules add --type protocol --target TCP --rate-limit 0 --priority 90 --name "ssh_code_priority"
```

### 🎮 Gamer with limited bandwidth
```bash
# Game gets full priority
blackout tools qos rules add --type app --target valorant.exe --priority 100 --name "gaming_first"

# Discord voice (high priority but capped)
blackout tools qos rules add --type app --target discord.exe --priority 85 --rate-limit 1000 --name "discord_voice"

# Everything else gets leftovers
blackout tools qos rules add --type app --target chrome.exe --priority 10 --rate-limit 2000 --name "chrome_background"
```

### 🏢 Office (prioritize work, throttle personal)
```bash
# Work email/documents (high priority)
blackout tools qos rules add --type app --target outlook.exe --priority 90 --name "work_email"

# Personal browsing (low priority, capped)
blackout tools qos rules add --type app --target chrome.exe --priority 20 --rate-limit 1000 --name "personal_browsing"

# Video meetings (interactive, needs priority)
blackout tools qos rules add --type app --target zoom.exe --priority 85 --name "zoom_meetings"
```

---

## Troubleshooting

### ❌ "WinDivert.dll not found"
**Solution:** Make sure files are in `C:\Program Files\WinDivert\`
```bash
# Check installation
ls "C:\Program Files\WinDivert"
```

### ❌ "Permission denied" when enabling mode
**Solution:** Run PowerShell as Administrator (WinDivert requires Admin for packet interception)

### ❌ "Rules not being enforced"
**Solution:** Check that mode is set to `enforce`
```bash
blackout tools qos mode         # Shows current mode
blackout tools qos mode enforce # Enable active shaping
```

### ⚠️ "Network is slow after enabling QoS"
**Solution:** Your rules might be too aggressive. Check violations and adjust:
```bash
blackout tools qos violations --hours 1  # See what got throttled
blackout tools qos rules list            # Review all rules
blackout tools qos mode monitor          # Temporarily disable to test
```

---

## Advanced: Filter by Port

### Block large downloads during work hours
```bash
# Torrent/P2P ports (typically 6881-6889, custom ranges)
blackout tools qos rules add --type port --target "6881,6882,6883,6884,6885" --priority 5 --rate-limit 500 --name "torrent_throttle"
```

### Prioritize SSH over HTTP
```bash
# SSH (port 22) gets priority
blackout tools qos rules add --type port --target "22" --priority 90 --rate-limit 0 --name "ssh_priority"

# HTTP/HTTPS (ports 80, 443) normal
blackout tools qos rules add --type port --target "80,443" --priority 50 --rate-limit 0 --name "web_normal"
```

---

## Tips & Best Practices

1. **Start with monitor mode** — Use `blackout tools qos mode monitor` to audit before enforcing
2. **No overlapping rules** — Order matters! More specific rules should have higher priority numbers
3. **Leave headroom** — Don't set total rate limits to 100% of your bandwidth (internet is bursty)
4. **Test with small numbers** — Start with low rate limits, then increase if too restrictive
5. **Disable when not needed** — `blackout tools qos mode off` to turn off completely

---

## What Happens Under the Hood

1. **Rule created** → Saved to `~/.blackout-kit/qos_rules.json`
2. **Mode = enforce** → QosShaper daemon starts WinDivert packet interception
3. **Packet arrives** → WinDivert intercepts it, checks against rules
4. **Rule matched** → Token bucket applies rate limiting (drop or delay)
5. **Over limit?** → Logged to `~/.blackout-kit/qos_violations.jsonl` for tracking
6. **Result** → Packet sent or dropped based on priority & rate limit

---

## Next Steps

- ✅ Create your first rule
- ✅ Test with real traffic (large download)
- ✅ Monitor with `blackout tools qos stats`
- ✅ Adjust priorities based on results
- ✅ Fine-tune rate limits for your network

**Questions?** Check `WINDIVER_INSTALLATION_LOG.md` for technical details! 🎓

---

**System Status:** 🟢 WinDivert ready, QoS active, kernel driver loaded ✅
