# Launch kit — Blackout Kit 1.9.0 (AmneziaWG)

Copy-paste material for announcing the release. Every claim here is backed by the evidence table
in the README — keep it that way. No "unblocks everything" claims.

---

## One-liner

> **AmneziaWG, native and verified.** Obfuscated WireGuard in pure userspace — no TUN, no drivers,
> no admin — with a real handshake measured against a production server.

## Short post (X / Mastodon)

> Blackout Kit 1.9.0 is out — AmneziaWG is now native.
>
> ✅ Obfuscated WireGuard (Jc/Jmin/Jmax, S1–S4, H1–H4) in pure userspace
> ✅ No TUN device, no drivers, no admin rights
> ✅ SOCKS5 :11080 + HTTP :11081 (Windows can't use a SOCKS system proxy — now it doesn't have to)
> ✅ Verified on a live server: handshake, 1.5 MB transferred, YouTube 200
> ✅ 1,523 tests green
>
> github.com/kiacoder/blackout-kit/releases/tag/v1.9.0

## Longer post (Telegram / Reddit)

> **AmneziaWG, native — and actually verified**
>
> Most "AmneziaWG support" is a config generator that hands you a sing-box outbound the runtime
> doesn't have. We built the core instead.
>
> Blackout Kit 1.9.0 ships `awg-go`: a userspace AmneziaWG client that parses your `.conf`
> directly — including every obfuscation parameter — converts the base64 keys the UAPI actually
> wants, terminates the tunnel in an in-process TCP/IP stack, and exposes ordinary proxies.
>
> No TUN adapter. No kernel driver. No administrator prompt. It runs from an ordinary user
> account, which is also why it works on locked-down machines.
>
> **The part nobody else shows you:** the handshake, measured. Production server, fresh
> `latest-handshake`, 1.5 MB transferred, 784 packets on `awg0`. `curl` through the tunnel returns
> the server's IP. YouTube loads in 3.3 s through both SOCKS5 and HTTP.
>
> Two details that took the longest and matter the most:
> 1. UAPI keys are **hex**, `.conf` keys are **base64**. Skip the conversion and you get a silent
>    "failed to set private_key".
> 2. Windows (WinINET) and Chrome **cannot use a SOCKS system proxy**. So the core serves HTTP
>    CONNECT too — that's `awg_http_port`, and it's why the browser finally works.
>
> `blackout start awg -d` → SOCKS5 :11080, HTTP :11081, system proxy set.
>
> 1,523 tests passing. Servers audited and hardened (key-only SSH, fail2ban, default-deny ufw).
>
> Release: github.com/kiacoder/blackout-kit/releases/tag/v1.9.0

## Elevator pitch (README-style)

| | |
|---|---|
| **What** | A native AmneziaWG client inside a 17-engine bypass toolkit |
| **Why it matters** | DPI-resistant obfuscated WireGuard without TUN/drivers/admin |
| **Proof** | Live handshake, 1.5 MB transferred, egress IP = server, YouTube 200 |
| **Cost** | One binary (`awg-go`, ~6 MB, pure Go) |

## Honest caveats (always include)

- AmneziaWG **mobile** bindings compile (`linux/arm64`), but `VpnService` wiring is the next
  milestone — the desktop CLI path is the verified one.
- Obfuscation parameters must match the server exactly; a mismatch produces a silent no-handshake.
- QUIC (UDP/443) cannot cross an HTTP proxy — disable QUIC in Chrome if video stalls.
- Windows/Linux only for the CLI; the WPF desktop app remains a read-only prototype.

## Assets to attach

- Screenshot: `blackout status` showing `System proxy ● Active 127.0.0.1:11081`
- Screenshot: `curl -x http://127.0.0.1:11081 https://api.ipify.org` → server IP
- Terminal capture: `blackout bins` showing "AmneziaWG Core (awg-go) ✓ Installed"
