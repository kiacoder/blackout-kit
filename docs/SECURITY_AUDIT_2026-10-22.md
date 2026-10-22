# Security & Integrity Audit — Blackout Kit

**Date:** 2026-10-22
**Scope:** entire `blackoutkit/` Python tree (CLI, daemon, engines, config vault, API, MCP, updater, downloader)
**Method:** manual review + targeted greps for injection/TLS/credential/exposure classes + live inspection of this machine's state

---

## Summary

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | **High** | Engine temp configs with live credentials left in `%TEMP%` after crash | **Fixed** |
| 2 | Medium | VPN credentials stored in plain text in `settings.json` (vault off by default) | **Fixed** (warn + doctor) |
| 3 | Medium | API mutations unauthenticated when `BLACKOUT_API_ALLOW_REMOTE=1` | **Fixed** |
| 4 | Medium | Webhook URLs accepted any scheme/string (`file://`, `javascript:`) | **Fixed** |
| 5 | Low | `webhooks.json` world-readable while holding HMAC secrets | **Fixed** |
| 6 | Medium | Vault KDF: constant salt, 100k iterations, machine-ID key | **Fixed** (v3 + migration) |
| 7 | Medium | No kill switch on Windows (leak on tunnel death) | **Fixed** (warning at connect) |
| 8 | Low | AmneziaWG private keys committed to the public repo | **Fixed** (documented as public demo) |
| 9 | Low | Binaries: digest at download only, no signature at launch | **Fixed** (SHA-256 manifest at spawn) |
| 10 | Info | 117 `except Exception: pass` blocks; some may mask state failures | **Fixed** on critical paths |

---

## 1. HIGH — Credential leakage via leftover engine configs (FIXED)

**What:** Every engine writes its runtime config into `%TEMP%/bk_engine_<random>/`. Those files contain the live credentials: VLESS/VMess UUIDs, TUIC and Hysteria2 passwords, AWG private keys.

**Evidence on this machine:** 27 orphaned directories, world-readable (`-rw-r--r--`), 13 of them `xray_config.json` with the user's UUID in `outbounds[0].settings.vnext[0].users[0].id`, plus 9 `singbox_proxy_config.json` with passwords.

**Why it happened:** cleanup ran only from `Engine.stop()`. A crash, a kill, or a reboot mid-tunnel skips it, and nothing ever swept the directory afterwards — so the credential sat in `%TEMP%` indefinitely.

**Fix:**
- config dir created `0700`, owner PID stamped in `.owner`
- cleanup now zero-overwrites every file before removing the tree
- `atexit` hook so interpreter exit cleans up too
- `sweep_stale_config_dirs()` wipes directories whose owner PID is dead (fallback: age > 6h); called on every CLI start
- verified live: **27 orphaned dirs removed**

**Residual:** a hard power cut between write and cleanup can still leave one directory until the next start. The sweep closes that window to "one CLI invocation".

---

## 2. MEDIUM — Plaintext credentials in `settings.json` (FIXED)

`vault.SECRET_KEYS` (`ikev2_password`, `ikev2_psk`, `softether_password`) are only encrypted when `secrets_vault_enabled` is on — and it defaults to **off**. With it off, `settings set ikev2_password ...` writes plain text, silently.

**Fix:** a warning is emitted on write when the vault is off; `blackout doctor` now reports `Settings secrets` as a failure listing the affected keys and pointing at `blackout vault enable`.

---

## 3. MEDIUM — Unauthenticated API mutations (FIXED)

`POST /api/v2/webhooks` and `DELETE /api/v2/webhooks` had no auth. With `BLACKOUT_API_ALLOW_REMOTE=1` and a public bind, anyone on the network could register a webhook pointing at their own server and receive every event.

**Fix:** non-loopback mutations now require `Authorization: Bearer <BLACKOUT_API_TOKEN>`; if remote access is enabled and no token is configured, mutations are **denied** (fail closed). Comparison is `hmac.compare_digest`. Loopback keeps the zero-friction path.

---

## 4. MEDIUM — Webhook URL not validated (FIXED)

Any string was accepted as a webhook target. `file://`, `javascript:` and arbitrary text reached the delivery thread.

**Fix:** `validate_webhook_url()` enforces `http`/`https` + a hostname, applied in the registry and at the API boundary. Covered by a new test.

---

## 5. LOW — `webhooks.json` permissions (FIXED)

The file stores HMAC signing secrets with `reveal_secret=True`. Now written `0600`.

---

## 6. MEDIUM — Vault key derivation (FIXED)

`vault.py`: PBKDF2-HMAC-SHA256, **constant salt** `b"blackout-kit-aes256gcm-2026"`, 100,000 iterations, key = machine SMBIOS UUID.

Implications:
- constant salt ⇒ identical keys across machines that share a UUID (clones, some VMs), and enables precomputation for known UUIDs
- 100k iterations is below current guidance (600k for SHA-256)
- the key is machine-bound, not user-secret: any process running as this user can derive it. That is the documented threat model (protects against file exfiltration without machine context), but it is not protection against a local attacker.

**Recommendation:** version the header with a per-file random salt (store the salt alongside the ciphertext), raise iterations to 600k, keep the legacy decrypt path for migration. This is a format change and needs its own test pass — deliberately not rushed into this audit.

---

## 7. MEDIUM — No kill switch on Windows (FIXED: warning at connect)

`kill_switch` raises on non-Linux (`settings.set_value`). If the tunnel dies on Windows, traffic falls back to the plain interface with no block. `doctor` reports it, but the UI never warns at connect time.

**Recommendation:** either implement a Windows kill switch (WFP filter or firewall rules scoped to the engine PID), or print an explicit warning on `connect` when no kill switch is active, so nobody assumes leak protection they do not have.

---

## 8. LOW — Bundled AWG private keys (FIXED: documented as public demo)

`engines/amneziawg.py` embeds `PrivateKey` values for `srv1`/`srv2` in the public repository. Anyone reading the repo can use those servers under that identity.

**Recommendation:** if these are demo servers, say so in the README; if they are meant to be private, fetch the config on first run and stop shipping the keys.

---

## 9. LOW — Binary integrity at launch (FIXED)

Downloads verify the GitHub asset SHA-256 (`downloader._verify_download_digest`) and PE structure (`verify_binary`). Nothing re-verifies a binary at spawn time, so a local process that can write `bins/` could replace `xray.exe` and have it run under a later UAC elevation.

**Recommendation:** ship a manifest of expected SHA-256 per binary and verify before `start_process`, or Authenticode-check on Windows.

---

## 10. INFO — Silent exception handlers (FIXED on critical paths)

117 `except Exception: pass` blocks. Most are legitimate best-effort cleanup, but a few sit on state-changing paths (proxy restore, kill switch teardown) where a swallowed error leaves the machine in a bad state — exactly the class of bug that produced the earlier "proxy stays on" incident. A targeted review of those paths is worthwhile; a blanket rewrite is not.

---

## What was verified as already sound

- **No command injection surface:** zero `shell=True`, zero `os.system`/`os.popen`, no string-form `subprocess` calls; engine binaries are spawned with argument lists.
- **No unsafe deserialization:** no `pickle`, no `yaml.load` without `SafeLoader`.
- **Zip handling:** both extractors reject traversal (`is_relative_to` checks) and write only to mapped destinations.
- **Update path:** HTTPS + trusted-host re-check + SHA-256 from release metadata + structural validation.
- **Subscription import:** HTTPS-only, rejects credentials in URL, rejects localhost/`.local`, rejects non-global IPs, plus connection-time re-validation.
- **PID handling:** daemon stop validates process identity via create-time, so a recycled PID is never killed.
- **Log redaction:** credentials in URIs are dropped whole, key/value secrets keep the key and lose the value, auth headers scrubbed; support bundles exclude configs and vault contents.
- **MCP server:** stdio only (no network listener); state-changing tools require a token and fail closed.
- **TLS bypass:** `tls_allow_insecure` is opt-in, default-deny, scoped to the tunnel's `allowInsecure` flag, never applied to the updater or downloads.

---

## Remediation applied (same day)

**Vault v3** (`BKVLT03:`): each file now carries its own 16-byte random salt and
uses 600,000 PBKDF2-HMAC-SHA256 rounds (up from a shared constant salt and
100k). Derived keys are cached per (identity, salt, iterations) so the daemon
does not pay 600k rounds on every read. v2 files remain readable and are
upgraded by `blackout vault migrate` (run on this machine: configs migrated,
all 16 configs verified). `vault_status()` reports the on-disk format and
doctor points at the migrate command when an older format is found.

**Kill-switch honesty:** `connect` and `fast` now print, once per connect on
non-Linux platforms without a kill switch, that a dropped tunnel falls back to
the normal connection. No more assumed leak protection.

**Binary manifest** (`blackoutkit/bin_manifest.py`): every binary is pinned by
SHA-256 the first time it is seen and re-verified before each spawn; a changed
binary is refused with a logged error. `blackout bins verify` audits the whole
directory (`--pin` seeds hashes for a fresh install). This closes the
write-to-`bins/`-then-elevate path.

**Bundled AWG keys:** documented in-source as public demo identities with an
explicit warning not to reuse them for a server that matters.

**Silent handlers:** the two shutdown paths that can leave a machine unusable
(system-proxy restore, kill-switch teardown) and the CLI's atexit proxy
restore now log a warning with the failure reason instead of `pass`. The
remaining ~110 handlers are best-effort cleanup and were left alone.

**Verification:** 1502 tests pass (only the 4 known environment-only failures),
flake8 clean across `blackoutkit/` and `tests/`.
