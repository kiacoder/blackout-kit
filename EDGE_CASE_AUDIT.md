# 🔴 Edge Case Audit - Biggest Crash Points

**Analysis Date:** 2026-09-09  
**Scope:** Deep dive into what causes crashes, hangs, and silent failures  
**Status:** ✅ **CLOSED 2026-10-15** — all 9 issues fixed, one struck as obsolete (see the priority matrix)

---

## 🔴 CRITICAL - Config Loading (Data Loss Risk)

### **Issue #1: Corrupted Configs Silently Return Empty List** ✅ FIXED (2026-10-15)
**File:** `blackoutkit/config/manager.py` — `load_configs()`
**Severity:** ~~CRITICAL — User sees empty config list and thinks data was deleted~~ **Resolved**
**Impact:** ~~HIGH — Affects every user, causes data loss panic~~ **Resolved**

**Fix shipped:** `load_configs()` now returns a `ConfigLoadResult` (a `list` subclass)
carrying an `error` message when a non-empty file cannot be read. Every user-facing caller
(`blackout config list`, `blackout test`, `blackout route`, the MCP `blackout_config` tool)
prints the reason; `blackout config import-setup` refuses to run when the current configs are
unreadable, because its rollback path would otherwise write an empty list over configs that
may be intact. Regression tests: `tests/test_config_manager.py` (five load-path tests).
Note: a partially-valid file still parses the good lines — only unreadable files set `error`.

---

### **Issue #2: Save Failures Silently Logged** ✅ FIXED (2026-09-09)
**File:** `blackoutkit/config/manager.py` — `save_configs()`
**Severity:** ~~HIGH — Configs not saved but user doesn't know~~ **Resolved**

**Fix shipped:** `save_configs()` raises `SaveError` with errno-specific detail
(permission denied / disk full / read-only filesystem). Verified 2026-10-15.

---- Permission denied  
- Write to read-only filesystem

**User result:** Thinks configs saved, but they weren't

---

## 🔴 CRITICAL - Network Operations (Hangs)

### **Issue #3: Threat Feed Imports Block Forever** ✅ FIXED (verified 2026-10-15)
**File:** `blackoutkit/threat_feeds.py` — feed fetch
**Severity:** ~~CRITICAL — User can't cancel, seems hung~~ **Resolved**
**Resolution:** Every network read is bounded — `httpx.get(feed.url, timeout=30, follow_redirects=False)`
on both the initial fetch and the redirect. The audit's "what about DNS taking 10 minutes" scenario is
covered because the 30 s timeout is end-to-end (DNS included) and redirects are capped. A hung feed
now fails with a timeout error instead of blocking forever.

---

### **Issue #4: DNS Resolution Can Block Forever** ✅ FIXED (verified 2026-10-15)
**File:** `blackoutkit/tools.py` — `resolve_doh`, `_dns_query`, `_system_resolve`
**Severity:** ~~HIGH — Intermittent hangs~~ **Resolved**
**Resolution:** Every resolution path carries its own finite timeout (`resolve_doh` 5 s,
`_dns_query` / `_system_resolve` 3 s), so the thread-global `setdefaulttimeout` noted in the
original audit is no longer the only guard.

---

## 🟠 HIGH - Daemon/Ownership Races

### **Issue #5: Concurrent Daemon Startup Race** ✅ FIXED (verified 2026-10-15)
**File:** `blackoutkit/daemon/ownership.py` — `acquire_start_lock()`
**Severity:** ~~HIGH — Two daemons claim ownership simultaneously~~ **Resolved**
**Resolution:** The lock now carries process identity (pid + create-time) with a try/retry
pattern: a lock owned by a *live* process is never stolen, a lock owned by a gone process is
reclaimed. TOCTOU is closed by the retry, not by a pre-check.

---

### **Issue #6: Stale Ownership Records** ✅ FIXED (verified 2026-10-15)
**File:** `blackoutkit/daemon/ownership.py` — `cleanup_stale_records()`
**Severity:** ~~HIGH — Cleanup fails, proxy stays active~~ **Resolved**
**Resolution:** `cleanup_stale_records()` removes stale start locks, leases, and PID files by
checking process liveness on startup, so a SIGKILLed daemon's leftovers no longer block the
next start.

---

## 🟠 HIGH - Engine Startup Silent Failures

### **Issue #7: Engine Initialization Failures Not Escalated** ✅ FIXED (2026-10-15)
**File:** `blackoutkit/daemon/__init__.py` (engine startup loop) + `blackoutkit/cli.py` (`_status_panel`)
**Severity:** ~~HIGH — Daemon keeps retrying, looks hung~~ **Resolved**
**Resolution:** From the 3rd consecutive engine failure (`ENGINE_FAILURE_ESCALATE_AFTER`) the
daemon log escalates from WARNING to ERROR with an actionable diagnosis (missing runtime /
blocked upstream / invalid config, with the command that checks each). The user-facing half:
`blackout status` now prints the `last_failure` reason — previously the panel showed only
"Next retry: Ns" with no reason at all — and points at `blackout doctor`.
Regression tests: `tests/test_engine_failure_escalation.py` (6 tests).

---

## 🟠 HIGH - IPC/Socket Issues

### **Issue #8: IPC Port Reuse on Graceful Shutdown** 🗑️ OBSOLETE (verified 2026-10-15)
**File:** ~~`blackoutkit/daemon/__init__.py:334`~~
**Severity:** ~~MEDIUM — Port stuck in TIME_WAIT~~ **No longer applicable**
**Resolution:** The daemon no longer binds any listening socket — `grep` for bind/setsockopt in
`blackoutkit/daemon/` returns nothing. The referenced `create_connection` is a client-side stop
request that uses an ephemeral source port, so TIME_WAIT there cannot block a rebind.
Struck from the open list; kept here for the audit trail.

---

## 🟡 MEDIUM - File Operations

### **Issue #9: Disk Full vs Permission Errors Not Distinguished** ✅ FIXED (verified 2026-10-15)
**File:** `blackoutkit/config/manager.py` — `load_configs()` and `save_configs()`
**Severity:** ~~MEDIUM — User can't fix error~~ **Resolved**
**Resolution:** Both paths branch on errno: 13 (permission denied), 28 (disk full),
30 (read-only filesystem) each produce a distinct, actionable message.

---

## 📊 Priority Matrix — RESOLVED 2026-10-15

All nine issues closed. Verification method noted per row; regression tests where added.

| Issue | Type | Severity | Status | Verified |
|-------|------|----------|--------|----------|
| #1: Config silent fail | Data loss | 🔴 CRITICAL | ✅ Fixed 2026-10-15 — `ConfigLoadResult.error`, surfaced in CLI + MCP; import-setup refuses to roll back from an unreadable file | 2026-10-15 (5 tests) |
| #2: Save not visible | Data loss | 🔴 CRITICAL | ✅ Fixed 2026-09-09 — `SaveError` with errno detail | 2026-10-15 code re-check |
| #3: Feed import hang | UX | 🔴 CRITICAL | ✅ Fixed — `timeout=30` on fetch + redirect | 2026-10-15 code re-check |
| #4: DNS timeout race | Stability | 🟠 HIGH | ✅ Fixed — per-path 3–5 s timeouts | 2026-10-15 code re-check |
| #5: Daemon race | Corruption | 🟠 HIGH | ✅ Fixed — create-time identity + try/retry lock | 2026-10-15 code re-check |
| #6: Stale ownership | Stability | 🟠 HIGH | ✅ Fixed — `cleanup_stale_records()` by liveness | 2026-10-15 code re-check |
| #7: Engine silent fail | UX | 🟠 HIGH | ✅ Fixed 2026-10-15 — ERROR escalation after 3 failures + reason in `blackout status` | 2026-10-15 (6 tests) |
| #8: IPC port reuse | Stability | 🟡 MEDIUM | 🗑️ Obsolete — daemon binds no socket anymore | 2026-10-15 code re-check |
| #9: File error clarity | UX | 🟡 MEDIUM | ✅ Fixed — errno 13/28/30 split on load and save | 2026-10-15 code re-check |

---

## 🎯 Recommended Fix Order — COMPLETE

- **Batch 1 (Data Integrity):** #1 ✅ (2026-10-15) · #2 ✅
- **Batch 2 (UX/Blocking):** #3 ✅ · #7 ✅ (2026-10-15) · #9 ✅
- **Batch 3 (Race Conditions):** #5 ✅ · #6 ✅ · #8 🗑️ obsolete

---

## 🚀 Implementation Plan — COMPLETE

All three phases delivered and verified. This audit is closed; new edge cases belong in a
fresh audit rather than reopening this one.

**Total Phase B Time: ~7-8 hours to address all critical issues** — all nine issues closed
across the 2026-09-09 (Phase B) and 2026-10-15 (escalation + surfacing) sessions.
