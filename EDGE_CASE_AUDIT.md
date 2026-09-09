# 🔴 Edge Case Audit - Biggest Crash Points

**Analysis Date:** 2026-09-09  
**Scope:** Deep dive into what causes crashes, hangs, and silent failures  
**Status:** Prioritized by impact  

---

## 🔴 CRITICAL - Config Loading (Data Loss Risk)

### **Issue #1: Corrupted Configs Silently Return Empty List**
**File:** `blackoutkit/config/manager.py:259-271`  
**Severity:** CRITICAL — User sees empty config list and thinks data was deleted  
**Impact:** HIGH — Affects every user, causes data loss panic

```python
# BEFORE (BROKEN):
def load_configs(path: Path | None = None) -> list[ProxyConfig]:
    # ...
    try:
        return _parse_config_text(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return []  # ← User thinks configs deleted!
```

**What can fail:**
- File corrupted (user edits file manually)
- Permission denied (file ownership changed)
- Disk read error (bad sectors)
- Encoding error
- Parse error in URI

**Current behavior:** Returns `[]` silently  
**User sees:** "You have no configs" (panic!)  
**User reality:** File exists with valid configs, but error hiding issue  

**Fix:** Log error + return special sentinel + alert user

---

### **Issue #2: Save Failures Silently Logged**
**File:** `blackoutkit/config/manager.py:295-298`  
**Severity:** HIGH — Configs not saved but user doesn't know

```python
# CURRENT:
except OSError as e:
    import logging
    logging.error(f"Failed to save proxy configs to {p}: {e}")
    raise
```

**Problem:** Error is logged (good) but only to log file. User doesn't see it.  
**What fails:**
- Disk full
- Permission denied  
- Write to read-only filesystem

**User result:** Thinks configs saved, but they weren't

---

## 🔴 CRITICAL - Network Operations (Hangs)

### **Issue #3: Threat Feed Imports Block Forever**
**File:** `blackoutkit/threat_feeds.py:255, 270`  
**Severity:** CRITICAL — User can't cancel, seems hung  

```python
# CURRENT (has timeout, but...):
response = httpx.get(feed.url, timeout=30, follow_redirects=False)
```

**Actual issue:** 30 seconds is long, but what about:
- DNS resolution that takes 10 minutes
- Firewall-level timeouts
- Proxy that never responds

**Better fix:** Add per-stage timeouts + progress indicator

---

### **Issue #4: DNS Resolution Can Block Forever**
**File:** `blackoutkit/tools.py:1110` (many places)  
**Severity:** HIGH — Intermittent hangs  

```python
# Example:
return socket.gethostbyname(domain)
```

**Protected by:** `socket.setdefaulttimeout(3.0)` at line 1108  
**But:** This is thread-global, can interfere with other operations  

**Risky places:**
- DNS benchmark in tools
- Engine initialization (resolves server IP)
- Network tests

---

## 🟠 HIGH - Daemon/Ownership Races

### **Issue #5: Concurrent Daemon Startup Race**
**File:** `blackoutkit/daemon/ownership.py`  
**Severity:** HIGH — Two daemons claim ownership simultaneously  

**Scenario:**
1. Process A checks ownership → not owned
2. Process B checks ownership → not owned  
3. Both claim it simultaneously
4. Filesystem has undefined behavior (depends on timing)

**Result:** One daemon gets killed, other keeps running but thinks it's not owner

---

### **Issue #6: Stale Ownership Records**
**File:** `blackoutkit/daemon/__init__.py`  
**Severity:** HIGH — Cleanup fails, proxy stays active

**Scenario:**
1. Daemon crashes hard (SIGKILL)
2. Ownership file not cleaned up
3. Next daemon can't start (thinks another owns it)
4. User manually deletes file
5. But proxy system is still active with old PID

---

## 🟠 HIGH - Engine Startup Silent Failures

### **Issue #7: Engine Initialization Failures Not Escalated**
**File:** `blackoutkit/daemon/__init__.py` (engine startup loop)  
**Severity:** HIGH — Daemon keeps retrying, looks hung  

**Scenario:**
1. Engine binary missing
2. Daemon tries to start, fails
3. Retries every 2-60 seconds
4. User sees "reconnecting" but never connects
5. No clear error about what's wrong

**Better:** Escalate after 3 failures with clear diagnosis

---

## 🟠 HIGH - IPC/Socket Issues

### **Issue #8: IPC Port Reuse on Graceful Shutdown**
**File:** `blackoutkit/daemon/__init__.py:334`  
**Severity:** MEDIUM — Port stuck in TIME_WAIT  

```python
with socket.create_connection(("127.0.0.1", port), timeout=2.0) as conn:
    conn.sendall(b"STOP\n")
```

**Problem:** After daemon shuts down, port may be in TIME_WAIT for 30-60 seconds  
**Result:** Next daemon can't bind to port

**Fix:** Set `SO_REUSEADDR` option

---

## 🟡 MEDIUM - File Operations

### **Issue #9: Disk Full vs Permission Errors Not Distinguished**
**File:** Multiple places in tools.py, daemon files  
**Severity:** MEDIUM — User can't fix error  

**Scenario:**
```
Error: Failed to write log file
```

**User doesn't know:** Is it disk full? Permission denied? Read-only fs?

**Fix:** Distinguish error types + provide specific guidance

---

## 📊 Priority Matrix

| Issue | Type | Severity | Impact | Fix Time | Users Affected |
|-------|------|----------|--------|----------|---|
| #1: Config silent fail | Data loss | 🔴 CRITICAL | Very High | **1h** | ALL |
| #2: Save not visible | Data loss | 🔴 CRITICAL | High | **30m** | Some |
| #3: Feed import hang | UX | 🔴 CRITICAL | High | **1.5h** | Many |
| #4: DNS timeout race | Stability | 🟠 HIGH | Medium | **1h** | Some |
| #5: Daemon race | Corruption | 🟠 HIGH | Medium | **2h** | Rare |
| #6: Stale ownership | Stability | 🟠 HIGH | Medium | **1.5h** | Some |
| #7: Engine silent fail | UX | 🟠 HIGH | Medium | **1.5h** | Many |
| #8: IPC port reuse | Stability | 🟡 MEDIUM | Low | **30m** | Rare |
| #9: File error clarity | UX | 🟡 MEDIUM | Low | **1h** | Some |

---

## 🎯 Recommended Fix Order

### **Batch 1 (Data Integrity - 1.5 hours)**
1. ✅ **Config loading error handling** — Stop silent failures
2. ✅ **Save failure visibility** — User sees when save fails

### **Batch 2 (UX/Blocking - 2.5 hours)**
3. **Feed import progress** — Show what's happening
4. **Engine startup clarity** — Tell user what's wrong
5. **Better error messages** — Disk full vs permission

### **Batch 3 (Race Conditions - 3-4 hours)**
6. **Daemon ownership races** — Atomic claims
7. **Stale ownership cleanup** — Force cleanup on startup
8. **IPC port reuse** — SO_REUSEADDR flag

---

## 🚀 Implementation Plan

**Phase B1: Data Integrity (1.5h)**
- [ ] Modify `load_configs()` to log + alert user
- [ ] Add retry logic for transient errors
- [ ] Make save failures visible in UI

**Phase B2: UX Polish (2.5h)**
- [ ] Add progress indicators
- [ ] Better error messages
- [ ] User-facing diagnostics

**Phase B3: Stability Fixes (3-4h)**
- [ ] Fix race conditions
- [ ] Add atomic operations
- [ ] Test under stress

---

**Total Phase B Time: ~7-8 hours to address all critical issues**

