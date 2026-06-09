# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-06-09
### Security & Hardening
- **Extensive Codebase Audit:** Ran 10 autonomous agents to audit all modules for security, logic, and concurrency bugs.
- **Fixed Path Traversal:** Fixed a critical Zip Slip vulnerability in `updater.py` that allowed rogue updates to escape the project directory.
- **Fixed Silent UAC Failures:** Core network operations (MTU, DNS) now proactively check for administrator privileges instead of failing silently.
- **Fixed Subprocess Deadlocks:** Redirected standard output to `DEVNULL` across all proxy engines, preventing silent daemon freezes caused by unread OS pipe buffers filling up.
- **Localization Bug Fixes:** Refactored `tools.py` to use `psutil` and `PowerShell` instead of scraping hardcoded English strings from `netsh`/`ipconfig`, ensuring full compatibility with non-English Windows setups.
- **Graceful Shutdowns:** Added `SIGINT`/`SIGTERM` handling to Go proxy wrappers (`xray`, `singbox`). Hard-kills no longer corrupt Windows routing tables or leave system proxy states mangled.
- **Concurrency Safety:** Applied safe file-writing patterns with temporary files and atomic replacements for the `ip_scanner` cache to prevent race conditions during concurrent IP tests.
- **Robust Updates:** Fixed a bug on Windows where update rollbacks would fail due to active Python file locks, corrupting the app directory.
- **HTTP Engine Stability:** Fixed body exhaustion and multi-value header mishandling in the Google Apps Script HTTP relay engine.
