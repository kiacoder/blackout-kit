---
name: Bug report
about: Report a reproducible Blackout Kit bug
title: ''
labels: 'bug'
assignees: ''
---

## Summary

Describe the bug in one or two clear sentences.

## Expected behavior

What did you expect to happen?

## Actual behavior

What happened instead?

## Reproduction steps

1. Run command or open feature: `...`
2. Use engine / mode / profile: `...`
3. Observe failure: `...`

## Scope of the failure

Please mark what this bug affects:

- [ ] CLI only
- [ ] GUI only
- [ ] MCP only
- [ ] Local readiness / status / routing output
- [ ] Connection startup
- [ ] Background daemon behavior
- [ ] Crash recovery / `blackout fix`
- [ ] Config or vault storage
- [ ] Packaging / install / runtime assets
- [ ] Documentation / help output

## Environment

- OS:
- Architecture:
- Blackout Kit version:
- Install method: standalone exe / source checkout / wheel / other
- Python version (if applicable):
- Engine used:
- Security mode:
- Country profile (auto or pinned):
- Was admin/root required for this path?

## Local vs remote context

This project distinguishes local behavior from remote reachability. Please tell us which kind of issue this is:

- [ ] Local-only bug (settings, routing UI, readiness, recovery, logs, packaging, etc.)
- [ ] Remote-dependent bug (needs a specific proxy/VPN server or filtered network)
- [ ] Not sure

If remote-dependent, include any non-sensitive context that matters:

- protocol involved (VLESS / Trojan / VMess / Hysteria2 / TUIC / VPN engine / other)
- whether you used a saved config, subscription import, or local-only engine path
- whether the issue happens on every network or only one ISP / location

## Logs / screenshots / terminal output

Paste relevant output from:

- `blackout status`
- `blackout ready <engine>`
- `blackout logs`
- `blackout doctor`

If you include screenshots, make sure they do not reveal secrets.

## Additional notes

Anything else that would help reproduce or narrow the bug?

## Before submitting

- [ ] I checked the current README and guides.
- [ ] I included platform, engine, and install details.
- [ ] I removed secrets, credentials, and subscription URLs from the report.
