# V2RayN-Style Mixed Proxy Design

**Status:** Approved for Stage 1 design

## Goal

Add an opt-in V2RayN-style HTTP+SOCKS mixed inbound to Blackout Kit's Xray path while preserving the existing HTTP and SOCKS listeners and keeping HTTP system proxy behavior as the default.

## Current behavior

- Xray creates a SOCKS inbound at `xray_socks_port` (default `10808`) and an HTTP inbound at `xray_http_port` (default `10809`).
- `settings.get_engine_proxy_details()` selects the HTTP inbound for `xray`, `sni`, and `legend` system-proxy setup.
- V2RayN uses Xray's `mixed` inbound at its local proxy port for Windows system-proxy mode. Xray Core dispatches SOCKS greetings as SOCKS and other first bytes to its HTTP handler.
- A temporary mixed-inbound test against the user's Google case did not resolve Chrome loading failure. This feature provides compatibility; it must not be represented as a confirmed fix for that issue.

## Approved behavior

Add a selectable `xray_system_proxy_mode` setting with the choices `http` and `mixed`:

- Default to `http` to preserve current behavior.
- In `http` mode, retain the existing SOCKS inbound at `xray_socks_port` and HTTP inbound at `xray_http_port`. Keep the Windows system proxy pointed to the HTTP inbound.
- In `mixed` mode, change the existing `xray_socks_port` inbound from `socks` to `mixed`, and retain the existing HTTP inbound on `xray_http_port`. Point the Windows system proxy at the mixed inbound using the plain `127.0.0.1:<xray_socks_port>` system-proxy endpoint, matching V2RayN's Windows behavior. Do not label this endpoint `socks=`; the mixed inbound itself detects HTTP versus SOCKS from the client's first bytes.
- Preserve the listener addresses (`127.0.0.1`), current sniffing settings, upstream routing, TLS behavior, port defaults, and proxy ownership/restore semantics.
- Do not add a third listener, silently move a port, replace the existing HTTP listener, or change the default mode.
- Apply the mode consistently to direct Xray connections and composite stacks that include Xray (`sni` and `legend`), using the same settings source already used to generate Xray config and choose the engine proxy endpoint.
- Keep the TUN engine a separate system-networking path. TUN safety/readiness changes are a separate design and implementation stage.

## Configuration interface

- Setting key: `xray_system_proxy_mode`
- Type: string enum
- Valid values: `http`, `mixed`
- Default: `http`
- Expose it through the existing settings grouping, descriptions, and choice validation so users can discover and set it with Blackout's current settings commands.
- Existing settings files that omit the key must continue to behave exactly as `http` mode.

## Compatibility and error behavior

- `http` remains the backward-compatible behavior for existing installs.
- `mixed` uses the existing SOCKS port, so readiness must still report that port as required/occupied consistently with the generated config.
- If the mixed listener cannot bind, fail startup through the normal Xray port readiness path; do not fall back silently to HTTP mode because that would make the selected system-proxy mode misleading.
- Proxy cleanup and restoration must continue using existing ownership-aware code; do not clear or overwrite an unrelated proxy.
- Settings validation rejects values other than `http` and `mixed` at the existing settings boundary.

## Test expectations

- Default/missing setting generates the current two inbounds unchanged: SOCKS at `10808`, HTTP at `10809`.
- `mixed` setting generates a mixed inbound at the configured SOCKS port and retains HTTP at the configured HTTP port.
- Both modes preserve loopback-only listeners, current sniffing options, and routing/outbound configuration.
- `get_engine_proxy_details()` returns the existing plain HTTP proxy host/HTTP port in `http` mode and the same plain host with the mixed listener/SOCKS port in `mixed` mode for `xray`, `sni`, and `legend`. The system-proxy registry value remains a single host:port entry; do not prefix it with `socks=`.
- Settings choice validation accepts only the two declared values.
- Readiness checks the ports used by the selected mode without changing existing port-conflict safety.
- Tests assert existing HTTP/SOCKS clients and defaults remain supported; no claim that mixed mode fixes Chrome should be encoded as an expectation.

## Explicit non-goals

- Changing Windows DNS, Chrome policies, ECH, QUIC, TLS fingerprint, fragmentation, sniffing, routing, upstream configuration, or Safe Browsing.
- Making mixed mode the default.
- Removing or renumbering the current HTTP/SOCKS listeners.
- Implementing or changing TUN behavior in Stage 1.
- Starting, stopping, or switching the user's live VPN as part of a config-mode change.
