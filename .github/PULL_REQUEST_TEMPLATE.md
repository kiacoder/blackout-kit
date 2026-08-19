## Summary

Describe what changed and why.

## Scope

What does this PR affect?

- [ ] CLI behavior
- [ ] GUI behavior
- [ ] MCP surface
- [ ] Engine/runtime behavior
- [ ] Downloader / runtime assets
- [ ] Config / vault behavior
- [ ] Recovery / `blackout fix`
- [ ] Packaging / release flow
- [ ] Documentation / help text only

## Platform impact

- [ ] Windows
- [ ] Linux
- [ ] Both
- [ ] No runtime/platform impact

## Engine / workflow impact

List the engine(s), protocol(s), or workflow(s) affected.

Examples: `xray`, `tun`, `gdpi`, `warp`, `psiphon`, `hysteria2`, `tuic`, config import, route ranking, readiness, vault, MCP, packaged exe.

## Boundary check

If relevant, explain how this PR preserves the important project boundaries:

- local readiness vs remote success
- targeted recovery vs destructive reset
- Linux-supported kill switch vs unsupported Windows legacy rules
- accurate platform scope
- accurate runtime asset naming and provenance

## Testing

Describe what you tested.

Include concrete commands when possible.

Examples:

- `python blackout.py version`
- `python blackout.py --help`
- `python blackout.py help quick_start`
- `python blackout.py ready xray`
- `python -m pytest --rootdir=. tests`

Also mention whether you tested:

- [ ] foreground CLI
- [ ] background daemon path
- [ ] interactive terminal path
- [ ] non-interactive path
- [ ] Windows-specific path
- [ ] Linux-specific path
- [ ] docs/help output alignment

## Documentation

- [ ] No documentation change needed
- [ ] I updated public docs (`README`, guides, or `SECURITY.md`)
- [ ] I updated in-app help text if command behavior or wording changed

## Screenshots / logs

Add screenshots or sanitized logs if they help explain the change.

## Notes for reviewers

Anything reviewers should pay special attention to?