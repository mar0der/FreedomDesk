# STATUS — FreedomDesk PO (the21th)

_Last updated: 2026-11-06 ~09:30 Dubai (Guardian bootstrap)_

- Host: the21th (Ubuntu 24.04, x86_64, HP Z4)
- Remote Control: `freedomdesk-po`
- tmux: `freedomdesk-claude`
- Repo: https://github.com/mar0der/FreedomDesk (public, AGPL-3.0)
- Path: `~/Developer/FreedomDesk`

## Now
- Docs bootstrap complete (README, SPEC, LICENSE, CLAUDE.md, STATUS).
- **Next for PO:** read SPEC.md, refine milestones in this file, start **P0 MVP on Linux** (the21th host).

## P0 MVP target
1. Screen capture on Linux (PipeWire / X11 fallback)
2. Encode (OpenH264 software first; VAAPI/NVENC later)
3. Viewer on LAN/Tailscale with mouse+keyboard control
4. Noise/rustls E2E session keys; basic consent prompt on host
5. Two-machine test: the21th host ↔ the20th viewer

## Blocked / notes
- GitHub auth for push lives on Petar’s Mac (`gh` as mar0der); the21th has no `gh` yet. Clone via HTTPS works (public repo).
- Do not disturb `freedomoffice-claude` or `the21th-claude`.
