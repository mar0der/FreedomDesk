# STATUS — FreedomDesk PO (the21th)

_Last updated: 2026-11-07 ~01:10 Dubai (PO `freedomdesk-po`)_

## Now
- **Protocol v2 shipped to main (149e296)** for Petar's Mac feedback:
  - **Cursor lag fixed**: pointer drawn by the viewer at the local mouse position (instant); host pointer sent on its own channel. Loopback: old input→video-cursor median 56 ms vs host-pointer echo 17 ms.
  - **Viewer zoom**: Fit / 1:1 (HiDPI-aware) / Ctrl+Alt+scroll, pinch, Ctrl+Alt + `= - 0 1` / arrows, edge-pan, hover toolbar. Host crops the 4K capture to the visible region → zoomed text is native resolution.
- **Host on the21th runs v2** (`~/.local/bin/freedomdesk host --bind 100.116.143.66 --port 47801`, FP `L4O7-LFLS-PTVE-HW7U-RR6P-VZWO`). T2 re-passed with v2 (the20th `/tmp/freedomdesk-t2`). **Mac viewer must be swapped to the v2 CI artifact** (old v1 binary is refused: protocol mismatch).
- Petar's Mac test of v1: works (T3 ✅ basic). Re-test v2 for lag + zoom.
- Next: H1 (headless + greeter/lock) — **needs Petar's OK for system changes** (see Blocked).

## Milestones
| M | Goal | State |
|---|------|-------|
| M0–M1 | Docs, capture→encode→decode | ✅ |
| M2 | Networked P0 (the21th ↔ the20th/Mac) | ✅ T2 headless, T3 Mac GUI by Petar; v2 retest pending |
| M3 | Crypto, consent, IDs, DoS limits | ✅ (glass-to-glass number still to measure on Tailscale) |
| **H1–H6** | Headless, greeter/lock, root daemon, scoped perms, **agent access (MCP)**, Wayland, macOS headless — SPEC §16, `docs/design/headless-login-agents.md` | ⏳ next, in that order |
| M4 | Join code + systemd autostart (folds into H2) | ⏳ |
| M5–M10 | Clipboard/files/multi-monitor, relay, macOS/Win hosts, HW encode/audio, mobile/2FA, packaging/crash reporter | ⏳ |

## Decisions (taken)
- One binary; TCP + Noise_XX; postcard; protocol v2 (Video has region; cursor channel; SetView).
- X11 first; Wayland via H5 spike before any box moves to 26.04.
- Viewer holds only modifiers on host, taps other keys; macOS Cmd → Ctrl; Ctrl+Alt(+Option) = viewer hotkeys.
- Host binds Tailscale IP only; unattended via `authorized_viewers` (re-read per connection).
- OpenH264 from source. ⚠ patent cover only for Cisco's binary — decide before packaging.

## Blocked / needs Petar
1. **H1 system changes on the21th + the20th** (all reversible, system-wide): GDM `WaylandEnable=false`, NVIDIA xorg.conf.d fixed-mode/EDID snippet, root systemd service. OK to proceed? Also: keep auto-login? Should `login` scope need a second factor?
2. **Release `v0.1.0-alpha.1`** was published on 2026-11-06 (before the "no release without OK" note). Keep it or delete it? No new tags will be made without OK.
3. Macs: one provisioning visit per Mac vs self-hosted MDM (TCC can't be granted remotely) — decide before H6.

## Known gaps
- Windows AltGr / macOS Option characters not forwarded; Ctrl+Alt+F-key can VT-switch the host.
- Consent dialog not killed if the viewer disconnects mid-prompt.
- Full-4K→1600×900 convert 11 ms (powersave governor); fine at 30 fps.

## Notes
- Do not disturb `freedomoffice-claude` or `the21th-claude`.
