# STATUS — FreedomDesk PO (the21th)

_Last updated: 2026-11-07 ~10:10 Dubai (PO `freedomdesk-po`)_

## Now
- **GUI launcher shipped** (Petar 2026-11-07 "no terminal"): `freedomdesk` with no args / **FreedomDesk.app** (macOS aarch64, CI artifact, ad-hoc signed) opens a machine list (add/edit/remove, quick connect), first-connect fingerprint check, session in the same window, Disconnect → back. Reviewed by a sub-agent; 9 findings fixed.
- **H1 applied on the21th** (Petar approved 07:35): `freedomdesk.service` (root supervisor → host runs as the console session's uid; identity on a pipe; audit → journald) is **live** on 100.116.143.66:47801, same FP `L4O7-…-VZWO`. Verified now: T2 from the20th, lock screen wakes + is captured + takes input remotely.
  - Pending a **reboot of the21th** (Guardian to schedule — it kills tmux sessions): GDM Xorg greeter + NVIDIA EDID pin take effect then. Then verify greeter/lock after reboot, then the20th.
  - Backup + undo: `/var/backups/freedomdesk-h1/latest`, `sudo scripts/h1-undo.sh`.
- **Petar's 09:44 GUI test: ~1 fps, clicks "dead"** → cause: the21th's TV went to standby ~08:30, no NVIDIA output lit → GNOME repaints ~1×/s (host sent every change). Not the GUI. Fix = H1 EDID pin (applied, needs GDM restart/reboot; blocked by FreedomOffice tests). Commit 73b525a: dark-display warning, per-session stats (fps/kbps/input), adaptive quality on slow links, SetView debounce.
- Mac swap to the v2/GUI build: Guardian.

## Milestones
| M | Goal | State |
|---|------|-------|
| M0–M3 | P0 capture→encode→viewer, crypto, consent, DoS limits | ✅ |
| GUI | Launcher + saved machines + macOS .app | ✅ CI; Petar test 20 Nov |
| **H1** | Xorg greeter, no-monitor EDID, root service | 🔶 the21th applied (reboot pending) → the20th |
| H2–H6 | Session follow w/o reconnect, scoped perms, agent MCP, Wayland, macOS headless | ⏳ SPEC §16 |
| M4 | Join code + autostart (service now covers autostart) | ⏳ |
| I1 / A1–A2 | iPhone viewer, controlling agents (plan only) | 📝 SPEC §17 |
| M5–M10 | Clipboard/files, relay, Mac/Win hosts, HW encode, packaging/crash reporter | ⏳ |

## Decisions (taken)
- One binary; TCP + Noise_XX; postcard; protocol v2.
- Root does no network parsing: service supervisor only; host runs as gdm / the user.
- Keep auto-login; no TOTP for login/lock; Macs: one provisioning visit each; keep v0.1.0-alpha.1, no new tags without OK.
- the20th: no EDID snippet while its TV is off (can't read the TV's own EDID; must not override the TV picture). Reboot/GDM restart only via Guardian.
- OpenH264 from source. ⚠ patent cover only for Cisco's binary — decide before packaging.

## Blocked / needs Petar or Guardian
1. Guardian: schedule a the21th reboot or GDM restart (outbox 20261107-0800). Until then the21th streams ~1 fps whenever its TV is off.
2. the20th H1 after the21th verifies; its GDM restart via Guardian.

## Known gaps
- the20th has no lit output either (TV off, headless metamode): as a host it would also be ~1 fps until a monitor/EDID is pinned.
- Session change (greeter ↔ desktop) drops the viewer; reconnect by hand until H2 (auto-reconnect).
- Windows AltGr / macOS Option characters not forwarded; consent dialog not killed if the viewer leaves.
- .app is not notarised: first launch needs `xattr -dr com.apple.quarantine` or "Open Anyway".

## Notes
- Do not disturb `freedomoffice-claude` or `the21th-claude`.
