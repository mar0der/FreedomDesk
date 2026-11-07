# STATUS — FreedomDesk PO (the21th)

_Last updated: 2026-11-07 ~12:00 Dubai (PO `freedomdesk-po`)_

## Now
- **GUI launcher shipped** (Petar 2026-11-07 "no terminal"): `freedomdesk` with no args / **FreedomDesk.app** (macOS aarch64, CI artifact, ad-hoc signed) opens a machine list (add/edit/remove, quick connect), first-connect fingerprint check, session in the same window, Disconnect → back. Reviewed by a sub-agent; 9 findings fixed.
- **H1 on the21th: done + verified** (GDM restarted by Guardian 11:05, no reboot). Xorg greeter, desktop 1920×1080@60 via the TV's own 1080p EDID pin + NVIDIA `LimitFrameRateWhenHeadless=false` (Guardian's extension; backup ~/Developer/_po/backup-virtualdisplay-20261107-110154). Verified 11:50: 30 changes/s with TV off; service follows console (desktop → greeter → desktop); greeter + lock screen captured and take remote input. Login/unlock with a password from the viewer: Petar to try (no password here). Petar's Mac session 11:32: 1155 input events, 0 failed.
- **H1 on the20th: applied 11:53, GDM restart pending (Guardian)**: WaylandEnable=false, `--headless-unthrottle` (limiter off only, no EDID/mode change: TV keeps its picture), service live on 100.115.64.43:47801, host FP `JSKM-BJCM-CFU6-SOGX-HS7J-PH6U`, authorised: Mac + the21th. Backup /var/backups/freedomdesk-h1/20261107-115305; scripts in the20th:~/freedomdesk-h1.
- Petar's 09:44 1 fps test: cause = NVIDIA headless 1 fps limiter (TV in standby) → fixed on the21th by H1 (above). 73b525a/6cdf075: dark-display warning, per-session stats, adaptive quality, SetView debounce.
- **v0.1.0-alpha.2 published** (pre-release, Petar OK 11:36): tag → 6cdf075, .app zip + CLI tarballs + sha256. Notes via `.github/release-notes/<tag>.md` (workflow `release-notes.yml`).
- Mac swap to the v2/GUI build: Guardian.

## Milestones
| M | Goal | State |
|---|------|-------|
| M0–M3 | P0 capture→encode→viewer, crypto, consent, DoS limits | ✅ |
| GUI | Launcher + saved machines + macOS .app | ✅ CI; Petar test 20 Nov |
| **H1** | Xorg greeter, no-monitor EDID, root service | ✅ the21th · 🔶 the20th (GDM restart pending) |
| H2–H6 | Session follow w/o reconnect, scoped perms, agent MCP, Wayland, macOS headless | ⏳ SPEC §16 |
| M4 | Join code + autostart (service now covers autostart) | ⏳ |
| I1 / A1–A2 | iPhone viewer, controlling agents (plan only) | 📝 SPEC §17 |
| M5–M10 | Clipboard/files, relay, Mac/Win hosts, HW encode, packaging/crash reporter | ⏳ |

## Decisions (taken)
- One binary; TCP + Noise_XX; postcard; protocol v2.
- Root does no network parsing: service supervisor only; host runs as gdm / the user.
- Keep auto-login; no TOTP for login/lock; Macs: one provisioning visit each; alpha.1 + alpha.2 pre-releases kept; no new tags without OK.
- the20th: no EDID snippet while its TV is off (can't read the TV's own EDID; must not override the TV picture). Reboot/GDM restart only via Guardian.
- OpenH264 from source. ⚠ patent cover only for Cisco's binary — decide before packaging.

## Blocked / needs Petar or Guardian
1. Guardian: schedule a GDM restart on the20th (outbox 20261107-1200). Then I verify.
2. Petar: physical TV check on the21th (1080p shows), and a password login/unlock from the viewer.

## Known gaps
- the20th streams ~1 fps while its TV is off until its GDM restart (limiter off then).
- Session change (greeter ↔ desktop) drops the viewer; reconnect by hand until H2 (auto-reconnect).
- Windows AltGr / macOS Option characters not forwarded; consent dialog not killed if the viewer leaves.
- .app is not notarised: first launch needs `xattr -dr com.apple.quarantine` or "Open Anyway".

## Notes
- Do not disturb `freedomoffice-claude` or `the21th-claude`.
