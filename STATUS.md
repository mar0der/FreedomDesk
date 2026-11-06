# STATUS — FreedomDesk PO (the21th)

_Last updated: 2026-11-06 ~10:55 Dubai (PO `freedomdesk-po`)_

## Now
- **T2 PASSED** (Guardian, headless): the20th → the21th over Tailscale, first frame 160 ms, rtt 1.5 ms. GUI input path still needs a human check.
- **Host live on the21th**: `~/.local/bin/freedomdesk host --bind 100.116.143.66 --port 47801` (setsid, log `~/.local/state/freedomdesk/host.log`), FP `L4O7-LFLS-PTVE-HW7U-RR6P-VZWO`. Unattended viewers in `~/.config/freedomdesk/authorized_viewers` (the20th listed); add with `freedomdesk authorize <FP>`.
- **T3 ready for Petar**: macOS arm64 viewer released — https://github.com/mar0der/FreedomDesk/releases/tag/v0.1.0-alpha.1 (5.8 MB, checksum verified). Or `cargo build` on the Mac. Steps: `docs/TESTING.md` §T3. CI builds Linux + macOS on every push; `v*` tags publish pre-releases.
- CI: https://github.com/mar0der/FreedomDesk/actions

## Milestones (SPEC §9, refined)
| M | Goal | Exit criteria | State |
|---|------|---------------|-------|
| M0 | Docs + PO online | SPEC, repo, PO running | ✅ |
| M1 | Capture → encode → decode loop | loopback decode on the21th + bench | ✅ |
| M2 | Networked P0 | the21th ↔ the20th over Tailscale, terminal + browser usable | 🔨 T2 headless ✅; GUI input + T3 Mac pending |
| M3 | Crypto + consent + IDs | Noise_XX, fingerprints, TOFU+confirm, consent dialog, audit log, DoS limits ✅; left: glass-to-glass latency measurement | 🔨 |
| M4 | Unattended + join code | systemd user service, authorized-viewers file, join code; Wayland/PipeWire capture + portal input | ⏳ next |
| M5 | Clipboard, files, multi-monitor | P1-3/4/5 | ⏳ |
| M6 | Relay + STUN | `fd-relay`, works off-Tailscale | ⏳ |
| M7 | macOS/Windows hosts | ScreenCaptureKit/DXGI, permission UX | ⏳ |
| M8 | HW encode, audio, recording | VAAPI/NVENC, PipeWire audio | ⏳ |
| M9 | Mobile viewer, 2FA, audit polish | | ⏳ |
| M10 | Crash reporter + packaging | deb/dmg/msi; coredump → toast → GitHub issue | ⏳ |

## P0 decisions (taken)
- One binary; crates fd-proto / fd-crypto / fd-capture / fd-codec / fd-input. TCP + Noise_XX (snow); QUIC at M6. postcard wire format (bincode 3 is a dead tombstone).
- X11 first (the21th = GNOME on Xorg; no PipeWire dev headers). Wayland = M4.
- Viewer holds only modifiers on the host, taps all other keys; macOS Cmd → Ctrl.
- Host binds Tailscale IP by default; refuses 0.0.0.0/public without `--allow-public-bind`.
- OpenH264 built from source (BSD). ⚠ H.264 patent cover only applies to Cisco's prebuilt binary — decide before shipping packages.
- `nasm` installed user-locally at `~/.local/bin/nasm` (no sudo) — halves encode time.

## Known gaps (tracked, not P0 blockers)
- Windows-viewer AltGr / macOS Option characters not forwarded; Ctrl+Alt+F-key can VT-switch the host.
- Consent dialog isn't killed if the viewer disconnects mid-prompt.

## Blocked / needs Petar
- T3: run the Mac viewer (docs/TESTING.md §T3): `freedomdesk id` on the Mac → `ssh the21th ~/.local/bin/freedomdesk authorize <FP>` → `freedomdesk view 100.116.143.66 --expect-fingerprint L4O7-LFLS-PTVE-HW7U-RR6P-VZWO`. Report what works/doesn't (esp. keyboard).
- Host is a plain setsid process (no autostart on reboot) — systemd user unit comes with M4.

## Notes
- Do not disturb `freedomoffice-claude` or `the21th-claude`.
