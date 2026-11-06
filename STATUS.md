# STATUS — FreedomDesk PO (the21th)

_Last updated: 2026-11-06 (PO `freedomdesk-po`)_

## Now
- **M1/M2 in progress**: Rust workspace up; X11 capture → OpenH264 → Noise_XX/TCP → egui viewer with mouse/keyboard.
- Next: T1 loopback smoke on the21th → T2 the21th ↔ the20th over Tailscale (needs Petar, see Blocked).

## Milestones (SPEC §9, refined)
| M | Goal | Exit criteria | State |
|---|------|---------------|-------|
| M0 | Docs + PO online | SPEC, repo, PO running | ✅ |
| M1 | Capture → encode → decode loop | headless loopback viewer decodes the21th screen; bench numbers recorded | 🔨 |
| M2 | Networked P0 | the21th host ↔ the20th viewer over Tailscale, mouse+keyboard usable for terminal + browser | 🔨 code done, needs T2 |
| M3 | Crypto + consent + IDs | ✅ Noise_XX, device keys, fingerprints, TOFU pinning, consent dialog, audit log (built with M2). Left: reconnect ×20 soak, negative tests in CI | 🔨 |
| M4 | Unattended + join code | systemd user service, authorized-viewers file, 6–8 char join code; Wayland (PipeWire portal) capture | ⏳ |
| M5 | Clipboard, file transfer, multi-monitor | P1-3/4/5 | ⏳ |
| M6 | Relay + STUN | `fd-relay`, works off-Tailscale | ⏳ |
| M7 | macOS/Windows hosts | ScreenCaptureKit/DXGI, permission UX | ⏳ |
| M8 | HW encode, audio, recording | VAAPI/NVENC, PipeWire audio | ⏳ |
| M9 | Mobile viewer, 2FA, audit polish | | ⏳ |
| M10 | Crash reporter + packaging | deb/dmg/msi; coredump → toast → GitHub issue | ⏳ |

## P0 design decisions (taken)
- One binary `freedomdesk` (`id` / `host` / `view`), crates: fd-proto, fd-crypto, fd-capture, fd-codec, fd-input.
- Transport **TCP + Noise_XX_25519_ChaChaPoly_BLAKE2s** (snow); QUIC later (M6). Wire msgs: postcard (bincode 3 is a dead tombstone release).
- Capture: **X11 MIT-SHM first** — the21th runs GNOME on Xorg and PipeWire dev headers aren't installed. Wayland/PipeWire = M4.
- Input: XTest; keys as X11 keysyms on the wire; unmapped chars (Cyrillic) via spare-keycode remap.
- 4K host downscaled to ≤1920×1080 before encode (CPU budget).
- Host binds Tailscale IP by default; refuses 0.0.0.0/public unless `--allow-public-bind`.
- OpenH264 is compiled from source (BSD). H.264 patent-licence note: Cisco's royalty coverage applies only to their prebuilt binary — revisit before distributing packages (option: runtime-load Cisco binary).

## Blocked / needs Petar
- **SSH the21th → the20th refused (publickey)** and no sudo here. For T2 I need either: (a) the21th's key in the20th `authorized_keys`, or (b) Petar runs the viewer on the20th/MacBook himself — steps in `docs/TESTING.md`.
- **Push to GitHub**: the21th has no `gh`/credentials. Commits are local until Petar provides auth or pushes from the Mac.

## Notes
- Do not disturb `freedomoffice-claude` or `the21th-claude`.
