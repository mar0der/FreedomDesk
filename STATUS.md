# STATUS — FreedomDesk PO (the21th)

_Last updated: 2026-11-06 ~10:45 Dubai (PO `freedomdesk-po`)_

## Now
- **P0 code complete on the21th, T1 green.** `freedomdesk host|view|id`: X11 capture (SHM, cursor, DAMAGE) → OpenH264 → Noise_XX/TCP → egui viewer with mouse + keyboard (XKB-aware, Cyrillic OK).
- T1 loopback: 20× reconnect, pin-mismatch refusal, SIGTERM clean stop — pass. GUI viewer checked in nested Xephyr.
- Perf (3840×2160 → 1080p, asm): capture 7–11 ms, convert 6 ms, encode 18–24 ms, decode 8 ms; 2-thread pipeline 35 fps busy / idle screen sends nothing.
- **Waiting on Petar for T2/T3** (the20th / MacBook viewer) — see Blocked.

## Milestones (SPEC §9, refined)
| M | Goal | Exit criteria | State |
|---|------|---------------|-------|
| M0 | Docs + PO online | SPEC, repo, PO running | ✅ |
| M1 | Capture → encode → decode loop | loopback decode on the21th + bench | ✅ |
| M2 | Networked P0 | the21th ↔ the20th over Tailscale, terminal + browser usable | 🔨 code ✅, T2 pending |
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
1. **Push**: the21th has no GitHub credentials (`gh auth login` or a deploy key needed). 5 commits on local `main`, not pushed.
2. **T2/T3**: no SSH from the21th → the20th (the21th has no SSH keypair at all). Either OK me to generate one and you add it to the20th, or run the viewer yourself: `git clone the21th:Developer/FreedomDesk && cargo build --release -p freedomdesk`, then follow `docs/TESTING.md`.

## Notes
- Do not disturb `freedomoffice-claude` or `the21th-claude`.
