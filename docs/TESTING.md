# FreedomDesk test checklist (P0)

Build (Ubuntu 24.04): `sudo apt install build-essential nasm libx11-dev libxcb1-dev libxkbcommon-dev`
plus a Rust toolchain (rustup), then `cargo build --release -p freedomdesk`.
(`nasm` is optional but halves H.264 encode time; without it OpenH264 silently builds plain C.)
macOS: `brew install nasm` (optional), then the same cargo command.
Binary: `target/release/freedomdesk`.

## T1 — loopback smoke (the21th alone)
`scripts/smoke-local.sh` (env: `FRAMES`, `RUNS`, `PROFILE`). View-only, no input injected.

## T2 — the21th host ↔ the20th viewer over Tailscale
On **the21th** (in the GNOME session, or from ssh/tmux with `DISPLAY=:0 XAUTHORITY=/run/user/1000/gdm/Xauthority`):
```
freedomdesk id                      # note the host fingerprint
freedomdesk host                    # binds the Tailscale IP, port 47801
```
On **the20th**:
```
freedomdesk view the21th --expect-fingerprint <HOST-FP>
# or without the flag: it shows the fingerprint and asks y/N before trusting
```
A consent dialog appears on the21th → **Allow**. Then check:
- [ ] picture appears < 2 s after Allow; title bar shows fps + rtt
- [ ] mouse move / left / right / middle click / scroll / drag a window
- [ ] terminal: type `ls -la | grep x`, Ctrl+C, arrows, Tab completion, Backspace
- [ ] browser: type a URL, Ctrl+L, Ctrl+T, Ctrl+W
- [ ] Bulgarian text: `здравей` typed via the viewer's layout appears correctly
- [ ] close viewer window → host logs "session … ended", accepts a new connection
- [ ] reconnect ×20 (headless): `for i in $(seq 20); do freedomdesk view the21th --headless --seconds 2; done`
      (needs the viewer in the host's `--unattended-viewer` list, otherwise each run prompts)
- [ ] mouse cursor visible and tracking in the viewer
- [ ] idle desktop: host CPU near zero (no changed frames are sent)
- [ ] Deny in the dialog → viewer prints "host denied"
- [ ] wrong `--expect-fingerprint` → refused before any video
- [ ] `~/.config/freedomdesk/audit.log` on the host has one line per session

Unattended (skip the dialog for a known viewer): on the viewer run `freedomdesk id`, then
`freedomdesk host --unattended-viewer <VIEWER-FP>` on the host.

## T3 — MacBook viewer
Same as T2 from macOS (`cargo build --release -p freedomdesk`; the host-side crates
compile to "unsupported" stubs on macOS, viewer works).
