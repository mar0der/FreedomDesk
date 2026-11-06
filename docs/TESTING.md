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

## T3 — Petar's MacBook Air (Apple Silicon) viewer → the21th

The Mac build is **viewer-only** (`host` says "Linux-only for now"). The viewer needs no
macOS permissions (it doesn't capture or inject anything locally).

**Get the binary** — either:
- **Build on the Mac** (Rust ≥ 1.89; nasm not needed):
  ```
  git clone https://github.com/mar0der/FreedomDesk && cd FreedomDesk
  cargo build --release -p freedomdesk --locked
  cp target/release/freedomdesk ~/bin/   # or run it in place
  ```
- **Or download the release** (pre-release `v0.1.0-alpha.1`; newer tags: see the Releases page). Use curl, not the browser, so
  Gatekeeper doesn't quarantine the unsigned binary:
  ```
  curl -LO https://github.com/mar0der/FreedomDesk/releases/download/v0.1.0-alpha.1/freedomdesk-macos-aarch64.tar.gz
  curl -LO https://github.com/mar0der/FreedomDesk/releases/download/v0.1.0-alpha.1/freedomdesk-macos-aarch64.tar.gz.sha256
  shasum -a 256 -c freedomdesk-macos-aarch64.tar.gz.sha256 && tar xzf freedomdesk-macos-aarch64.tar.gz
  ```

**Authorise the Mac on the host** (once — so nobody has to click Allow on the21th):
```
./freedomdesk id                                   # on the Mac: note "Device fingerprint"
ssh the21th ~/.local/bin/freedomdesk authorize <MAC-FP> --label petar-macbook
```
(Without this, the21th shows an Allow/Deny dialog and auto-denies after 30 s.)

**Connect:**
```
./freedomdesk view 100.116.143.66 --expect-fingerprint L4O7-LFLS-PTVE-HW7U-RR6P-VZWO
```
Checklist: same as T2, plus Mac specifics —
- [ ] Cmd+C / Cmd+V / Cmd+T act as Ctrl+C / Ctrl+V / Ctrl+T on the Linux host
- [ ] trackpad scrolling (both axes) and two-finger right click
- [ ] Retina scaling: pointer lands exactly where clicked
- [ ] known gap: Option+key special characters are not forwarded yet
- [ ] cursor follows the trackpad instantly (drawn locally, remote shape: arrow / I-beam / hand)
- [ ] zoom: pinch, Ctrl+Option+scroll, Ctrl+Option+1 (1:1), Ctrl+Option+0 (fit), toolbar at the top edge
- [ ] zoomed in, 4K text is sharp (host crops natively); edge-pan by moving to the window edge
- [ ] clicks land exactly under the cursor at fit, 1:1 and 400%
