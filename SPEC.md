# FreedomDesk — Product & Architecture Spec

**Version:** 0.1 (bootstrap)  
**Date:** 2026-11-06 (Asia/Dubai)  
**Owner:** mar0der (Petar Petkov)  
**PO:** Claude Code Remote Control `freedomdesk-po` on the21th  
**Repo:** https://github.com/mar0der/FreedomDesk  
**Licence:** AGPL-3.0 (see §14)

---

## 1. Mission

Replace TeamViewer (and every paid remote-access tool Petar uses) with an open-source, free-for-everyone remote desktop that is:

- Written in **Rust**, **lightweight**, no Electron
- At least as capable as the best of TeamViewer, AnyDesk, RustDesk, Parsec, Chrome Remote Desktop, Splashtop, NoMachine and MeshCentral
- Self-hostable and optionally **Tailscale-only** (no public rendezvous required)
- Security-first: E2E encryption, key pinning, 2FA, consent, audit log

First concrete use case: **remote support for Petar’s mother’s laptop in Bulgaria over Tailscale**.

Part of the FreedomOffice family (`mar0der/FreedomOffice`).

---

## 2. Competitive takeaways (what to copy / beat)

| Product | Steal this | Avoid / beat this |
|---------|------------|-------------------|
| **TeamViewer** | Unattended access, address book, multi-platform, file transfer, chat, session recording, wake-on-LAN, mobile apps, attended quick-support codes | Commercial detection, pricing, telemetry, closed source |
| **AnyDesk** | Tiny footprint, excellent codec on weak links, fast ad-hoc support | Personal-use traps, closed source |
| **RustDesk** | Self-hostable ID/relay, open source, works out of the box, Flutter mobile | Binary size / dependency weight; public relay quality; AGPL is fine — we share that choice |
| **Parsec** | Near-zero latency, 4K/high FPS, HW encode, P2P feel for interactive work | Gaming-first (weak IT/support story); commercial Warp wall |
| **Chrome Remote Desktop** | Zero-friction setup, browser viewer, PIN simplicity | Feature-thin; Google account dependency |
| **Splashtop** | Polished business UX, solid FPS/price for pros | Closed; seat licensing |
| **NoMachine** | Multi-monitor excellence, HW H.264, audio/mic, screen blanking, USB/printer forwarding | Closed NX; encode limits on huge multi-monitor spans |
| **MeshCentral** | Self-hosted management, device groups, WoL mesh, session recording, audit, 2FA, web UI, agent model | Node/JS stack; not a “tiny Rust binary” aesthetic |

**FreedomDesk north star:** AnyDesk/Parsec latency + TeamViewer/MeshCentral support features + RustDesk self-host freedom + Chrome RD simplicity for family + NoMachine multi-monitor/audio — in a small Rust binary with Tailscale-native mode.

---

## 3. Feature set by priority

### P0 — MVP (ship a useful Linux host ↔ viewer loop)

| ID | Feature | Notes |
|----|---------|-------|
| P0-1 | Remote screen view | Capture host display; stream to viewer |
| P0-2 | Remote control | Mouse + keyboard injection on host |
| P0-3 | Low-latency codec path | Software OpenH264 first; pluggable HW later |
| P0-4 | E2E session crypto | Noise protocol or rustls mutual auth; no cleartext control plane |
| P0-5 | Direct / LAN / Tailscale connect | Connect by Tailscale IP or LAN IP without public relay |
| P0-6 | Host consent prompt | Attended mode: host must Accept (with timeout) |
| P0-7 | Linux host | the21th: Wayland (PipeWire) preferred, X11 fallback |
| P0-8 | Desktop viewer | egui or Tauri viewer on Linux (the20th) and path clear for macOS |
| P0-9 | Basic device identity | Stable device ID + public key; show fingerprint for pinning |
| P0-10 | Two-machine test harness | Scripted checklist: the21th host ↔ the20th viewer |

### P1 — Real support tool

| ID | Feature | Notes |
|----|---------|-------|
| P1-1 | Unattended access | Permanent password or key-based; service/daemon on host |
| P1-2 | Quick-support / join code | One-time code, short TTL, attended (mum’s laptop scenario) |
| P1-3 | Clipboard sync | Text first; files later |
| P1-4 | File transfer | Drag/drop or dual-pane; resume; integrity hash |
| P1-5 | Multi-monitor | List displays; switch; optional span; encode active monitor preferentially (avoid NoMachine’s “all monitors → NVENC limit” pitfall) |
| P1-6 | Audio (host → viewer) | PipeWire/WASAPI/CoreAudio capture |
| P1-7 | Address book | Named devices, last-seen, tags (`family`, `lab`) |
| P1-8 | NAT traversal | STUN + hole punch; self-hostable relay fallback |
| P1-9 | Self-hosted rendezvous/relay | Single Rust binary / Docker; config file |
| P1-10 | Tailscale-only mode | Skip public rendezvous entirely when both peers on Tailscale |
| P1-11 | Key pinning + TOFU | First connect pins; later mismatch hard-fails with clear UI |
| P1-12 | macOS + Windows hosts | Screen Recording / Accessibility / Input Monitoring prompts documented |
| P1-13 | Session chat | Text chat alongside session |
| P1-14 | Audit log (local) | Who connected, when, duration, outcome |

### P2 — Beat the commercial suites

| ID | Feature | Notes |
|----|---------|-------|
| P2-1 | Hardware encode/decode | VAAPI, NVENC, VideoToolbox, MediaFoundation; auto-negotiate |
| P2-2 | Wake-on-LAN | From address book; optional mesh helper on same L2 |
| P2-3 | Session recording | Local viewer-side and/or host-side; opt-in |
| P2-4 | Mobile viewers | Android / iOS (or Flutter/Tauri mobile) |
| P2-5 | 2FA | TOTP for unattended unlock; optional WebAuthn later |
| P2-6 | Screen blanking / privacy screen | Host display black while controlled |
| P2-7 | Mic / VoIP forward | Viewer mic → host (support calls) |
| P2-8 | Multi-user permissions | Viewer roles: view-only / control / file |
| P2-9 | Web viewer | Optional WASM/WebRTC viewer for emergency browser-only |
| P2-10 | Crash reporter | FreedomOffice pattern: systemd-coredump → toast → optional GitHub issue |
| P2-11 | Auto-update (optional) | Signed updates; off by default for self-hosters |
| P2-12 | USB / printer redirect | Stretch; study NoMachine approach |
| P2-13 | Virtual display | Headless hosts (Parsec/Warp-like) |
| P2-14 | Internationalisation | EN first; BG useful for family support UX |

---

## 4. Architecture

### 4.1 Crates (workspace)

```
FreedomDesk/
  Cargo.toml                 # workspace
  crates/
    fd-common/               # IDs, config, errors, serde types, versioning
    fd-proto/                # framing, messages, capability negotiation
    fd-crypto/               # Noise (snow) or rustls, key store, pinning
    fd-capture/              # OS capture: PipeWire, X11, macOS ScreenCaptureKit, DXGI
    fd-encode/               # openh264, optional ffmpeg/vaapi/nvenc wrappers
    fd-input/                # enigo / platform input injection + permissions
    fd-audio/                # optional audio capture/playback
    fd-net/                  # QUIC (quinn), TCP fallback, STUN, relay client
    fd-relay/                # self-hosted rendezvous + relay binary
    fd-host/                 # host service / tray agent
    fd-viewer/               # viewer UI (egui preferred for size; Tauri optional)
    fd-cli/                  # headless connect / scripting / CI tests
```

Keep the **viewer + host agent under ~15–25 MB** compressed where practical (AnyDesk-class). Prefer static linking carefully; strip + LTO for release.

### 4.2 Protocol sketch

1. **Discovery / rendezvous** (optional): register `device_id` + pubkey with rendezvous; request peer connection → candidate addrs (direct, Tailscale, relay).
2. **Transport:** prefer **QUIC (quinn)** for multiplexed video/control/clipboard/file streams; TCP+TLS fallback.
3. **Handshake:** Noise_IK or Noise_XX (via `snow`) **or** rustls mTLS with pinned certs. Derive session keys; confirm fingerprints in UI.
4. **Streams:**
   - `video` — encoded frames + damage regions / keyframe requests
   - `input` — mouse, keyboard, wheel, clipboard signals
   - `clipboard` / `files` / `audio` / `chat` — separate channels
5. **Capabilities:** negotiate codec, max FPS/resolution, monitors, audio, permissions at start and mid-session.

Wire format: length-prefixed protobuf **or** compact bincode + schema version. Prefer protobuf if we want non-Rust clients later; bincode OK for P0 if versioned.

### 4.3 Capture & encode

| Platform | Capture | Encode |
|----------|---------|--------|
| Linux Wayland | PipeWire / xdg-desktop-portal | OpenH264; VAAPI; NVENC |
| Linux X11 | `scrap` / `xcap` / XDamage | same |
| macOS | ScreenCaptureKit | VideoToolbox H.264/HEVC; OpenH264 fallback |
| Windows | DXGI Desktop Duplication | MediaFoundation / NVENC; OpenH264 |

P0: Linux PipeWire + OpenH264 software. Adaptive bitrate + keyframe on scene change / packet loss.

### 4.4 UI

- **P0/P1:** `egui` + `eframe` (matches FreedomOffice Sheets stack; small, Rust-native).
- **Alternative:** Tauri 2 if we need native web mobile/web viewer later — not required for MVP.
- Host: system tray (status, last connections, “allow remotely”, copy device ID).
- Viewer: address book, connect, monitor picker, toolbar (Ctrl+Alt+… break keys), file transfer pane.

### 4.5 Keeping the client small

- Feature-flag HW codecs and relay
- Avoid bundling full FFmpeg unless behind `ffmpeg` feature
- One agent binary that is both host and viewer (mode switch), plus optional `fd-relay`
- LTO, `strip`, `panic=abort` in release; care with debug symbols on crash-reporter builds

---

## 5. Networking modes

1. **Tailscale-only (recommended for Petar’s family use):** both peers on Tailscale; connect to `100.x` / MagicDNS name; **no** public rendezvous. Default for mum’s laptop.
2. **LAN direct:** mDNS or manual IP.
3. **STUN + hole punch:** for general internet without relay when NAT allows.
4. **Self-hosted relay:** `fd-relay` on a VPS or the18th/the20th; only ciphertext relayed.
5. **Optional public community relay:** later, if ever — never required.

Policy: never expose host agent ports on `0.0.0.0` public internet by default; bind Tailscale/LAN unless user opts in.

---

## 6. Security & threat model

### Assets
- Host screen contents, keystrokes, clipboard, files
- Long-term device private keys
- Unattended access secrets
- Audit records

### Adversaries
- Network eavesdropper / MITM on path or malicious relay
- Malicious rendezvous operator
- Local malware on viewer or host
- Curious household member on mum’s laptop
- Supply-chain (dependency / update) attacker

### Guarantees (goals)
- **E2E confidentiality & integrity** of session data even if relay is hostile
- **TOFU + pinning** of device keys; visible fingerprint
- **Consent** for attended sessions; clear UI on host
- **Unattended** requires explicit enable + strong secret / key + optional 2FA
- **No** cleartext passwords on disk; OS keychain / encrypted store
- Relay sees only opaque packets + routing metadata (IPs, timing) — minimise metadata where possible
- Audit log on host (and optional viewer) for support accountability

### Non-goals (initially)
- Protecting against a compromised host OS kernel
- Anonymity / Tor (may document as possible later)
- DRM / preventing viewer-side screenshots

### Permissions matrix (hosts)

| OS | Needed | UX |
|----|--------|-----|
| Linux Wayland | Portal screen share; input via `uinput`/ydotool/remote-desktop portal where available | First-run guide |
| Linux X11 | XTest / uinput | Document security tradeoffs |
| macOS | Screen Recording, Accessibility, Input Monitoring | Open System Settings deep links |
| Windows | Secure Desktop / UAC considerations; service install for unattended | MSI/tray helper |

---

## 7. Self-hosted rendezvous / relay

- Binary: `fd-relay`
- Roles: device registration (short-lived tokens), signalling, optional TURN-like relay
- Config: TOML; TLS certs (ACME optional); allowlist of device keys optional
- Deploy: Docker compose one-liner; systemd unit
- Does **not** terminate E2E session keys
- Metrics: connections, bytes relayed (no payload logging)

---

## 8. Test plan

### Lab (continuous)

| Test | Host | Viewer | Network |
|------|------|--------|---------|
| T1 smoke | the21th | the21th (second session / another VT) | local |
| T2 LAN/Tailscale | the21th | the20th | Tailscale |
| T3 macOS viewer | the21th | Petar’s MacBook Air | Tailscale |
| T4 macOS host (later) | MacBook | the20th | Tailscale |
| T5 latency | the21th | the20th | measure FPS, RTT, input lag |
| T6 loss | the21th | the20th | tc netem packet loss |
| T7 file/clipboard | the21th | the20th | integrity check |
| T8 unattended reboot | the21th | the20th | agent survives reboot |
| T9 Bulgaria | mum’s laptop | Dubai viewer | Tailscale cross-country |

### Acceptance for P0
- [ ] Viewer sees host screen < 200 ms glass-to-glass on LAN (target; measure)
- [ ] Mouse/keyboard usable for terminal + browser
- [ ] Fingerprint shown and pinable
- [ ] Consent required in attended mode
- [ ] No crash on disconnect/reconnect × 20
- [ ] Documented build on Ubuntu 24.04

### Security checks
- [ ] Relay cannot read frame contents (negative test with instrumented relay)
- [ ] Key mismatch refuses connect
- [ ] Secrets absent from logs and git

---

## 9. Milestones

| Milestone | Goal | Exit criteria |
|-----------|------|---------------|
| **M0** | Docs + PO online | This SPEC, repo public, `freedomdesk-po` running |
| **M1** | Capture → encode → decode loop | Local preview window on the21th |
| **M2** | Networked P0 | the21th ↔ the20th over Tailscale with control |
| **M3** | Crypto + consent + IDs | Pinning, attended Accept, stable device ID |
| **M4** | Unattended + join code | Service mode; mum-ready quick support |
| **M5** | Files + clipboard + multi-monitor | P1 support basics |
| **M6** | Relay + STUN | Works without Tailscale for friends |
| **M7** | macOS/Windows hosts | Permission UX polished |
| **M8** | HW encode + audio + recording | Parsec/NoMachine class feel |
| **M9** | Mobile viewer + 2FA + audit polish | TeamViewer-class support kit |
| **M10** | Crash reporter + packaging | Deb/Rpm/MSI/DMG; FreedomOffice-style toast→issue |

---

## 10. First use case — Mum in Bulgaria

**Goal:** Petar (Dubai) supports mother’s laptop without TeamViewer.

**Preferred path:** Tailscale on her laptop (`tag:family`), FreedomDesk unattended **or** quick-support join code, RustDesk-like simplicity, Tailscale-only mode (no public relay).

**UX bar:**
1. She double-clicks FreedomDesk (or it runs as a service).
2. Either: Petar picks “Mum” in address book → connects with pinned key; **or** she reads a 6–8 character code over the phone.
3. Consent banner she understands (Bulgarian strings in P2-14).
4. Session ends cleanly; audit line written.

**Out of scope for first visit:** MeshCentral-scale fleet management; USB redirect.

---

## 11. Non-goals

- Replacing enterprise RMM (full MeshCentral parity) in v1
- Cloud account mandatory
- Mining / adware / “sponsored” free tier
- Closed “Pro” binary — AGPL covers server and client equally

---

## 12. Open decisions (PO may refine in STATUS)

1. egui vs Tauri for viewer long-term → **default egui** for P0
2. Noise (`snow`) vs rustls-only → **prefer Noise_IK for peer sessions**, rustls for relay HTTPS
3. Protobuf vs bincode → **bincode+version for P0**, revisit before non-Rust clients
4. Single binary (host+viewer) vs split → **single agent + separate relay**
5. Default codec profile → **H.264 baseline/main, 30 FPS, adaptive**

---

## 13. Inspiration references (implementation)

- Capture: `scrap`, `xcap`, PipeWire portal crates
- Input: `enigo`, platform-specific fallbacks
- Encode: `openh264`, optional `ffmpeg-next`, VAAPI via `libva`
- Net: `quinn`, `tokio`, STUN crates, optionally `webrtc` stack later for web viewer
- Crypto: `snow` (Noise), `rustls`, `ed25519-dalek`, `zeroize`, OS keyring
- UI: `egui` / `eframe` (FreedomOffice alignment)
- Pack/crash: study FreedomOffice Linux crash-reporter plan (coredumpctl → toast → GitHub issue)

---

## 14. Licence choice — AGPL-3.0

**Chosen: GNU Affero General Public License v3.0.**

**Why not MIT/Apache dual (FreedomOffice uses MIT):**  
FreedomDesk includes a **network service** (rendezvous/relay). Under MIT/Apache, a vendor could fork the relay, run it as a hosted SaaS, and never share improvements — recreating the TeamViewer trap. AGPL-3.0 requires sharing source for network-provided modified versions, matching RustDesk’s rationale and protecting “free for the world” permanently.

**Tradeoff:** some companies avoid AGPL. Acceptable — Petar’s goal is freedom from paid remote-access vendors, not maximising proprietary adoption. Apache/MIT can be reconsidered later for **libraries** only if needed; the agent + relay stay AGPL.

---

## 15. Name check

- **FreedomDesk** — fits FreedomOffice family.
- GitHub: no active `FreedomDesk` remote-desktop project; `mar0der/FreedomDesk` created public.
- crates.io: no `freedomdesk` crate (API 404/403).
- Unrelated: “FreedomDesk” dental phone-AI SaaS (freedomdeskai.com) — different domain; we are remote desktop. If trademark conflict appears, fallback name **FreedomRemote**.

---

_End of SPEC v0.1 — PO should treat this as living; update STATUS.md when milestones move._
