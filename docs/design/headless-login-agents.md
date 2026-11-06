# Design: headless hosts, login/lock-screen access, and agent access

_Status: proposal, 2026-11-07. Nothing here is implemented yet. Sources are numbered [n] and listed at the end. "Verify" means we have no solid source and it must be tested on our own machines._

## 1. Goal

Petar must be able to fully operate machines that have **no monitor**: the20th and the21th (Ubuntu 24.04, GNOME 46, NVIDIA Quadro P4000, proprietary driver 580), a future Mac mini and a MacBook Air left at home. "Fully" includes the screens that normally need someone sitting there: GDM greeter, lock screen, polkit dialogs, the macOS login window, admin password prompts and TCC dialogs. AI agents (Claude Code and similar) should get the same reach through an MCP server and CLI, using their own keys, scoped permissions, a visible indicator, a kill switch and an audit log.

The security bar stays the same: Tailscale-only by default, Noise_XX with key pinning, unattended access only for listed keys, and an audit log.

**Today:** `freedomdesk host` is a user process inside petar's Xorg session. It uses MIT-SHM capture, XTest input, OpenH264 and Noise_XX over TCP, plus the `authorized_viewers` allow-list (fingerprint + label), the consent dialog and `audit.log`. It can only see the session it was started in, so it never sees the GDM greeter, and it dies at logout.

**Measured on our boxes (2026-11-07):**
- Both boxes are GNOME Shell 46.0 on Xorg (`Type=x11`).
- GDM has `AutomaticLogin=petar` on both.
- `gnome-remote-desktop` 46.3 is installed.
- `org.gnome.Mutter.ScreenCast` and `org.gnome.Mutter.RemoteDesktop` are on the session bus.
- **the20th already runs its Xorg session with every connector disconnected.** Its Xorg log shows NVIDIA `AllowEmptyInitialConfiguration` enabled, and the root window is 3840x2160. Monitor-less X11 already works for the logged-in session on NVIDIA.

## 2. Findings: Linux

### 2.1 Getting a framebuffer without a monitor

| Option | Logged-in session | GDM greeter / lock | Notes |
|---|---|---|---|
| NVIDIA Xorg `AllowEmptyInitialConfiguration` / `ConnectedMonitor` + `CustomEDID` | ✅ (running on the20th now) | ✅ if the greeter is Xorg | `ConnectedMonitor` makes the driver behave as if a display is attached. `CustomEDID` loads a stored EDID [1][2]. Best fit for our NVIDIA boxes. |
| Kernel EDID override `drm.edid_firmware=CONN:edid/x.bin video=CONN:e` | ✅ | ✅ for X11 and Wayland (the kernel reports "connected") | Documented in community guides, with caveats [3]. **Verify:** the proprietary `nvidia-drm` driver may ignore it. |
| `xserver-xorg-video-dummy` | ✅ | Possible, but GDM would need a custom Xorg config | No GPU acceleration. Reported black-screen and resolution quirks [4]. |
| Xvfb / Xvnc | Separate session only | ❌ | Not the console session, so it doesn't meet the goal. |
| `mutter --headless --virtual-monitor WxH` | Headless Wayland session | Only via GDM remote login (2.2) | Mutter calls it mainly a debugging/CI backend [5]. People report it failing to acquire the ScreenCast/RemoteDesktop bus names [6]. |
| vkms | Possible | Possible | The kernel docs call it a test driver: one CRTC/connector, no scaling [7]. Not for production. |
| HDMI/DP dummy plug | ✅ | ✅ | Hardware fallback that always works. Costs about $10. |

### 2.2 How GNOME does remote login (GNOME 46 = Ubuntu 24.04)

gnome-remote-desktop (g-r-d) has a **system daemon** that listens for RDP. On connect it calls GDM's `RemoteDisplayFactory.CreateRemoteDisplay`. GDM then starts a **headless** greeter, and a per-session handover daemon receives the connection through a `ServerRedirection` [8][9]. Only RDP supports this mode [10].

Three limits matter for us:
- It creates a **separate headless session**. It can't attach to the console session.
- If the same user already has a local session, GNOME refuses or offers to kill it [11][12].
- In g-r-d's "remote assistance" mode (attaching to an existing session), "locking the screen also closes the remote desktop connection" [10].

g-r-d's system D-Bus interface had a local-user TLS-key interception CVE in 46 (CVE-2024-5148) [13], so this is young code.

A TigerVNC maintainer said in Nov 2025: "Headless GNOME will not be possible to use with any other remote desktop system than their own" [14].

### 2.3 How RustDesk handles the Linux login screen

RustDesk requires the greeter to be **X11**: `WaylandEnable=false` in `/etc/gdm3/custom.conf`, then a reboot. Its Wayland support is still experimental [15][16]. A root service finds the active X display and its Xauthority (the greeter's under `/run/user/<gdm-uid>/gdm/`) and captures it.

### 2.4 Wayland capture and input

- **Portals.** `org.freedesktop.portal.ScreenCast` and `RemoteDesktop` need a user to click a dialog once. `persist_mode=2` returns a single-use `restore_token` that must be swapped for the new token every time [17]. Input goes through `ConnectToEIS` (libei) [18]. Mutter refuses to create or restore a portal screencast while the session is locked, and failed attempts can burn the token [19]. So the portal path can't show us the lock screen and doesn't fit unattended use.
- **Mutter's own D-Bus API** (`org.gnome.Mutter.ScreenCast` + `RemoteDesktop`, PipeWire stream, `ConnectToEIS`). This is what the portal backend and g-r-d use [20]. GNOME Shell has started limiting some private D-Bus APIs to allow-listed senders [21][22]. Maintainers say this is not a security boundary against unsandboxed processes [20]. Whether an unsandboxed session process can use it without a dialog on GNOME 46, and whether it survives a screen lock, is **not settled** (sources conflict [23]). This is the key Wayland spike.
- **Lock screen and polkit.** On GNOME, both are drawn by gnome-shell inside the session compositor. Under **X11** they are ordinary pixels on the same X screen: XShm captures them and XTest reaches them. We expect this to work with today's code, but must verify. Under **Wayland** only compositor-level capture/injection reaches them, and lock behavior is the open question above.
- **Deadline.** Ubuntu 26.04 LTS has **no Xorg GNOME session** [24]. X11 is the right path for 24.04 now, but it is a dead end.

## 3. Findings: macOS

### 3.1 Architecture Apple supports

Apple DTS (Quinn) describes the standard screen-sharing architecture [25]:
- A **LaunchDaemon** handles networking and state.
- A **LaunchAgent** with `LimitLoadToSessionType = [Aqua, LoginWindow]` does capture and `CGEvent` posting. The two talk over XPC.

From the same thread: ScreenCaptureKit works in the pre-login context **from macOS 14.4** (a bug fix, r. 121253782). Before 14.4, `CGDisplayStream` is needed. Capture attempted from the daemon itself fails ("lack of graphical context"). One developer reports a LoginWindow agent registered through `SMAppService` never started, while a plist in `/Library/LaunchAgents` did [26].

### 3.2 Monitor-less Macs

- A vendor claims headless Apple Silicon Macs fall back to a 1920x1080 non-Retina framebuffer [27]. Verify on our hardware.
- `CGVirtualDisplay` is private, undocumented API. It can create HiDPI virtual displays, but behavior varies across OS versions [28]. BetterDisplay and BetterDummy use it [27].
- A dummy plug is the boring, reliable option, though one user reports dummy displays not showing in VNC on Apple Silicon [27].

### 3.3 What is limited or impossible on macOS

| Surface | Status |
|---|---|
| TCC consent alerts, Accessibility prompts, keychain prompts, the security-extension "Allow" UI | **Synthetic events are dropped by design.** Synthetic CoreGraphics events are filtered for protected UI [29]. Remote-tool users report the Allow button "can't be clicked" over Screen Sharing, ARD or TeamViewer [30][31]. **Plan on needing a physical visit or MDM.** |
| Granting Screen Recording ahead of time | PPPC profiles can't silently grant `ScreenCapture`. They can only let a standard user approve it [32]. Accessibility and PostEvent can be set to Allow by MDM [32]. |
| macOS 15 recurring screen-capture re-prompt | Weekly in 15.0, monthly from 15.1. Can be suppressed only with the MDM restriction `forceBypassScreenCaptureAlert` [33][34], or with the Apple-gated `persistent-content-capture` entitlement for VNC apps [35]. |
| Enabling Apple Screen Sharing remotely | `kickstart` can't enable it since 12.1. It takes MDM or a click in the GUI [36]. |
| FileVault pre-boot | No app runs there. **macOS 26 (Apple Silicon only)** can unlock FileVault over SSH if Remote Login was enabled before the reboot [37]. |
| Login window, lock screen, admin password prompts (SecurityAgent) | Expected to work with the daemon+agent design on 14.4+ [25]. Whether posted keystrokes reach secure text fields under Secure Event Input is **unverified**. Secure Input is known to block event *taps* [38], not posting. |

**Fallback:** Apple Screen Sharing (built-in VNC), enabled once on site and reached over Tailscale. It reaches the login window, but it can't click TCC alerts either [30].

## 4. Findings: agent / computer-use interface

- **Anthropic's current computer-use tool.** For Claude 5.5 models it is `computer_toolset_20260801`, with 17 members [39]:
  - Screen: `screenshot`, `zoom(region)`, `cursor_position`
  - Clicks: `left_click`/`right_click`/`middle_click`/`double_click`/`triple_click` (`coordinate`, modifier `text`), `left_click_drag`, `left_mouse_down`/`up`, `mouse_move`
  - Other: `scroll(scroll_direction, scroll_amount)`, `type`, `key(repeat)`, `hold_key`, `wait`

  Coordinates are in screenshot pixels; the client scales them back to the real display. Anthropic recommends about 1280x720–1366x768 and never above 1920x1080. It also says: use isolated environments, never give the model credentials, and require human confirmation for consequential actions. Screenshots can carry prompt injection [39].
- **MCP.** Tools are listed with JSON Schema, and results can carry `image` content. The spec says there "SHOULD always be a human in the loop with the ability to deny tool invocations". Servers MUST validate inputs, enforce access control and rate-limit. Clients SHOULD log tool use. Tool annotations (`readOnlyHint`, `destructiveHint`) are untrusted hints [40]. A local stdio server gets no auth from the protocol, so security has to come from our own transport.
- **Prior art.** VNC MCP servers already exist: hrrrsn/mcp-vnc, mcvnc, claude-kvm, and others [41]. Ideas worth copying:
  - grid overlay on screenshots
  - downscaled screenshots with coordinates mapped back to native resolution
  - a "wait for screen change" tool

  None of them have per-key scopes, an indicator or an audit log. That's our edge.

## 5. Proposed architecture

### 5.1 Process split (same shape on every OS)

```
            Tailscale (Noise_XX, pinned keys)
viewer / freedomdesk mcp ──────────────► fd-daemon  (root: systemd system unit / LaunchDaemon)
                                          │  network, Noise, authorized_viewers policy,
                                          │  consent routing, audit, kill switch,
                                          │  session tracking
                                          │  Unix socket, SO_PEERCRED / XPC + audit token
                                          ▼
                                         fd-session-agent  (one per active console session;
                                          runs as that session's uid, e.g. gdm or petar)
                                          capture → encode, input injection, indicator overlay,
                                          local consent dialog
```

- **The daemon never touches pixels.** The agent runs as the session's own user, so it needs no extra privileges to reach that session. This is also Apple's prescribed split [25].
- **Following the console (Linux).** The daemon watches logind's `Seat0.ActiveSession` (via zbus). For an X11 session it starts the agent with `DISPLAY` + `XAUTHORITY`: the greeter's Xauthority for the `gdm` uid, the user's for petar. For Wayland it uses `DBUS_SESSION_BUS_ADDRESS=/run/user/<uid>/bus`.
  - Login, logout or a VT switch: the daemon starts a new agent and tells the viewer `SessionChanged{kind: greeter|user|locked}`, then forces a keyframe. The Noise session stays up.
  - Lock/unlock inside a GNOME session doesn't change the session. We still report `locked` from `LockedHint`.
- **Following the console (macOS).** One agent plist with `LimitLoadToSessionType = [Aqua, LoginWindow]` [25]. launchd starts an agent instance per GUI session, and each one checks in with the daemon. The daemon routes to the console session (`SCDynamicStoreCopyConsoleUser`).

### 5.2 Virtual display strategy

| Host | Now | Later |
|---|---|---|
| the20th / the21th (24.04, NVIDIA) | Xorg greeter (`WaylandEnable=false`) plus NVIDIA `ConnectedMonitor` + `CustomEDID` (a 2560x1440 EDID) in an `xorg.conf.d` snippet, so greeter and session get the same fixed mode with or without the TV. `AllowEmptyInitialConfiguration` alone is proven for the session (the20th). | Wayland (26.04): spike Mutter direct API vs a g-r-d bridge (5.4). Use a kernel EDID override or a dummy plug for a fixed mode. |
| Mac mini / MacBook Air (lid closed) | HDMI dummy plug (known-good). Optional `CGVirtualDisplay` behind a `virtual-display` feature for HiDPI. | Same. Private API risk is accepted only behind the feature flag. |

### 5.3 Agent access

- **Identity.** `freedomdesk agent-key new <name>` creates a separate static key (`agents/<name>.key`) and prints its fingerprint. Agents never use the viewer's key, so revoking an agent leaves Petar's access untouched.
- **Transport.** `freedomdesk mcp --host the21th` is a stdio MCP server, likely built on `rmcp`, the official Rust MCP SDK (verify maturity). It opens a normal Noise_XX session with `mode=agent`. There is also a matching CLI, `freedomdesk act the21th screenshot|click X Y|type …|key …`, for scripts and tests.
- **Tools.** Mirror the computer-use toolset names 1:1 [39], plus `list_hosts` and `session_state` (greeter/user/locked, resolution, scale). Screenshots are JPEG/PNG downscaled to ≤1366 px on the long edge, and we keep the scale factor to map coordinates back. Prefer requesting a single keyframe over streaming.
- **Host-side enforcement.** MCP annotations are only hints [40], so enforcement happens in the daemon:
  - per-key scope check on every input message
  - rate limit (e.g. 10 actions/s, 2 screenshots/s)
  - idle timeout (5 min) and max session length (1 h, configurable)
  - while the session state is `greeter`/`locked`, agents get no `type` unless the key has `login` (see 5.5). Credentials never pass through a model [39].
- **Indicator.**
  - On the host: an always-on-top overlay border plus a label, "AI agent ‹name› is controlling". X11: an override-redirect window. Wayland: TBD. macOS: an NSWindow at screen-saver level.
  - On every human viewer attached to that host: a banner.
  - Headless boxes have nobody to see the host overlay, so the viewer banner and the audit log are the real controls.
- **Kill switch.**
  - `freedomdesk kill [--agents|--all]` over SSH or local, plus a "Kick agents" button in the viewer. Both drop sessions in under 1 s.
  - `freedomdesk revoke <FP>` edits the allow-list. It is re-read on each connect, and live sessions are re-checked.
  - A `agents.disabled` flag file blocks all agent sessions daemon-wide.
- **Audit.** One line per action: time, key label, mode, action, coordinates. For `type` we log the length only, not the text. We log a screenshot hash, not the image. Opt-in full-frame recording comes later with P2-3.

### 5.4 Wayland options (decide after the spike)

1. **Mutter direct API** in the session agent, with PipeWire for capture and libei through the `reis` crate for input. This is lightest if it works with no dialog and survives a lock.
2. **Portal with restore tokens.** Needs one approval, and fails on the lock screen [19]. Fits attended support (mum) only.
3. **g-r-d bridge.** The daemon runs g-r-d's system/headless mode and connects to it on loopback as an RDP client (IronRDP is a Rust RDP stack). Re-encoding it into our protocol keeps our auth and audit, and it is the only GNOME-blessed greeter path once GNOME is Wayland-only [8][14]. Costs: double encode, and it is a separate session, not the console [11].

### 5.5 Permissions in `authorized_viewers` (v2, backward-compatible)

```
# FP                         [key=value ...]                         label
L4O7-LFLS-PTVE-HW7U-RR6P-VZWO                                         the20th viewer   # legacy line = view,control
ABCD-…                       perms=view,control,login               petar-macbook
EFGH-…                       perms=view,control kind=agent until=2026-12-31  claude-the20th
IJKL-…                       perms=view kind=agent                  claude-readonly
```

- `view`: see the user session.
- `control`: mouse and keyboard in the user session.
- `login`: see and act on the greeter and lock screen, and type into them. Only Petar's own viewers should get it. Agents get it only explicitly, with a warning on `authorize`.
- `kind=agent`: forces the indicator, per-action audit, rate limits and timeouts, and always shows up as "agent" in UI and logs.
- `until=`: expiry date.
- Future scopes: `clipboard`, `files`.
- Per-machine scope is natural because each host has its own file.
- Parsing rule: a token containing `=` before the label is an attribute. An unknown attribute **denies** the line (fail closed).
- Caveat: an old binary would read the tokens as part of the label and grant full control, so all hosts must upgrade together.
- `freedomdesk authorize <FP> --perms view,control --agent --until …` writes v2 lines.

### 5.6 Crate and module changes

| Crate / module | Purpose |
|---|---|
| `fd-ipc` (new) | Daemon↔agent framing (postcard), peer-credential checks, fd passing |
| `fd-session` (new) | logind watcher (zbus), agent spawn/supervise, `SessionChanged`; macOS launchd/XPC glue |
| `fd-policy` (new) | `authorized_viewers` v2 parser, scopes, rate limits, timeouts, kill flag; moves out of `freedomdesk/src/authorized.rs` |
| `fd-capture` | Add `mutter` (ScreenCast + PipeWire), `portal`, `macos` (ScreenCaptureKit, `CGDisplayStream` fallback) |
| `fd-input` | Add `ei` (reis), `macos` (CGEvent) |
| `fd-display` (new, small) | Linux: check/report mode, xrandr setup. macOS: `CGVirtualDisplay` behind a feature |
| `fd-overlay` (new) | Agent/remote-control indicator per backend |
| `fd-mcp` (new) | stdio MCP server and tool↔protocol mapping, screenshot scaling |
| `fd-proto` | `Hello{mode: viewer\|agent}`, `SessionChanged`, `Screenshot` request, `Kill` |
| `freedomdesk` bin | Subcommands `daemon`, `session-agent`, `mcp`, `act`, `agent-key`, `revoke`, `kill`; `host` stays as the single-session dev mode |
| packaging | systemd unit `freedomdesk.service` (root), Xorg snippet + GDM change as documented opt-in steps; macOS LaunchDaemon + LaunchAgent plists |

## 6. Milestones

These come before or alongside STATUS M4. Each one exits only on a test run on our machines.

| # | Goal | Exit criteria |
|---|---|---|
| **H1** | Headless display + Linux greeter/lock via X11 (manual) | On the21th: TV unplugged, `WaylandEnable=false`, NVIDIA EDID snippet applied, reboot. Then a root-started `freedomdesk host --display :0 --xauthority <gdm>` shows the GDM greeter at a fixed resolution, and login from the viewer works. Lock (Super+L) → unlock from the viewer works. A `pkexec true` polkit dialog is answered remotely. Same on the20th. |
| **H2** | Root daemon + per-session agent (Linux) | systemd system unit. Greeter → login → logout → greeter happens with no viewer reconnect, or auto-reconnect in under 2 s. Survives reboot (T8). Audit records session kind. The pre-auth parser is fuzzed. |
| **H3** | Scoped permissions + kill | v2 allow-list. A view-only key can't inject (negative test). A key without `login` sees "locked" with a placeholder frame, not the greeter. `kill`/`revoke` drop live sessions in under 1 s. |
| **H4** | Agent access (MCP + CLI) | Claude Code on the20th, via `freedomdesk mcp`, opens a terminal on the21th, runs a command and reads the result from a screenshot. The indicator is shown on host and viewer. Per-action audit lines are present. A view-only agent key is refused input. |
| **H5** | Wayland decision | Spike report on 5.4 options 1–3 on a GNOME 46 Wayland session (and GNOME 50 in a VM). Must answer: dialog-free? Survives lock? Reaches the greeter? Then implement the chosen one before any box moves to 26.04. |
| **H6** | macOS host, headless (part of M7) | Mac mini on a dummy plug: reboot → (FileVault: SSH unlock on 26) → login window visible and usable → login → lock → admin-password prompt typed remotely. Plus a written provisioning checklist of TCC grants that need physical presence or MDM. |

## 7. Risks and open questions for Petar

1. **System changes on both boxes need your OK:** GDM `WaylandEnable=false`, an NVIDIA `xorg.conf.d` snippet, and a root systemd service. All are reversible, but they are system-wide.
2. **Auto-login is on for both boxes.** With remote greeter access, do we keep it (box boots straight into a session that then locks) or turn it off (box boots to the greeter)? It also matters for physical security of the Mac and the boxes.
3. **Remote unlock means your login password crosses the wire,** inside Noise, but a stolen viewer key plus `login` scope equals the whole machine. Should `login` require a second factor (TOTP, P2-5) per session?
4. **Agents and passwords:** proposed policy is that agents never get `login` by default and never see credentials. OK?
5. **macOS TCC can't be done remotely.** Choose between one provisioning visit per Mac (grant Screen Recording + Accessibility, enable Screen Sharing and Remote Login as fallbacks) or enrolling the Macs in a self-hosted MDM (e.g. NanoMDM). MDM can pre-grant Accessibility, suppress the monthly prompt and enable Remote Desktop [32][33][36]. MDM is more work but removes most physical visits.
6. **FileVault on the Mac mini:** remote unlock needs macOS 26, Apple Silicon and Remote Login enabled beforehand [37]. Otherwise the alternative is no FileVault, and a reboot then needs someone on site.
7. **Wayland horizon:** 24.04 is supported until 2029, but 26.04 has no X11 session [24]. Mutter's private API may be restricted further, and headless GNOME may become g-r-d-only [14]. Option 3 (bridge) is the hedge.
8. **Root daemon attack surface:** pre-auth parsing runs as root. Mitigations: keep the daemon minimal (no codecs, no UI), sandbox it with systemd (`ProtectSystem`, `NoNewPrivileges` where possible), and fuzz the handshake. Alternative: run as a dedicated user with `CAP_SETUID`/`CAP_SETGID` only.
9. **Unverified items to test first:**
   - Does the NVIDIA proprietary driver honor kernel EDID override (vs Xorg `CustomEDID`)?
   - Do macOS posted keystrokes reach SecurityAgent/login-window password fields?
   - What does Apple Silicon do with no display attached?
   - Does Mutter's direct API survive the GNOME lock screen?

## Sources

1. nvidia-xconfig(1), ConnectedMonitor / CustomEDID — https://www.mankier.com/1/nvidia-xconfig
2. NVIDIA forum, AllowEmptyInitialConfiguration + ConnectedMonitor for headless GNOME — https://forums.developer.nvidia.com/t/quadro-m2000-gdm-fails-to-return-after-each-reboot-on-rhel-7-4/55035
3. Monado EDID override guide — https://gitlab.freedesktop.org/monado/webpage/-/commit/98b23ca6449e4c9d5146bb5b0d34740176d100d5 ; video=…:e caveat — https://lists.freedesktop.org/archives/dri-devel/attachments/20180728/cb9b5d08/attachment.html
4. Dummy driver guides — https://techoverflow.net/2019/02/23/how-to-run-x-server-using-xserver-xorg-video-dummy-driver-on-ubuntu ; https://docs.dwservice.net/docs/site/troubleshootfaq/set-up-a-device-without-a-monitor-headless/
5. Mutter headless backend MR — https://gitlab.gnome.org/GNOME/mutter/-/merge_requests/1698 ; https://www.phoronix.com/news/GNOME-40-Headless-Virtual
6. Fedora: headless mutter fails to get ScreenCast/RemoteDesktop names — https://discussion.fedoraproject.org/t/remote-desktop-works-only-with-attached-display/77879
7. Kernel vkms docs — https://docs.kernel.org/gpu/vkms.html
8. SUSE, Headless remote sessions in GNOME pt. 2 — https://www.suse.com/c/headless-remote-sessions-in-gnome-part-2
9. Phoronix, GNOME 46 RDP remote login — https://www.phoronix.com/news/GNOME-RDP-Remote-Login
10. g-r-d configuration docs — https://github.com/GNOME/gnome-remote-desktop/blob/main/docs/configuration.md
11. c-nergy review of GNOME remote login — https://c-nergy.be/blog/?p=19594
12. GDM issue 900, same user logged in twice — https://gitlab.gnome.org/GNOME/gdm/-/issues/900 ; "Session Already Running" on Ubuntu — https://discuss.kde.org/t/is-it-possible-to-have-rdp-without-console-access/31830
13. CVE-2024-5148 g-r-d — https://www.openwall.com/lists/oss-security/2024/05/24/1 ; https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/issues/196
14. TigerVNC maintainer on headless GNOME (Nov 2025) — https://groups.google.com/g/tigervnc-users/c/WQNulZS-7KI
15. RustDesk Linux docs — https://rustdesk.com/docs/en/client/linux
16. RustDesk issue 220 — https://github.com/rustdesk/rustdesk/issues/220
17. RemoteDesktop portal spec — https://flatpak.github.io/xdg-desktop-portal/docs/_sources/doc-org.freedesktop.portal.RemoteDesktop.rst.txt
18. libportal ConnectToEIS — https://valadoc.org/libportal/Xdp.Session.html ; libei in portals — https://lists.freedesktop.org/archives/wayland-devel/2023-July/042893.html
19. Pinggy, Wayland unattended access and lock-screen behaviour — https://pinggy.io/blog/remote_desktop_into_wayland_without_a_vps/
20. GNOME Discourse, security of Mutter ScreenCast — https://discourse.gnome.org/t/security-for-mutter-screencast/35009
21. gnome-shell DBusSenderChecker — https://lists.gnome.org/archives/commits-list/2021-September/msg01056.html
22. RH bug: GNOME 41+ blocks private D-Bus APIs — https://bugzilla.redhat.com/show_bug.cgi?id=2055366
23. Mutter RemoteDesktop/ScreenCast automation write-up (conflicting on dialogs) — https://dev.to/the_bomber_f1e42beb1feaec/desktop-automation-on-gnome-wayland-without-root-using-mutter-remotedesktop-and-screencast-over-d24
24. Ubuntu 26.04 drops Xorg session — https://www.omgubuntu.co.uk/2026/04/ubuntu-26-04-lts-released ; https://www.theregister.com/2026/04/24/ubuntu_resolute_raccoon/
25. Apple DTS on login-window capture, daemon+agent, SCK from 14.4 — https://developer.apple.com/forums/thread/814152 ; https://developer.apple.com/forums/thread/692749
26. SMAppService LoginWindow agent not starting — https://developer.apple.com/forums/thread/726864
27. Headless Mac mini displays / dummy plugs — https://astropad.com/blog/dummy-plug-headless-mac-mini/ ; BetterDummy — https://github.com/Brezel31/BetterDummy
28. CGVirtualDisplay wrapper notes — https://pkg.go.dev/github.com/go-macos/virtualdisplay
29. Objective-See, Synthetic Reality — https://objective-see.org/blog/blog_0x36.html
30. Apple forums: Allow can't be clicked via Screen Sharing — https://developer.apple.com/forums/thread/87924 ; macOS 15 dialogs not clickable by remote robot — https://developer.apple.com/forums/thread/808391
31. Clicks via ARD/TeamViewer blocked for extension approval — https://automatica-astro.pages.dev/2020/04/allow-clicks-in-system-preferences-to-permit-system-extensions-via-apple-remote-desktop-or-teamviewer
32. PPPC limits (ScreenCapture standard-user only) — https://community.jamf.com/general-discussions-2/beyondtrust-remote-support-sequoia-remote-desktop-35321 ; https://kb.wisc.edu/124636
33. forceBypassScreenCaptureAlert — https://docs.fortinet.com/document/fortidlp-agent/latest/fortidlp-agent-deployment-guide/419245/permitting-user-controlled-agent-functionality-on-macos
34. Jamf thread on monthly prompts — https://community.jamf.com/t5/jamf-pro/monthly-tccc-prompts-macos-v15/m-p/326764
35. TidBITS on monthly prompt and persistent-content-capture — https://tidbits.com/2024/08/19/apple-reduces-excessive-sequoia-permission-requests-shifts-to-monthly
36. Apple: kickstart can't enable Screen Sharing on 12.1+ — https://support.apple.com/guide/remote-desktop/apd8b1c65bd/mac
37. FileVault SSH unlock in macOS 26 — https://www.jeffgeerling.com/blog/2025/you-can-finally-manage-macs-filevault-remotely-tahoe/
38. Secure Event Input blocks event taps — https://forum.cursor.com/t/cursor-leaks-secure-event-input-breaks-all-system-wide-input-taps-until-quit-or-screen-lock/167585
39. Anthropic computer-use tool docs — https://platform.claude.com/docs/en/agents-and-tools/tool-use/computer-use-tool
40. MCP spec 2025-11-25, Tools — https://modelcontextprotocol.io/specification/2025-11-25/server/tools
41. VNC MCP servers — https://glama.ai/mcp/servers/hrrrsn/mcp-vnc/tree ; https://pypi.org/project/mcvnc/ ; https://dev.to/remrearas/claude-kvm-1ffc
