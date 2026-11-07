# Clipboard sync (text)

Opt-in, text-only, viewer <-> host. Off unless **both** sides enable it.

- Host: `freedomdesk host --clipboard`
- Viewer: `freedomdesk view --clipboard`, or the "Share clipboard" checkbox on the launcher (applies to the next connection)

## Compatibility and negotiation

postcard cannot skip an unknown enum variant, and both sides hard-reject a `protocol` value other than their own, so a new message must never reach an old peer and `PROTOCOL_VERSION` stays 2.

Features are capability bits (`fd_proto::caps`) appended as a trailing `caps: u32` field of `ViewerMsg::Hello` and `HostMsg::Welcome`:

1. An old host decodes `Hello` with `postcard::from_bytes`, which ignores trailing bytes, so it sees a normal v2 Hello. An old viewer does the same with `Welcome`.
2. A new host/viewer decodes with `decode_viewer` / `decode_host`, which fall back to the capability-less layout (caps = 0) when the trailing field is missing.
3. The viewer offers bits in `Hello`; the host answers in `Welcome` with the intersection of the viewer's offer and what the host allows. The viewer masks that again against its own offer.
4. `ViewerMsg::Clipboard` / `HostMsg::Clipboard` are appended as the last enum variants (existing indices unchanged) and are sent only if the negotiated bit for that direction is set. An old peer therefore never receives one. Unnegotiated incoming clipboard messages are dropped.

| viewer | host | result |
|---|---|---|
| old | new (`--clipboard`) | works, no clipboard (caps = 0) |
| new (`--clipboard`) | old | works, no clipboard (Welcome carries no caps) |
| new, flag off | new `--clipboard` | no clipboard |
| new `--clipboard` | new, flag off | no clipboard |
| both on | both on | both directions |
| both on | host view-only | host -> viewer only |

Tests: `crates/fd-proto/src/lib.rs` (wire compatibility against verbatim copies of the old enums) and `crates/freedomdesk/src/clipboard.rs` (negotiation, echo suppression, caps, view-only).

## Behaviour

- Each side polls its local clipboard every 500 ms. The content present when the session starts is recorded and **never** sent; only later changes are.
- Echo suppression: a digest of the last text seen or written is kept; text we just wrote is not sent back, so the sides never ping-pong.
- Direction bits: `CLIPBOARD_TO_HOST` (viewer writes host) and `CLIPBOARD_TO_VIEWER`. A view-only host (`--view-only`, or input injection unavailable) never grants `CLIPBOARD_TO_HOST`, so a view-only session never writes the host clipboard.
- Backend: `arboard` (X11 on Linux, NSPasteboard on macOS) behind the `ClipboardBackend` trait. Wayland-native clipboards are not supported yet.

## Threat model

Assets: whatever the user copies (passwords, tokens). Peers are already authenticated (Noise, pinned keys) and, on the host, consented; clipboard is an extra channel on that session.

- **Off by default** on both sides; the host operator alone decides to expose its clipboard; the viewer user alone decides to share theirs.
- **Text only**, UTF-8, at most 1 MiB. Oversized text is dropped, not truncated.
- **Sanitised** on receive and send: CR/CRLF -> LF; NUL, ESC and other control characters (except newline and tab) and bidi override characters are removed; whitespace-only text is dropped. This limits terminal-escape and hidden-text tricks, but pasting text into a shell is still the user's risk; a malicious host can place a command on the viewer's clipboard (and vice versa).
- **No content in logs.** Debug and audit output carry byte lengths only. The host audit log gets one line per transfer: `clipboard=viewer_to_host bytes=N` or `host_to_viewer`. The viewer logs the same under the `audit` log target.
- Pre-session clipboard content is never transmitted.
- Not covered: rate limiting beyond the 500 ms poll, per-transfer consent prompts, clipboard history managers on the peer that may persist copied text.
