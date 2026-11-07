//! FreedomDesk application-level wire messages.
//!
//! These travel *inside* the encrypted Noise channel (see `fd-crypto`); nothing
//! here is ever sent in cleartext. Encoding is postcard (compact, serde-based).
//! Bump [`PROTOCOL_VERSION`] on any incompatible change.

use serde::{Deserialize, Serialize};

/// v2: Video carries its screen region; cursor is a separate channel; viewer sets its view.
pub const PROTOCOL_VERSION: u16 = 2;

/// Optional features, negotiated in `Hello`/`Welcome` (`Hello::caps`, `Welcome::caps`).
///
/// **Compatibility rule:** a peer only ever receives message variants it has
/// advertised support for. postcard cannot skip an unknown enum variant, so an
/// unannounced new message would kill an old peer's session. [`PROTOCOL_VERSION`]
/// therefore stays 2 (old peers hard-reject any other value) and features are
/// added as capability bits that ride *after* the v2 fields of Hello/Welcome.
pub mod caps {
    /// Viewer → host text clipboard (host writes its clipboard).
    pub const CLIPBOARD_TO_HOST: u32 = 1 << 0;
    /// Host → viewer text clipboard (viewer writes its clipboard).
    pub const CLIPBOARD_TO_VIEWER: u32 = 1 << 1;
    /// Every bit this build understands; unknown bits from peers are masked off.
    pub const KNOWN: u32 = CLIPBOARD_TO_HOST | CLIPBOARD_TO_VIEWER;

    /// What a session may use: the intersection of both offers, known bits only.
    pub fn negotiate(viewer_offer: u32, host_offer: u32) -> u32 {
        viewer_offer & host_offer & KNOWN
    }
}

/// Maximum clipboard payload (UTF-8 bytes) in either direction.
pub const CLIPBOARD_MAX_BYTES: usize = 1024 * 1024;

/// Default TCP port for the host agent.
pub const DEFAULT_PORT: u16 = 47801;

/// Normalised coordinate range for pointer positions (0..=NORM_MAX spans the remote screen).
pub const NORM_MAX: u16 = u16::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    Back,
    Forward,
}

/// Rectangle in host screen pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

/// Input event sent viewer → host.
///
/// Keys are identified by **X11 keysym values** (a stable, documented,
/// layout-independent namespace; e.g. Return = 0xff0d, Shift_L = 0xffe1,
/// 'a' = 0x61). Non-X11 hosts translate keysyms to their native key codes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InputEvent {
    /// Absolute pointer position, normalised: 0 = left/top, NORM_MAX = right/bottom.
    MouseMove { x: u16, y: u16 },
    MouseButton { button: MouseButton, down: bool },
    /// Scroll in wheel notches. Positive `dy` = scroll up, positive `dx` = scroll right.
    Scroll { dx: i16, dy: i16 },
    /// Press or release a key by keysym (used for modifiers, navigation, shortcuts).
    Key { keysym: u32, down: bool },
    /// Type one character (press + release), host picks the key and shift level.
    Text { ch: char },
}

/// Messages host → viewer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HostMsg {
    /// Session accepted. `screen_*` is the host's native capture size,
    /// `video_*` the encoded stream size (may be downscaled).
    Welcome {
        protocol: u16,
        host_name: String,
        screen_width: u32,
        screen_height: u32,
        video_width: u32,
        video_height: u32,
        /// Negotiated capability bits ([`caps`]). Trailing field: v2 viewers
        /// ignore the extra bytes. Absent (0) when an old host sent the message.
        caps: u32,
    },
    /// Host user (or policy) refused the session.
    Denied { reason: String },
    /// One encoded H.264 access unit (Annex-B) showing `region` of a
    /// `screen_width`×`screen_height` screen (the viewer's zoom crop).
    Video {
        seq: u64,
        keyframe: bool,
        /// Host monotonic capture timestamp, microseconds since session start.
        ts_us: u64,
        region: Rect,
        screen_width: u32,
        screen_height: u32,
        data: Vec<u8>,
    },
    /// New pointer image (straight RGBA8, ≤ 256×256). The viewer draws the
    /// cursor itself, so pointer motion never waits for video.
    CursorShape { serial: u32, width: u32, height: u32, xhot: u32, yhot: u32, rgba: Vec<u8> },
    /// Host pointer position in screen pixels.
    CursorPos { x: i32, y: i32, visible: bool },
    Pong { ts_us: u64 },
    Bye { reason: String },
    /// Host clipboard text (UTF-8, ≤ [`CLIPBOARD_MAX_BYTES`]). Only sent when
    /// [`caps::CLIPBOARD_TO_VIEWER`] was negotiated. MUST stay the last variant
    /// appended so existing variant indices never change.
    Clipboard { text: String },
}

/// Messages viewer → host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ViewerMsg {
    /// `caps` is a trailing field: v2 hosts ignore the extra bytes; new hosts
    /// accept its absence (see [`decode_viewer`]).
    Hello { protocol: u16, viewer_name: String, caps: u32 },
    Input(InputEvent),
    RequestKeyframe,
    /// The part of the screen the viewer shows (normalised 0..=NORM_MAX) and
    /// the physical pixel size it is shown at. The host crops and scales to it.
    SetView { x: u16, y: u16, w: u16, h: u16, max_width: u32, max_height: u32 },
    Ping { ts_us: u64 },
    Bye,
    /// Viewer clipboard text; only sent when [`caps::CLIPBOARD_TO_HOST`] was negotiated.
    Clipboard { text: String },
}

/// The capability-less `Hello` / `Welcome` exactly as v2 peers without caps encode them.
/// Variant 0 of the respective enum, so decoding falls back to these.
#[derive(Deserialize)]
struct LegacyHello {
    protocol: u16,
    viewer_name: String,
}
#[derive(Deserialize)]
struct LegacyWelcome {
    protocol: u16,
    host_name: String,
    screen_width: u32,
    screen_height: u32,
    video_width: u32,
    video_height: u32,
}

pub fn encode<T: Serialize>(msg: &T) -> anyhow::Result<Vec<u8>> {
    Ok(postcard::to_stdvec(msg)?)
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> anyhow::Result<T> {
    Ok(postcard::from_bytes(bytes)?)
}

/// Decode a viewer message, accepting a capability-less `Hello` from an old viewer (caps = 0).
pub fn decode_viewer(bytes: &[u8]) -> anyhow::Result<ViewerMsg> {
    match decode::<ViewerMsg>(bytes) {
        Ok(m) => Ok(m),
        Err(e) if bytes.first() == Some(&0) => {
            let h: LegacyHello = decode(&bytes[1..]).map_err(|_| e)?;
            Ok(ViewerMsg::Hello { protocol: h.protocol, viewer_name: h.viewer_name, caps: 0 })
        }
        Err(e) => Err(e),
    }
}

/// Decode a host message, accepting a capability-less `Welcome` from an old host (caps = 0).
pub fn decode_host(bytes: &[u8]) -> anyhow::Result<HostMsg> {
    match decode::<HostMsg>(bytes) {
        Ok(m) => Ok(m),
        Err(e) if bytes.first() == Some(&0) => {
            let w: LegacyWelcome = decode(&bytes[1..]).map_err(|_| e)?;
            Ok(HostMsg::Welcome {
                protocol: w.protocol,
                host_name: w.host_name,
                screen_width: w.screen_width,
                screen_height: w.screen_height,
                video_width: w.video_width,
                video_height: w.video_height,
                caps: 0,
            })
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let m = ViewerMsg::Input(InputEvent::Text { ch: 'Ж' });
        let b = encode(&m).unwrap();
        assert_eq!(decode::<ViewerMsg>(&b).unwrap(), m);
        let h = HostMsg::Video {
            seq: 7,
            keyframe: true,
            ts_us: 42,
            region: Rect { x: 1, y: 2, w: 3, h: 4 },
            screen_width: 3840,
            screen_height: 2160,
            data: vec![0, 0, 0, 1, 0x67],
        };
        let b = encode(&h).unwrap();
        assert_eq!(decode::<HostMsg>(&b).unwrap(), h);
    }

    /// Verbatim copies of the pre-clipboard enums as an old (v2, no caps) peer has them.
    mod old {
        use super::super::{InputEvent, Rect};
        use serde::{Deserialize, Serialize};

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        pub enum HostMsg {
            Welcome { protocol: u16, host_name: String, screen_width: u32, screen_height: u32, video_width: u32, video_height: u32 },
            Denied { reason: String },
            Video { seq: u64, keyframe: bool, ts_us: u64, region: Rect, screen_width: u32, screen_height: u32, data: Vec<u8> },
            CursorShape { serial: u32, width: u32, height: u32, xhot: u32, yhot: u32, rgba: Vec<u8> },
            CursorPos { x: i32, y: i32, visible: bool },
            Pong { ts_us: u64 },
            Bye { reason: String },
        }
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        pub enum ViewerMsg {
            Hello { protocol: u16, viewer_name: String },
            Input(InputEvent),
            RequestKeyframe,
            SetView { x: u16, y: u16, w: u16, h: u16, max_width: u32, max_height: u32 },
            Ping { ts_us: u64 },
            Bye,
        }
    }

    fn welcome(caps: u32) -> HostMsg {
        HostMsg::Welcome {
            protocol: PROTOCOL_VERSION,
            host_name: "h".into(),
            screen_width: 1,
            screen_height: 2,
            video_width: 3,
            video_height: 4,
            caps,
        }
    }

    #[test]
    fn clipboard_messages_roundtrip() {
        let m = ViewerMsg::Clipboard { text: "здравей\nworld".into() };
        assert_eq!(decode_viewer(&encode(&m).unwrap()).unwrap(), m);
        let m = HostMsg::Clipboard { text: "x".into() };
        assert_eq!(decode_host(&encode(&m).unwrap()).unwrap(), m);
    }

    #[test]
    fn existing_variant_indices_unchanged() {
        let old_msgs = [old::ViewerMsg::Bye, old::ViewerMsg::RequestKeyframe, old::ViewerMsg::Ping { ts_us: 9 }];
        for m in old_msgs {
            let bytes = postcard::to_stdvec(&m).unwrap();
            let new: ViewerMsg = decode(&bytes).unwrap();
            assert_eq!(postcard::to_stdvec(&new).unwrap(), bytes);
        }
        let m = old::HostMsg::Pong { ts_us: 5 };
        assert_eq!(decode_host(&postcard::to_stdvec(&m).unwrap()).unwrap(), HostMsg::Pong { ts_us: 5 });
    }

    #[test]
    fn old_viewer_hello_accepted_by_new_host_without_caps() {
        let hello = old::ViewerMsg::Hello { protocol: 2, viewer_name: "old".into() };
        let bytes = postcard::to_stdvec(&hello).unwrap();
        let got = decode_viewer(&bytes).unwrap();
        assert_eq!(got, ViewerMsg::Hello { protocol: 2, viewer_name: "old".into(), caps: 0 });
        // Strict decode fails, which is why the fallback exists.
        assert!(decode::<ViewerMsg>(&bytes).is_err());
    }

    #[test]
    fn new_viewer_hello_accepted_by_old_host() {
        let hello = ViewerMsg::Hello { protocol: PROTOCOL_VERSION, viewer_name: "new".into(), caps: caps::KNOWN };
        let old_view: old::ViewerMsg = decode(&encode(&hello).unwrap()).unwrap();
        assert_eq!(old_view, old::ViewerMsg::Hello { protocol: 2, viewer_name: "new".into() });
    }

    #[test]
    fn old_host_welcome_accepted_by_new_viewer_without_caps() {
        let w = old::HostMsg::Welcome {
            protocol: 2,
            host_name: "h".into(),
            screen_width: 1,
            screen_height: 2,
            video_width: 3,
            video_height: 4,
        };
        assert_eq!(decode_host(&postcard::to_stdvec(&w).unwrap()).unwrap(), welcome(0));
    }

    #[test]
    fn new_host_welcome_accepted_by_old_viewer() {
        let b = encode(&welcome(caps::CLIPBOARD_TO_HOST)).unwrap();
        let got: old::HostMsg = decode(&b).unwrap();
        assert!(matches!(got, old::HostMsg::Welcome { protocol: 2, screen_height: 2, .. }));
    }

    #[test]
    fn old_peers_cannot_decode_clipboard_so_it_must_never_be_sent() {
        let v = encode(&ViewerMsg::Clipboard { text: "secret".into() }).unwrap();
        assert!(decode::<old::ViewerMsg>(&v).is_err());
        let h = encode(&HostMsg::Clipboard { text: "secret".into() }).unwrap();
        assert!(decode::<old::HostMsg>(&h).is_err());
    }

    #[test]
    fn negotiation_matrix() {
        use caps::*;
        // (viewer offer, host offer, result)
        let cases = [
            (0, 0, 0),
            (KNOWN, 0, 0),
            (0, KNOWN, 0),
            (KNOWN, KNOWN, KNOWN),
            (KNOWN, CLIPBOARD_TO_VIEWER, CLIPBOARD_TO_VIEWER),
            (CLIPBOARD_TO_HOST, CLIPBOARD_TO_VIEWER, 0),
            (KNOWN | 1 << 20, KNOWN | 1 << 21, KNOWN),
        ];
        for (v, h, want) in cases {
            assert_eq!(negotiate(v, h), want, "viewer {v:#x} host {h:#x}");
        }
    }

    #[test]
    fn garbage_rejected() {
        assert!(decode::<HostMsg>(&[0xff, 0xff, 0xff]).is_err());
    }
}
