//! FreedomDesk application-level wire messages.
//!
//! These travel *inside* the encrypted Noise channel (see `fd-crypto`); nothing
//! here is ever sent in cleartext. Encoding is postcard (compact, serde-based).
//! Bump [`PROTOCOL_VERSION`] on any incompatible change.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

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
    },
    /// Host user (or policy) refused the session.
    Denied { reason: String },
    /// One encoded H.264 access unit (Annex-B).
    Video {
        seq: u64,
        keyframe: bool,
        /// Host monotonic capture timestamp, microseconds since session start.
        ts_us: u64,
        data: Vec<u8>,
    },
    Pong { ts_us: u64 },
    Bye { reason: String },
}

/// Messages viewer → host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ViewerMsg {
    Hello { protocol: u16, viewer_name: String },
    Input(InputEvent),
    RequestKeyframe,
    Ping { ts_us: u64 },
    Bye,
}

pub fn encode<T: Serialize>(msg: &T) -> anyhow::Result<Vec<u8>> {
    Ok(postcard::to_stdvec(msg)?)
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> anyhow::Result<T> {
    Ok(postcard::from_bytes(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let m = ViewerMsg::Input(InputEvent::Text { ch: 'Ж' });
        let b = encode(&m).unwrap();
        assert_eq!(decode::<ViewerMsg>(&b).unwrap(), m);
        let h = HostMsg::Video { seq: 7, keyframe: true, ts_us: 42, data: vec![0, 0, 0, 1, 0x67] };
        let b = encode(&h).unwrap();
        assert_eq!(decode::<HostMsg>(&b).unwrap(), h);
    }

    #[test]
    fn garbage_rejected() {
        assert!(decode::<HostMsg>(&[0xff, 0xff, 0xff]).is_err());
    }
}
