//! Screen capture.
//!
//! Backends:
//! - Linux X11 (`x11` module): MIT-SHM fast path, plain `GetImage` fallback.
//! - Linux Wayland / PipeWire, macOS ScreenCaptureKit, Windows DXGI: not implemented yet.

#[cfg(target_os = "linux")]
mod x11;

#[cfg(target_os = "linux")]
pub use x11::X11Capturer;

/// One captured frame, 32 bpp **BGRX** (bytes in memory: B, G, R, X), top-down rows.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    /// Bytes per row (>= width * 4).
    pub stride: usize,
    pub data: Vec<u8>,
}

impl Frame {
    /// Borrowed view of this frame.
    pub fn view(&self) -> FrameRef<'_> {
        FrameRef {
            width: self.width,
            height: self.height,
            stride: self.stride,
            data: &self.data,
        }
    }
}

/// Borrowed captured frame, same layout as [`Frame`] (BGRX, top-down, `stride` bytes per row).
/// Returned by [`Capturer::capture_if_changed`] without copying (e.g. straight out of the X
/// shared-memory segment); the borrow ends at the next capture call.
#[derive(Clone, Copy)]
pub struct FrameRef<'a> {
    pub width: u32,
    pub height: u32,
    pub stride: usize,
    pub data: &'a [u8],
}

impl<'a> From<&'a Frame> for FrameRef<'a> {
    fn from(f: &'a Frame) -> Self {
        f.view()
    }
}

/// Cut a sub-rectangle out of a frame without copying (same stride; the last row ends right
/// after the crop). The rectangle is clamped to the frame; if nothing overlaps the result is
/// 0x0 with empty data.
pub fn crop<'a>(f: FrameRef<'a>, x: u32, y: u32, w: u32, h: u32) -> FrameRef<'a> {
    let empty = FrameRef {
        width: 0,
        height: 0,
        stride: f.stride,
        data: &[],
    };
    let (x, y) = (x.min(f.width), y.min(f.height));
    let (w, h) = (w.min(f.width - x), h.min(f.height - y));
    if w == 0 || h == 0 {
        return empty;
    }
    let start = y as usize * f.stride + x as usize * 4;
    let len = (h as usize - 1) * f.stride + w as usize * 4;
    match f.data.get(start..start + len) {
        Some(data) => FrameRef {
            width: w,
            height: h,
            stride: f.stride,
            data,
        },
        None => empty, // malformed input (data shorter than its geometry)
    }
}

/// Largest cursor shape handed out by [`Capturer::cursor`] (bigger ones are cropped around the
/// hotspot).
pub const MAX_CURSOR_SHAPE: u32 = 256;

/// Mouse cursor state for drawing it on the viewer side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorInfo {
    /// Pointer (hotspot) position in captured-area pixels.
    pub x: i32,
    pub y: i32,
    /// False if the pointer is on another screen or the cursor image is fully transparent.
    pub visible: bool,
    /// Changes whenever the cursor image changes.
    pub serial: u32,
    /// Present on the first call and whenever `serial` changed since the previous call.
    pub shape: Option<CursorShape>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    pub width: u32,
    pub height: u32,
    pub xhot: u32,
    pub yhot: u32,
    /// Straight (non-premultiplied) RGBA8, `width * height * 4` bytes.
    pub rgba: Vec<u8>,
}

pub trait Capturer: Send {
    /// Native size of the captured area in pixels.
    fn size(&self) -> (u32, u32);
    /// Grab the current screen contents. The returned frame is reused between calls.
    fn capture(&mut self) -> anyhow::Result<&Frame>;

    /// Grab the screen unless nothing changed since the previous capture (either kind):
    /// returns `Ok(None)` cheaply, without grabbing, when neither the screen contents nor the
    /// cursor (position/shape, if drawn) changed. Backends that cannot tell always grab.
    ///
    /// Zero-copy where possible (X11: borrowed straight from the MIT-SHM segment), so prefer
    /// this over `capture()` in the streaming loop. Use `capture()` for an unconditional grab
    /// (e.g. the first frame / keyframe requests) — after `capture()` the next
    /// `capture_if_changed()` is relative to that grab.
    fn capture_if_changed(&mut self) -> anyhow::Result<Option<FrameRef<'_>>> {
        self.capture().map(|f| Some(f.view()))
    }

    /// Unconditional grab, zero-copy where possible (see `capture_if_changed`).
    fn capture_ref(&mut self) -> anyhow::Result<FrameRef<'_>> {
        self.capture().map(|f| f.view())
    }

    /// Draw the mouse cursor into captured frames (default: on, where supported). When off,
    /// cursor motion/shape changes do not count as changes for `capture_if_changed` (use
    /// [`cursor`](Self::cursor) to send the cursor separately).
    fn set_draw_cursor(&mut self, _on: bool) {}

    /// Current cursor position (cheap: one round trip) plus its shape when it changed since
    /// the previous call. `Ok(None)` if the backend can't report the cursor.
    fn cursor(&mut self) -> anyhow::Result<Option<CursorInfo>> {
        Ok(None)
    }

    /// Number of display outputs currently showing a picture (lit CRTCs), if known.
    /// `Some(0)` means no monitor is driven: GPU compositors (NVIDIA + GNOME) then
    /// repaint only about once a second, so streams drop to ~1 fps.
    fn active_outputs(&mut self) -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: u32, h: u32) -> Frame {
        let stride = w as usize * 4 + 8;
        let mut data = vec![0u8; stride * h as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                data[y * stride + x * 4] = x as u8;
                data[y * stride + x * 4 + 1] = y as u8;
            }
        }
        Frame {
            width: w,
            height: h,
            stride,
            data,
        }
    }

    #[test]
    fn crop_inside() {
        let f = frame(40, 30);
        let c = crop(f.view(), 5, 7, 11, 9);
        assert_eq!((c.width, c.height, c.stride), (11, 9, f.stride));
        assert_eq!(c.data.len(), 8 * f.stride + 11 * 4);
        assert_eq!((c.data[0], c.data[1]), (5, 7));
        let last = 8 * c.stride + 10 * 4;
        assert_eq!((c.data[last], c.data[last + 1]), (15, 15));
    }

    #[test]
    fn crop_clamps() {
        let f = frame(40, 30);
        let c = crop(f.view(), 30, 25, 100, 100);
        assert_eq!((c.width, c.height), (10, 5));
        assert_eq!(c.data.len(), 4 * f.stride + 10 * 4);
        let full = crop(f.view(), 0, 0, u32::MAX, u32::MAX);
        assert_eq!((full.width, full.height), (40, 30));
        for (x, y, w, h) in [
            (40, 0, 5, 5),
            (0, 30, 5, 5),
            (u32::MAX, u32::MAX, 1, 1),
            (3, 3, 0, 4),
        ] {
            let e = crop(f.view(), x, y, w, h);
            assert_eq!((e.width, e.height, e.data.len()), (0, 0, 0));
        }
        // Crop of a crop.
        let c2 = crop(crop(f.view(), 10, 10, 20, 20), 5, 5, 3, 3);
        assert_eq!((c2.data[0], c2.data[1]), (15, 15));
        // Malformed source (data too short for its geometry) does not panic.
        let bad = FrameRef {
            width: 40,
            height: 30,
            stride: f.stride,
            data: &f.data[..100],
        };
        assert_eq!(crop(bad, 0, 10, 5, 5).width, 0);
    }
}

/// Returned (inside `anyhow::Error`) by [`Capturer::capture`] when the captured screen changed
/// size since the capturer was opened. The capturer is then unusable; open a new one
/// (and a new encoder). Detect with `err.downcast_ref::<ScreenResized>()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenResized {
    pub old: (u32, u32),
    pub new: (u32, u32),
}

impl std::fmt::Display for ScreenResized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "screen resized from {}x{} to {}x{}; reopen the capturer",
            self.old.0, self.old.1, self.new.0, self.new.1
        )
    }
}

impl std::error::Error for ScreenResized {}

/// Open the best capturer for this platform/session.
pub fn open_default() -> anyhow::Result<Box<dyn Capturer>> {
    platform_open_default()
}

#[cfg(target_os = "linux")]
fn platform_open_default() -> anyhow::Result<Box<dyn Capturer>> {
    let display = std::env::var_os("DISPLAY").filter(|d| !d.is_empty());
    if display.is_some() {
        return Ok(Box::new(X11Capturer::open(None)?));
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        anyhow::bail!(
            "fd-capture: Wayland session without DISPLAY; Wayland/PipeWire capture is not implemented yet \
             (log into an Xorg session, or set DISPLAY to an X server)"
        );
    }
    anyhow::bail!(
        "fd-capture: DISPLAY is not set; only X11 capture is implemented (Wayland/PipeWire capture is not implemented yet)"
    )
}

#[cfg(not(target_os = "linux"))]
fn platform_open_default() -> anyhow::Result<Box<dyn Capturer>> {
    anyhow::bail!("fd-capture: screen capture is not supported on this platform yet")
}
