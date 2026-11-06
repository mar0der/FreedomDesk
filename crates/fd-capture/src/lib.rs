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

    /// Draw the mouse cursor into captured frames (default: on, where supported).
    fn set_draw_cursor(&mut self, _on: bool) {}
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
