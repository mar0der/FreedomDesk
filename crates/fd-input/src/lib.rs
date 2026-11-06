//! Input injection on the host.
//!
//! Linux/X11: XTest via x11rb (see `x11.rs`). Wayland (uinput / RemoteDesktop
//! portal), macOS and Windows backends are future work; `open_default` returns
//! a clear error there so the workspace still builds everywhere.

use fd_proto::InputEvent;

pub mod keysym;

#[cfg(target_os = "linux")]
mod x11;

pub trait InputInjector: Send {
    fn inject(&mut self, ev: &InputEvent) -> anyhow::Result<()>;
    /// Release every key/button this injector currently holds down (call on disconnect).
    fn release_all(&mut self) -> anyhow::Result<()>;
    /// The captured screen changed size; normalised pointer coordinates map onto the new size.
    fn set_screen_size(&mut self, width: u32, height: u32);
}

/// Undo keyboard-mapping changes left behind by this process (or by dead
/// FreedomDesk host processes on the same display): spare keycodes borrowed
/// for typing are reset to NoSymbol. Opens its own X connection. Not
/// async-signal-safe: call it from normal code, e.g. a thread that waits for
/// SIGTERM/SIGINT, before exiting. `open_default` also does this for dead
/// processes automatically, and dropping an injector restores its own bindings.
#[cfg(target_os = "linux")]
pub fn emergency_cleanup() -> anyhow::Result<()> {
    if std::env::var_os("DISPLAY").is_none_or(|d| d.is_empty()) {
        return Ok(());
    }
    x11::emergency_cleanup()
}

#[cfg(not(target_os = "linux"))]
pub fn emergency_cleanup() -> anyhow::Result<()> {
    Ok(())
}

/// Open the platform injector. `screen_*` is the native size of the captured
/// area that normalised pointer coordinates map onto.
#[cfg(target_os = "linux")]
pub fn open_default(
    screen_width: u32,
    screen_height: u32,
) -> anyhow::Result<Box<dyn InputInjector>> {
    let display = std::env::var_os("DISPLAY").filter(|d| !d.is_empty());
    if display.is_none() {
        anyhow::bail!(
            "fd-input: DISPLAY is not set; only X11 (XTest) injection is supported yet \
             (Wayland via uinput / RemoteDesktop portal is future work)"
        );
    }
    if std::env::var("XDG_SESSION_TYPE").is_ok_and(|t| t == "wayland") {
        log::warn!(
            "fd-input: Wayland session detected; XTest via XWayland only reaches X11 clients"
        );
    }
    Ok(Box::new(x11::XTestInjector::open(
        screen_width,
        screen_height,
    )?))
}

#[cfg(not(target_os = "linux"))]
pub fn open_default(
    _screen_width: u32,
    _screen_height: u32,
) -> anyhow::Result<Box<dyn InputInjector>> {
    anyhow::bail!("fd-input: input injection is not supported on this OS yet")
}
