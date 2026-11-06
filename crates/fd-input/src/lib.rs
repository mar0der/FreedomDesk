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
}

/// Open the platform injector. `screen_*` is the native size of the captured
/// area that normalised pointer coordinates map onto.
#[cfg(target_os = "linux")]
pub fn open_default(screen_width: u32, screen_height: u32) -> anyhow::Result<Box<dyn InputInjector>> {
    let display = std::env::var_os("DISPLAY").filter(|d| !d.is_empty());
    if display.is_none() {
        anyhow::bail!(
            "fd-input: DISPLAY is not set; only X11 (XTest) injection is supported yet \
             (Wayland via uinput / RemoteDesktop portal is future work)"
        );
    }
    if std::env::var("XDG_SESSION_TYPE").is_ok_and(|t| t == "wayland") {
        log::warn!("fd-input: Wayland session detected; XTest via XWayland only reaches X11 clients");
    }
    Ok(Box::new(x11::XTestInjector::open(screen_width, screen_height)?))
}

#[cfg(not(target_os = "linux"))]
pub fn open_default(_screen_width: u32, _screen_height: u32) -> anyhow::Result<Box<dyn InputInjector>> {
    anyhow::bail!("fd-input: input injection is not supported on this OS yet")
}
