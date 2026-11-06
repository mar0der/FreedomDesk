//! X11 root-window capture: MIT-SHM fast path with plain `GetImage` fallback.

use anyhow::{anyhow, bail, Context};
use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::shm::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, ImageOrder, VisualClass, Window};
use x11rb::rust_connection::RustConnection;

use crate::{Capturer, Frame, ScreenResized};

const ALL_PLANES: u32 = !0;

/// A System V shared memory segment attached both locally and to the X server.
struct ShmSegment {
    seg: shm::Seg,
    addr: *mut u8,
    size: usize,
}

// SAFETY: the mapping is owned exclusively by this struct; the raw pointer is only
// dereferenced through `&self`/`&mut self` of the owning capturer.
unsafe impl Send for ShmSegment {}

impl ShmSegment {
    fn create(conn: &RustConnection, size: usize) -> anyhow::Result<Self> {
        // SAFETY: plain libc calls; every failure path is checked and cleaned up.
        unsafe {
            let id = libc::shmget(libc::IPC_PRIVATE, size, libc::IPC_CREAT | 0o600);
            if id < 0 {
                bail!("shmget({size}) failed: {}", std::io::Error::last_os_error());
            }
            let addr = libc::shmat(id, std::ptr::null(), 0);
            if addr as isize == -1 {
                let err = std::io::Error::last_os_error();
                libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
                bail!("shmat failed: {err}");
            }
            let seg = match conn.generate_id() {
                Ok(seg) => seg,
                Err(e) => {
                    libc::shmdt(addr);
                    libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
                    return Err(anyhow!("generate_id: {e}"));
                }
            };
            // Read-write from the server's point of view: it writes the image into it.
            let attached = conn
                .shm_attach(seg, id as u32, false)
                .map_err(anyhow::Error::from)
                .and_then(|c| c.check().map_err(anyhow::Error::from));
            // Mark for removal right away: the segment disappears once both we and the
            // server have detached (also if we crash).
            libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
            if let Err(e) = attached {
                libc::shmdt(addr);
                return Err(e.context("XShmAttach failed (remote X server?)"));
            }
            Ok(Self { seg, addr: addr.cast(), size })
        }
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: addr..addr+size is our live mapping.
        unsafe { std::slice::from_raw_parts(self.addr, self.size) }
    }

    fn release(&mut self, conn: &RustConnection) {
        if let Ok(c) = conn.shm_detach(self.seg) {
            let _ = c.check();
        }
        // SAFETY: addr came from shmat and is detached exactly once (Drop of owner).
        unsafe {
            libc::shmdt(self.addr.cast());
        }
    }
}

pub struct X11Capturer {
    conn: RustConnection,
    root: Window,
    width: u32,
    height: u32,
    shm: Option<ShmSegment>,
    frame: Frame,
}

impl X11Capturer {
    /// Connect to `display` (or `$DISPLAY` if `None`) and prepare to capture its default root window.
    pub fn open(display: Option<&str>) -> anyhow::Result<Self> {
        let (conn, screen_num) = x11rb::connect(display).context("fd-capture: cannot connect to X display")?;
        let setup = conn.setup();
        let screen = setup
            .roots
            .get(screen_num)
            .ok_or_else(|| anyhow!("X screen {screen_num} not found"))?;
        let root = screen.root;
        let depth = screen.root_depth;

        // Validate the pixel layout: TrueColor, 24/32-bit depth, 32 bpp, LSB-first, xRGB masks
        // => bytes in memory are B, G, R, X.
        let visual = screen
            .allowed_depths
            .iter()
            .flat_map(|d| d.visuals.iter())
            .find(|v| v.visual_id == screen.root_visual)
            .ok_or_else(|| anyhow!("root visual not found"))?;
        let fmt = setup
            .pixmap_formats
            .iter()
            .find(|f| f.depth == depth)
            .ok_or_else(|| anyhow!("no pixmap format for depth {depth}"))?;
        let bgrx = visual.class == VisualClass::TRUE_COLOR
            && (depth == 24 || depth == 32)
            && fmt.bits_per_pixel == 32
            && setup.image_byte_order == ImageOrder::LSB_FIRST
            && visual.red_mask == 0x00ff_0000
            && visual.green_mask == 0x0000_ff00
            && visual.blue_mask == 0x0000_00ff;
        if !bgrx {
            bail!(
                "fd-capture: unsupported X pixel format (class {:?}, depth {}, bpp {}, byte order {:?}, masks r={:#x} g={:#x} b={:#x}); \
                 only 24/32-bit TrueColor little-endian BGRX is supported",
                visual.class,
                depth,
                fmt.bits_per_pixel,
                setup.image_byte_order,
                visual.red_mask,
                visual.green_mask,
                visual.blue_mask
            );
        }
        let pad_bits = u32::from(fmt.scanline_pad.max(8));
        let width = u32::from(screen.width_in_pixels);
        let height = u32::from(screen.height_in_pixels);
        let stride = ((width * 32).div_ceil(pad_bits) * pad_bits / 8) as usize;

        let shm = Self::try_shm(&conn, stride * height as usize);
        match &shm {
            Ok(_) => log::info!("fd-capture: X11 {width}x{height} via MIT-SHM"),
            Err(e) => log::warn!("fd-capture: MIT-SHM unavailable ({e:#}); falling back to slow GetImage"),
        }

        Ok(Self {
            conn,
            root,
            width,
            height,
            shm: shm.ok(),
            frame: Frame { width, height, stride, data: vec![0; stride * height as usize] },
        })
    }

    fn try_shm(conn: &RustConnection, size: usize) -> anyhow::Result<ShmSegment> {
        if std::env::var_os("FD_CAPTURE_NO_SHM").is_some() {
            bail!("disabled by FD_CAPTURE_NO_SHM");
        }
        if conn.extension_information(shm::X11_EXTENSION_NAME)?.is_none() {
            bail!("MIT-SHM extension not present");
        }
        conn.shm_query_version()?.reply()?;
        ShmSegment::create(conn, size)
    }

    /// Whether the fast MIT-SHM path is in use.
    pub fn uses_shm(&self) -> bool {
        self.shm.is_some()
    }

    fn resized_error(&self, new: (u32, u32)) -> anyhow::Error {
        anyhow::Error::new(ScreenResized { old: (self.width, self.height), new })
    }
}

impl Capturer for X11Capturer {
    fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn capture(&mut self) -> anyhow::Result<&Frame> {
        // Pipeline a geometry query with the image request: detects RandR resizes at no extra
        // round trip. (If the root shrank, GetImage fails with BadMatch; if it grew, we'd
        // silently capture a sub-rectangle — both are reported as ScreenResized.)
        let geom_cookie = self.conn.get_geometry(self.root)?;
        let (w, h) = (self.width as u16, self.height as u16);
        let size = self.frame.data.len();
        if let Some(shm) = &self.shm {
            let cookie =
                self.conn.shm_get_image(self.root, 0, 0, w, h, ALL_PLANES, ImageFormat::Z_PIXMAP.into(), shm.seg, 0)?;
            let geom = geom_cookie.reply()?;
            let new = (u32::from(geom.width), u32::from(geom.height));
            let reply = cookie.reply();
            if new != (self.width, self.height) {
                return Err(self.resized_error(new));
            }
            let reply = reply.context("XShmGetImage failed")?;
            if reply.size as usize != size {
                bail!("XShmGetImage returned {} bytes, expected {size}", reply.size);
            }
            self.frame.data.copy_from_slice(&shm.bytes()[..size]);
        } else {
            let cookie = self.conn.get_image(ImageFormat::Z_PIXMAP, self.root, 0, 0, w, h, ALL_PLANES)?;
            let geom = geom_cookie.reply()?;
            let new = (u32::from(geom.width), u32::from(geom.height));
            let reply = cookie.reply();
            if new != (self.width, self.height) {
                return Err(self.resized_error(new));
            }
            let reply = reply.context("XGetImage failed")?;
            if reply.data.len() != size {
                bail!("XGetImage returned {} bytes, expected {size}", reply.data.len());
            }
            self.frame.data = reply.data;
        }
        Ok(&self.frame)
    }
}

impl Drop for X11Capturer {
    fn drop(&mut self) {
        if let Some(mut shm) = self.shm.take() {
            shm.release(&self.conn);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs a reachable X display; skipped otherwise.
    #[test]
    fn capture_root_if_display_available() {
        if std::env::var_os("DISPLAY").is_none() {
            eprintln!("DISPLAY not set; skipping");
            return;
        }
        let mut cap = match X11Capturer::open(None) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("cannot open X display ({e:#}); skipping");
                return;
            }
        };
        let (w, h) = cap.size();
        let f = cap.capture().expect("capture");
        assert_eq!((f.width, f.height), (w, h));
        assert!(f.stride >= w as usize * 4);
        assert_eq!(f.data.len(), f.stride * h as usize);
        // Second capture reuses the buffer.
        cap.capture().expect("capture 2");
    }
}
