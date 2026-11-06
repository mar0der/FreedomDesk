//! X11 root-window capture: MIT-SHM fast path with plain `GetImage` fallback, XFixes cursor
//! compositing and DAMAGE-based change detection.

use anyhow::{anyhow, bail, Context};
use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::damage::{self, ConnectionExt as _, ReportLevel};
use x11rb::protocol::shm::{self, ConnectionExt as _};
use x11rb::protocol::xfixes::{self, ConnectionExt as _, CursorNotifyMask};
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, ImageOrder, VisualClass, Window};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::NONE;

use crate::{Capturer, CursorInfo, CursorShape, Frame, FrameRef, ScreenResized, MAX_CURSOR_SHAPE};

const ALL_PLANES: u32 = !0;
/// Largest cursor image we accept from the server (defensive; real cursors are <= 256x256).
const MAX_CURSOR_DIM: u16 = 512;

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
            Ok(Self {
                seg,
                addr: addr.cast(),
                size,
            })
        }
    }

    // SAFETY (both): addr..addr+size is our live private mapping. The X server writes into it
    // only while processing our ShmGetImage, and we only hand out slices after that request's
    // reply and before issuing the next one (enforced by the &self/&mut self borrows).
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.addr, self.size) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.addr, self.size) }
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

/// Cached cursor image, premultiplied ARGB (0xAARRGGBB) as delivered by XFixes.
struct CursorImage {
    width: usize,
    height: usize,
    xhot: i32,
    yhot: i32,
    serial: u32,
    /// Every pixel fully transparent (apps "hide" the cursor this way).
    blank: bool,
    pixels: Vec<u32>,
}

impl CursorImage {
    /// Straight-alpha RGBA, cropped around the hotspot to at most MAX_CURSOR_SHAPE square.
    fn to_shape(&self) -> CursorShape {
        let max = MAX_CURSOR_SHAPE as usize;
        let (cw, ch) = (self.width.min(max), self.height.min(max));
        let x0 = (self.xhot.max(0) as usize)
            .saturating_sub(cw / 2)
            .min(self.width - cw);
        let y0 = (self.yhot.max(0) as usize)
            .saturating_sub(ch / 2)
            .min(self.height - ch);
        let mut rgba = Vec::with_capacity(cw * ch * 4);
        for y in y0..y0 + ch {
            for &p in &self.pixels[y * self.width + x0..][..cw] {
                rgba.extend_from_slice(&unpremultiply(p));
            }
        }
        CursorShape {
            width: cw as u32,
            height: ch as u32,
            xhot: (self.xhot - x0 as i32).clamp(0, cw as i32 - 1) as u32,
            yhot: (self.yhot - y0 as i32).clamp(0, ch as i32 - 1) as u32,
            rgba,
        }
    }
}

/// Premultiplied 0xAARRGGBB -> straight [R, G, B, A].
fn unpremultiply(p: u32) -> [u8; 4] {
    let a = p >> 24;
    if a == 0 {
        return [0; 4];
    }
    let un = |c: u32| ((c * 255 + a / 2) / a).min(255) as u8;
    [
        un((p >> 16) & 0xff),
        un((p >> 8) & 0xff),
        un(p & 0xff),
        a as u8,
    ]
}

struct CursorState {
    image: Option<CursorImage>,
    /// Shape changed (XFixes CursorNotify) since we last fetched the image.
    stale: bool,
    /// Pointer position used for the last captured frame.
    last_pos: Option<(i32, i32)>,
    /// Serial of the shape last returned by `cursor()`.
    reported_serial: Option<u32>,
}

pub struct X11Capturer {
    conn: RustConnection,
    root: Window,
    width: u32,
    height: u32,
    shm: Option<ShmSegment>,
    frame: Frame,
    /// DAMAGE object on the root window; `None` if the extension is unavailable.
    damage: Option<damage::Damage>,
    /// Something changed since the last capture (or we can't tell).
    dirty: bool,
    /// XFixes cursor support; `None` if unavailable.
    cursor: Option<CursorState>,
    draw_cursor: bool,
}

impl X11Capturer {
    /// Connect to `display` (or `$DISPLAY` if `None`) and prepare to capture its default root window.
    pub fn open(display: Option<&str>) -> anyhow::Result<Self> {
        let (conn, screen_num) =
            x11rb::connect(display).context("fd-capture: cannot connect to X display")?;
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
            Err(e) => {
                log::warn!("fd-capture: MIT-SHM unavailable ({e:#}); falling back to slow GetImage")
            }
        }
        let cursor = match Self::try_xfixes(&conn, root) {
            Ok(()) => Some(CursorState {
                image: None,
                stale: true,
                last_pos: None,
                reported_serial: None,
            }),
            Err(e) => {
                log::warn!(
                    "fd-capture: XFixes unavailable ({e:#}); the mouse cursor will not be drawn"
                );
                None
            }
        };
        let damage = match Self::try_damage(&conn, root) {
            Ok(d) => Some(d),
            Err(e) => {
                log::warn!("fd-capture: DAMAGE unavailable ({e:#}); every frame counts as changed");
                None
            }
        };

        Ok(Self {
            conn,
            root,
            width,
            height,
            shm: shm.ok(),
            frame: Frame {
                width,
                height,
                stride,
                data: vec![0; stride * height as usize],
            },
            damage,
            dirty: true,
            cursor,
            draw_cursor: true,
        })
    }

    fn try_shm(conn: &RustConnection, size: usize) -> anyhow::Result<ShmSegment> {
        if std::env::var_os("FD_CAPTURE_NO_SHM").is_some() {
            bail!("disabled by FD_CAPTURE_NO_SHM");
        }
        if conn
            .extension_information(shm::X11_EXTENSION_NAME)?
            .is_none()
        {
            bail!("MIT-SHM extension not present");
        }
        conn.shm_query_version()?.reply()?;
        ShmSegment::create(conn, size)
    }

    fn try_xfixes(conn: &RustConnection, root: Window) -> anyhow::Result<()> {
        if conn
            .extension_information(xfixes::X11_EXTENSION_NAME)?
            .is_none()
        {
            bail!("XFIXES extension not present");
        }
        let v = conn.xfixes_query_version(4, 0)?.reply()?;
        if v.major_version < 2 {
            bail!("XFIXES {}.{} too old", v.major_version, v.minor_version);
        }
        conn.xfixes_select_cursor_input(root, CursorNotifyMask::DISPLAY_CURSOR)?
            .check()?;
        Ok(())
    }

    fn try_damage(conn: &RustConnection, root: Window) -> anyhow::Result<damage::Damage> {
        if conn
            .extension_information(damage::X11_EXTENSION_NAME)?
            .is_none()
        {
            bail!("DAMAGE extension not present");
        }
        conn.damage_query_version(1, 1)?.reply()?;
        let id = conn.generate_id()?;
        // NON_EMPTY: one notify when the damage region goes from empty to non-empty; we reset it
        // with Subtract before every capture.
        conn.damage_create(id, root, ReportLevel::NON_EMPTY)?
            .check()?;
        Ok(id)
    }

    /// Whether the fast MIT-SHM path is in use.
    pub fn uses_shm(&self) -> bool {
        self.shm.is_some()
    }

    /// Whether DAMAGE-based change detection is available.
    pub fn has_damage(&self) -> bool {
        self.damage.is_some()
    }

    /// The most recent grab, wherever it lives (SHM segment or `self.frame`).
    fn grabbed(&self) -> FrameRef<'_> {
        let data = match &self.shm {
            Some(shm) => &shm.bytes()[..self.frame.data.len()],
            None => &self.frame.data[..],
        };
        FrameRef {
            width: self.width,
            height: self.height,
            stride: self.frame.stride,
            data,
        }
    }

    fn resized_error(&self, new: (u32, u32)) -> anyhow::Error {
        anyhow::Error::new(ScreenResized {
            old: (self.width, self.height),
            new,
        })
    }

    /// Cache a fetched cursor image (clears the stale flag).
    fn store_shape(cursor: &mut Option<CursorState>, img: xfixes::GetCursorImageReply) {
        let Some(c) = cursor.as_mut() else { return };
        c.stale = false;
        let n = usize::from(img.width) * usize::from(img.height);
        c.image = (img.width > 0
            && img.height > 0
            && img.width <= MAX_CURSOR_DIM
            && img.height <= MAX_CURSOR_DIM
            && img.cursor_image.len() >= n)
            .then(|| CursorImage {
                width: usize::from(img.width),
                height: usize::from(img.height),
                xhot: i32::from(img.xhot),
                yhot: i32::from(img.yhot),
                serial: img.cursor_serial,
                blank: img.cursor_image[..n].iter().all(|&p| p >> 24 == 0),
                pixels: img.cursor_image,
            });
    }

    /// Drain pending X events into the dirty / cursor-stale flags.
    fn process_events(&mut self) -> anyhow::Result<()> {
        while let Some(ev) = self.conn.poll_for_event()? {
            match ev {
                Event::DamageNotify(_) => self.dirty = true,
                Event::XfixesCursorNotify(_) => {
                    if let Some(c) = &mut self.cursor {
                        c.stale = true;
                        if self.draw_cursor {
                            self.dirty = true;
                        }
                    }
                }
                Event::Error(e) => log::warn!("fd-capture: X error: {e:?}"),
                _ => {}
            }
        }
        Ok(())
    }

    /// Grab the screen (into the SHM segment, or `self.frame` without SHM) and draw the cursor.
    /// With `copy`, the result is always in `self.frame` afterwards. With `only_if_changed`,
    /// returns `Ok(false)` without grabbing when neither DAMAGE nor the cursor reported a change.
    fn capture_inner(&mut self, only_if_changed: bool, copy: bool) -> anyhow::Result<bool> {
        self.process_events()?;
        let want_cursor = self.draw_cursor && self.cursor.is_some();
        let fetch_shape = want_cursor && self.cursor.as_ref().is_some_and(|c| c.stale);

        // Pointer position (one small round trip) — needed both to detect cursor motion and to
        // place the cursor. A shape fetch returns the position too.
        let mut pos = None;
        if want_cursor && !fetch_shape {
            let p = self.conn.query_pointer(self.root)?.reply()?;
            if p.same_screen {
                pos = Some((i32::from(p.root_x), i32::from(p.root_y)));
            }
            if self.cursor.as_ref().is_some_and(|c| c.last_pos != pos) {
                self.dirty = true;
            }
        }
        if only_if_changed && !self.dirty && self.damage.is_some() && !fetch_shape {
            return Ok(false);
        }

        // Reset damage *before* grabbing so that anything drawn from now on re-notifies.
        if let Some(d) = self.damage {
            self.conn.damage_subtract(d, NONE, NONE)?;
        }
        let geom_cookie = self.conn.get_geometry(self.root)?;
        let shape_cookie = if fetch_shape {
            Some(self.conn.xfixes_get_cursor_image()?)
        } else {
            None
        };
        let (w, h) = (self.width as u16, self.height as u16);
        let size = self.frame.data.len();
        if let Some(shm) = &self.shm {
            let cookie = self.conn.shm_get_image(
                self.root,
                0,
                0,
                w,
                h,
                ALL_PLANES,
                ImageFormat::Z_PIXMAP.into(),
                shm.seg,
                0,
            )?;
            let geom = geom_cookie.reply()?;
            let new = (u32::from(geom.width), u32::from(geom.height));
            let reply = cookie.reply();
            if new != (self.width, self.height) {
                return Err(self.resized_error(new));
            }
            let reply = reply.context("XShmGetImage failed")?;
            if reply.size as usize != size {
                bail!(
                    "XShmGetImage returned {} bytes, expected {size}",
                    reply.size
                );
            }
        } else {
            let cookie =
                self.conn
                    .get_image(ImageFormat::Z_PIXMAP, self.root, 0, 0, w, h, ALL_PLANES)?;
            let geom = geom_cookie.reply()?;
            let new = (u32::from(geom.width), u32::from(geom.height));
            let reply = cookie.reply();
            if new != (self.width, self.height) {
                return Err(self.resized_error(new));
            }
            let reply = reply.context("XGetImage failed")?;
            if reply.data.len() != size {
                bail!(
                    "XGetImage returned {} bytes, expected {size}",
                    reply.data.len()
                );
            }
            self.frame.data = reply.data;
        }

        if let Some(cookie) = shape_cookie {
            let img = cookie.reply().context("XFixesGetCursorImage failed")?;
            pos = Some((i32::from(img.x), i32::from(img.y)));
            Self::store_shape(&mut self.cursor, img);
        }
        if want_cursor {
            let c = self.cursor.as_mut().expect("cursor state");
            c.last_pos = pos;
            if let (Some(img), Some((x, y))) = (&c.image, pos) {
                let buf = match &mut self.shm {
                    Some(shm) => &mut shm.bytes_mut()[..size],
                    None => &mut self.frame.data[..],
                };
                composite_cursor(
                    buf,
                    self.width,
                    self.height,
                    self.frame.stride,
                    img,
                    x - img.xhot,
                    y - img.yhot,
                );
            }
        }
        if copy {
            if let Some(shm) = &self.shm {
                self.frame.data.copy_from_slice(&shm.bytes()[..size]);
            }
        }
        self.dirty = false;
        Ok(true)
    }
}

/// Alpha-blend a premultiplied ARGB cursor onto a BGRX buffer at (x0, y0), clipped.
fn composite_cursor(
    data: &mut [u8],
    width: u32,
    height: u32,
    stride: usize,
    img: &CursorImage,
    x0: i32,
    y0: i32,
) {
    let (fw, fh) = (width as i32, height as i32);
    let xs = x0.max(0);
    let xe = (x0 + img.width as i32).min(fw);
    let ys = y0.max(0);
    let ye = (y0 + img.height as i32).min(fh);
    if xs >= xe || ys >= ye {
        return;
    }
    for y in ys..ye {
        let src =
            &img.pixels[(y - y0) as usize * img.width..][(xs - x0) as usize..(xe - x0) as usize];
        let dst = &mut data[y as usize * stride + xs as usize * 4..][..(xe - xs) as usize * 4];
        for (d, &p) in dst.chunks_exact_mut(4).zip(src) {
            let a = p >> 24;
            if a == 0 {
                continue;
            }
            let inv = 255 - a;
            for (c, shift) in [(0usize, 0u32), (1, 8), (2, 16)] {
                let s = (p >> shift) & 0xff;
                d[c] = (s + (u32::from(d[c]) * inv + 127) / 255).min(255) as u8;
            }
        }
    }
}

impl Capturer for X11Capturer {
    fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn capture(&mut self) -> anyhow::Result<&Frame> {
        self.capture_inner(false, true)?;
        Ok(&self.frame)
    }

    fn capture_if_changed(&mut self) -> anyhow::Result<Option<FrameRef<'_>>> {
        if !self.capture_inner(true, false)? {
            return Ok(None);
        }
        Ok(Some(self.grabbed()))
    }

    fn capture_ref(&mut self) -> anyhow::Result<FrameRef<'_>> {
        self.capture_inner(false, false)?;
        Ok(self.grabbed())
    }

    fn cursor(&mut self) -> anyhow::Result<Option<CursorInfo>> {
        let Some(stale) = self.cursor.as_ref().map(|c| c.stale) else {
            return Ok(None);
        };
        self.process_events()?;
        let stale = stale || self.cursor.as_ref().is_some_and(|c| c.stale);
        let (x, y, on_screen) = if stale {
            let img = self
                .conn
                .xfixes_get_cursor_image()?
                .reply()
                .context("XFixesGetCursorImage failed")?;
            let pos = (i32::from(img.x), i32::from(img.y), true);
            Self::store_shape(&mut self.cursor, img);
            pos
        } else {
            let p = self.conn.query_pointer(self.root)?.reply()?;
            (i32::from(p.root_x), i32::from(p.root_y), p.same_screen)
        };
        let c = self.cursor.as_mut().expect("cursor state");
        let serial = c.image.as_ref().map_or(0, |i| i.serial);
        let shape = if c.reported_serial != Some(serial) {
            c.reported_serial = Some(serial);
            c.image.as_ref().map(CursorImage::to_shape)
        } else {
            None
        };
        let visible = on_screen && c.image.as_ref().is_some_and(|i| !i.blank);
        Ok(Some(CursorInfo {
            x,
            y,
            visible,
            serial,
            shape,
        }))
    }

    fn set_draw_cursor(&mut self, on: bool) {
        if on != self.draw_cursor {
            self.draw_cursor = on;
            self.dirty = true;
            if let Some(c) = &mut self.cursor {
                c.stale = true;
            }
        }
    }
}

impl Drop for X11Capturer {
    fn drop(&mut self) {
        if let Some(d) = self.damage.take() {
            let _ = self.conn.damage_destroy(d);
        }
        if let Some(mut shm) = self.shm.take() {
            shm.release(&self.conn);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_or_skip() -> Option<X11Capturer> {
        if std::env::var_os("DISPLAY").is_none() {
            eprintln!("DISPLAY not set; skipping");
            return None;
        }
        match X11Capturer::open(None) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("cannot open X display ({e:#}); skipping");
                None
            }
        }
    }

    fn f_stride(c: &X11Capturer) -> usize {
        c.frame.stride
    }
    fn f_len(c: &X11Capturer) -> usize {
        c.frame.data.len()
    }

    /// Needs a reachable X display; skipped otherwise.
    #[test]
    fn capture_root_if_display_available() {
        let Some(mut cap) = open_or_skip() else {
            return;
        };
        let (w, h) = cap.size();
        let f = cap.capture().expect("capture");
        assert_eq!((f.width, f.height), (w, h));
        assert!(f.stride >= w as usize * 4);
        assert_eq!(f.data.len(), f.stride * h as usize);
        // Second capture reuses the buffer.
        cap.capture().expect("capture 2");
        // Zero-copy grab has the same geometry.
        let v = cap.capture_ref().expect("capture_ref");
        assert_eq!(
            (v.width, v.height, v.stride, v.data.len()),
            (w, h, f_stride(&cap), f_len(&cap))
        );
        // Without cursor drawing, capture_if_changed must work (Some or None) without error.
        cap.set_draw_cursor(false);
        cap.capture_if_changed().expect("capture_if_changed");
    }

    /// Maps a small override-redirect window for a moment (visible on the real screen!), so
    /// it is ignored by default: `cargo test -p fd-capture -- --ignored`.
    #[test]
    #[ignore]
    fn damage_detects_change() {
        use x11rb::protocol::xproto::{CreateWindowAux, WindowClass};
        use x11rb::COPY_DEPTH_FROM_PARENT;
        let Some(mut cap) = open_or_skip() else {
            return;
        };
        assert!(cap.has_damage());
        cap.set_draw_cursor(false);
        cap.capture().unwrap();
        // Let any in-flight repaint settle, then expect "unchanged" at least once.
        let mut unchanged = false;
        for _ in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if cap.capture_if_changed().unwrap().is_none() {
                unchanged = true;
                break;
            }
        }
        assert!(
            unchanged,
            "screen never reported unchanged (something animating?)"
        );

        let (conn, screen_num) = x11rb::connect(None).unwrap();
        let screen = &conn.setup().roots[screen_num];
        let win = conn.generate_id().unwrap();
        let aux = CreateWindowAux::new()
            .override_redirect(1)
            .background_pixel(0x00ff_00ff);
        conn.create_window(
            COPY_DEPTH_FROM_PARENT,
            win,
            screen.root,
            0,
            0,
            16,
            16,
            0,
            WindowClass::INPUT_OUTPUT,
            0,
            &aux,
        )
        .unwrap();
        conn.map_window(win).unwrap();
        conn.flush().unwrap();
        let mut changed = false;
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(25));
            if cap.capture_if_changed().unwrap().is_some() {
                changed = true;
                break;
            }
        }
        conn.destroy_window(win).unwrap();
        conn.flush().unwrap();
        assert!(changed, "DAMAGE did not report the mapped window");
    }

    /// Warps the pointer, so it only runs against a throwaway server named by FD_TEST_DISPLAY
    /// (e.g. `Xephyr :5 -screen 320x240`):
    /// `FD_TEST_DISPLAY=:5 cargo test -p fd-capture -- --ignored cursor_motion`.
    #[test]
    #[ignore]
    fn cursor_motion_counts_only_when_drawn() {
        let Some(display) = std::env::var("FD_TEST_DISPLAY").ok() else {
            eprintln!("FD_TEST_DISPLAY not set; skipping");
            return;
        };
        let mut cap = X11Capturer::open(Some(&display)).unwrap();
        let (w, h) = cap.size();
        let root = cap.root;
        let warp = |cap: &X11Capturer, x: i16, y: i16| {
            cap.conn
                .warp_pointer(NONE, root, 0, 0, 0, 0, x, y)
                .unwrap()
                .check()
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        let settle = |cap: &mut X11Capturer| {
            for _ in 0..20 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if cap.capture_if_changed().unwrap().is_none() {
                    return;
                }
            }
            panic!("screen never settled");
        };
        // Not drawn: motion must not count; cursor() still tracks it.
        cap.set_draw_cursor(false);
        warp(&cap, 10, 10);
        cap.capture().unwrap();
        settle(&mut cap);
        warp(&cap, (w / 2) as i16, (h / 2) as i16);
        assert!(
            cap.capture_if_changed().unwrap().is_none(),
            "pure cursor motion reported as a change with draw_cursor(false)"
        );
        let ci = cap.cursor().unwrap().expect("XFixes");
        assert_eq!((ci.x, ci.y), ((w / 2) as i32, (h / 2) as i32));
        // Drawn: motion counts.
        cap.set_draw_cursor(true);
        cap.capture().unwrap();
        settle(&mut cap);
        warp(&cap, 20, 20);
        assert!(cap.capture_if_changed().unwrap().is_some());
    }

    #[test]
    fn cursor_info_reports_shape_once() {
        let Some(mut cap) = open_or_skip() else {
            return;
        };
        cap.set_draw_cursor(false);
        let first = cap.cursor().unwrap().expect("XFixes available");
        let shape = first.shape.expect("shape on first call");
        assert!(shape.width >= 1 && shape.width <= MAX_CURSOR_SHAPE);
        assert!(shape.height >= 1 && shape.height <= MAX_CURSOR_SHAPE);
        assert_eq!(shape.rgba.len(), (shape.width * shape.height * 4) as usize);
        assert!(shape.xhot < shape.width && shape.yhot < shape.height);
        let (w, h) = cap.size();
        assert!((0..w as i32).contains(&first.x) && (0..h as i32).contains(&first.y));
        let second = cap.cursor().unwrap().unwrap();
        if second.serial == first.serial {
            assert!(
                second.shape.is_none(),
                "shape must only be sent when the serial changes"
            );
        }
    }

    #[test]
    fn cursor_shape_crop_and_unpremultiply() {
        assert_eq!(unpremultiply(0x8040_2010), [0x80, 0x40, 0x20, 0x80]);
        assert_eq!(unpremultiply(0x0000_0000), [0, 0, 0, 0]);
        assert_eq!(unpremultiply(0xffff_ffff), [255, 255, 255, 255]);
        let img = CursorImage {
            width: 300,
            height: 20,
            xhot: 290,
            yhot: 5,
            serial: 7,
            blank: false,
            pixels: vec![0xff00_ff00; 300 * 20],
        };
        let s = img.to_shape();
        assert_eq!((s.width, s.height), (256, 20));
        assert_eq!((s.xhot, s.yhot), (290 - 44, 5));
        assert_eq!(&s.rgba[..4], &[0, 255, 0, 255]);
    }

    #[test]
    fn cursor_blend_clips_and_blends() {
        let mut f = vec![100u8; 32];
        // 2x2 cursor: opaque red, transparent, 50% premultiplied white, opaque blue.
        let img = CursorImage {
            width: 2,
            height: 2,
            xhot: 0,
            yhot: 0,
            serial: 1,
            blank: false,
            pixels: vec![0xffff_0000, 0x0000_0000, 0x8080_8080, 0xff00_00ff],
        };
        composite_cursor(&mut f, 4, 2, 16, &img, 3, 0); // only the left column is visible (x=3)
        assert_eq!(&f[12..15], &[0, 0, 255]); // red -> B,G,R
        let half = &f[16 + 12..16 + 15];
        assert!(
            half.iter()
                .all(|&v| (v as i32 - (128 + 100 * 127 / 255)).abs() <= 1),
            "{half:?}"
        );
        composite_cursor(&mut f, 4, 2, 16, &img, -5, -5); // fully off-screen: no panic
    }
}
