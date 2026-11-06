//! X11 input injection through the XTest extension (x11rb, pure Rust).
//!
//! The keyboard map is read through XKB (per key: groups x levels) and the
//! active XKB group is queried before every key/text event, so typing on a
//! multi-layout host (e.g. us,bg) uses the real keys of the active layout.
//!
//! Characters/keysyms not reachable at level 0/1 of the active group are typed
//! by temporarily binding the keysym to a spare, unused keycode via core
//! ChangeKeyboardMapping (the xdotool technique). Bindings are kept for a
//! short while (and reused) because X clients re-read the keymap lazily after
//! MappingNotify; restoring right after the key press would race with them.
//! Borrowed keycodes are recorded in a state file so a crashed/killed host can
//! be cleaned up by the next start (or [`crate::emergency_cleanup`]).

use std::collections::HashMap;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use fd_proto::{InputEvent, MouseButton};
use x11rb::connection::{Connection, RequestConnection as _};
use x11rb::protocol::xkb::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{
    ConnectionExt as _, ModMask, Window, BUTTON_PRESS_EVENT, BUTTON_RELEASE_EVENT, KEY_PRESS_EVENT,
    KEY_RELEASE_EVENT, MOTION_NOTIFY_EVENT,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::NONE;

use crate::keysym::{self, Key, Keymap, RateLimiter, ShiftAction};
use crate::InputInjector;

/// Remote can hold at most this many distinct keys at once.
const MAX_HELD_KEYS: usize = 16;
/// At most this many spare keycodes are borrowed for unmapped keysyms.
const MAX_SPARE_SLOTS: usize = 32;
/// A spare binding unused for this long is restored to NoSymbol.
const SPARE_IDLE: Duration = Duration::from_secs(2);
/// Never rebind a spare keycode sooner than this after it was last typed
/// (clients must still see the old binding when decoding the earlier press).
const MIN_REBIND_AGE: Duration = Duration::from_millis(300);
/// New spare bindings per second (burst = same amount).
const SPARE_BINDS_PER_SEC: f64 = 20.0;

const XK_SHIFT_L: u32 = 0xffe1;
const XK_SHIFT_R: u32 = 0xffe2;

fn core_kbd() -> xkb::DeviceSpec {
    xkb::ID::USE_CORE_KBD.into()
}

#[derive(Debug)]
struct SpareSlot {
    keycode: u8,
    keysym: u32,
    last_used: Instant,
    /// Held down by a Key event; must not be rebound/restored until released.
    pinned: bool,
}

#[derive(Debug, Clone, Copy)]
struct HeldKey {
    keycode: u8,
    spare: bool,
}

/// Outcome of trying to get a spare keycode for a keysym.
enum Spare {
    Bound(u8),
    /// Rate limit / no free slot right now: drop the event.
    Dropped,
}

pub struct XTestInjector {
    conn: RustConnection,
    root: Window,
    width: u32,
    height: u32,
    keymap: Keymap,
    keymap_dirty: bool,
    /// GetModifierMapping keycodes, 8 rows of `keycodes_per_modifier`.
    modmap: Vec<u8>,
    /// Spare keycodes (no keysyms, not modifiers) seen at startup.
    spare_candidates: Vec<u8>,
    spares: Vec<SpareSlot>,
    bind_limiter: RateLimiter,
    state_file: Option<PathBuf>,
    held_keys: HashMap<u32, HeldKey>,
    /// Bitmask of held buttons (bit n = button n).
    held_buttons: u16,
}

// ---------------------------------------------------------------- state file

fn display_tag() -> String {
    std::env::var("DISPLAY")
        .unwrap_or_default()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn state_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
}

fn state_prefix() -> String {
    format!("freedomdesk-input-{}-", display_tag())
}

fn own_state_file() -> Option<PathBuf> {
    state_dir().map(|d| d.join(format!("{}{}.state", state_prefix(), std::process::id())))
}

/// State files on this display whose owner process is gone (plus our own pid's,
/// which can only be a leftover from a previous process with the same pid or
/// an explicit emergency cleanup).
fn stale_state_files() -> Vec<PathBuf> {
    let Some(dir) = state_dir() else {
        return Vec::new();
    };
    let prefix = state_prefix();
    let me = std::process::id();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let pid: u32 = name
                .strip_prefix(&prefix)?
                .strip_suffix(".state")?
                .parse()
                .ok()?;
            let alive = pid != me && Path::new(&format!("/proc/{pid}")).exists();
            (!alive).then(|| e.path())
        })
        .collect()
}

fn parse_state(text: &str) -> Vec<(u8, u32)> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((
                it.next()?.parse().ok()?,
                u32::from_str_radix(it.next()?.trim_start_matches("0x"), 16).ok()?,
            ))
        })
        .collect()
}

fn write_state(path: &Path, spares: &[SpareSlot]) -> std::io::Result<()> {
    if spares.is_empty() {
        return match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    for s in spares {
        writeln!(f, "{} {:#x}", s.keycode, s.keysym)?;
    }
    f.sync_data()?;
    std::fs::rename(&tmp, path)
}

fn load_keymap(conn: &RustConnection) -> anyhow::Result<Keymap> {
    let r = conn
        .xkb_get_map(
            core_kbd(),
            xkb::MapPart::KEY_SYMS,
            xkb::MapPart::from(0u16),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            xkb::VMod::from(0u16),
            0,
            0,
            0,
            0,
            0,
            0,
        )?
        .reply()?;
    let syms = r.map.syms_rtrn.unwrap_or_default();
    let keys = syms
        .iter()
        .map(|m| Key::from_xkb(m.group_info, m.width, &m.syms))
        .collect();
    Ok(Keymap::new(r.first_key_sym, keys))
}

fn init_xkb(conn: &RustConnection) -> anyhow::Result<()> {
    if conn
        .extension_information(xkb::X11_EXTENSION_NAME)?
        .is_none()
    {
        bail!("fd-input: X server has no XKEYBOARD extension");
    }
    let r = conn.xkb_use_extension(1, 0)?.reply()?;
    if !r.supported {
        bail!(
            "fd-input: XKB 1.0 not supported by server ({}.{})",
            r.server_major,
            r.server_minor
        );
    }
    Ok(())
}

/// Clear keycodes listed in stale state files (only if they still carry the
/// keysym we bound) and delete the files. Errors are logged, not fatal.
fn cleanup_stale(
    conn: &RustConnection,
    keymap: &Keymap,
    files: &[PathBuf],
) -> anyhow::Result<bool> {
    let mut changed = false;
    for path in files {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        for (kc, ks) in parse_state(&text) {
            if keymap.holds_binding(kc, ks) {
                log::info!("fd-input: clearing leftover binding keycode {kc} = {ks:#x}");
                conn.change_keyboard_mapping(1, kc, 2, &[0, 0])?;
                changed = true;
            }
        }
        if let Err(e) = std::fs::remove_file(path) {
            log::warn!("fd-input: cannot remove {}: {e}", path.display());
        }
    }
    if changed {
        conn.sync()?;
    }
    Ok(changed)
}

/// See [`crate::emergency_cleanup`].
pub fn emergency_cleanup() -> anyhow::Result<()> {
    let mut files = stale_state_files();
    if let Some(own) = own_state_file().filter(|p| p.exists()) {
        files.push(own);
    }
    if files.is_empty() {
        return Ok(());
    }
    let (conn, _) =
        RustConnection::connect(None).context("fd-input: cannot connect to X display")?;
    init_xkb(&conn)?;
    let keymap = load_keymap(&conn)?;
    cleanup_stale(&conn, &keymap, &files)?;
    Ok(())
}

// ---------------------------------------------------------------- injector

impl XTestInjector {
    pub fn open(width: u32, height: u32) -> anyhow::Result<Self> {
        let (conn, screen_num) =
            RustConnection::connect(None).context("fd-input: cannot connect to X display")?;
        if conn
            .extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)?
            .is_none()
        {
            bail!("fd-input: X server has no XTEST extension");
        }
        let v = conn.xtest_get_version(2, 2)?.reply()?;
        log::debug!("XTEST {}.{}", v.major_version, v.minor_version);
        init_xkb(&conn)?;
        // Get told about keymap changes (core MappingNotify may be suppressed
        // for XKB-aware clients).
        let parts = xkb::MapPart::KEY_TYPES | xkb::MapPart::KEY_SYMS | xkb::MapPart::MODIFIER_MAP;
        conn.xkb_select_events(
            core_kbd(),
            xkb::EventType::from(0u16),
            xkb::EventType::MAP_NOTIFY | xkb::EventType::NEW_KEYBOARD_NOTIFY,
            parts,
            parts,
            &xkb::SelectEventsAux::new(),
        )?;
        let root = conn
            .setup()
            .roots
            .get(screen_num)
            .context("fd-input: X screen not found")?
            .root;

        // Leftovers from a crashed/killed previous host process.
        let stale = stale_state_files();
        if !stale.is_empty() {
            let km = load_keymap(&conn)?;
            cleanup_stale(&conn, &km, &stale)?;
        }

        let state_file = own_state_file();
        if state_file.is_none() {
            log::warn!("fd-input: XDG_RUNTIME_DIR unset; borrowed keycodes cannot be recovered after a crash");
        }
        let mut me = Self {
            conn,
            root,
            width,
            height,
            keymap: Keymap::default(),
            keymap_dirty: true,
            modmap: Vec::new(),
            spare_candidates: Vec::new(),
            spares: Vec::new(),
            bind_limiter: RateLimiter::new(SPARE_BINDS_PER_SEC, SPARE_BINDS_PER_SEC),
            state_file,
            held_keys: HashMap::new(),
            held_buttons: 0,
        };
        me.refresh_keymap()?;
        me.spare_candidates = me.keymap.spare_keycodes(&me.modmap);
        log::debug!(
            "fd-input: {} spare keycodes available",
            me.spare_candidates.len()
        );
        Ok(me)
    }

    fn refresh_keymap(&mut self) -> anyhow::Result<()> {
        self.keymap = load_keymap(&self.conn)?;
        self.modmap = self.conn.get_modifier_mapping()?.reply()?.keycodes;
        self.keymap_dirty = false;
        // Drop spare slots whose binding was overwritten by someone else (e.g. a
        // layout switch rewrote the whole map): we must not "restore" them.
        let keymap = &self.keymap;
        let before = self.spares.len();
        self.spares.retain(|s| {
            let ok = keymap.holds_binding(s.keycode, s.keysym);
            if !ok {
                log::debug!("fd-input: spare keycode {} binding lost", s.keycode);
            }
            ok
        });
        if self.spares.len() != before {
            self.save_state();
        }
        Ok(())
    }

    fn save_state(&self) {
        if let Some(p) = &self.state_file {
            if let Err(e) = write_state(p, &self.spares) {
                log::warn!("fd-input: cannot write {}: {e}", p.display());
            }
        }
    }

    /// Drain pending events; mapping notifications invalidate the keymap cache.
    fn poll_events(&mut self) -> anyhow::Result<()> {
        while let Some(ev) = self.conn.poll_for_event()? {
            match ev {
                Event::MappingNotify(_)
                | Event::XkbMapNotify(_)
                | Event::XkbNewKeyboardNotify(_) => self.keymap_dirty = true,
                Event::Error(e) => log::warn!("fd-input: X error: {e:?}"),
                _ => {}
            }
        }
        if self.keymap_dirty {
            self.refresh_keymap()?;
        }
        Ok(())
    }

    /// Active XKB group (0..=3) and effective modifier mask.
    fn xkb_state(&self) -> anyhow::Result<(u8, ModMask)> {
        let s = self.conn.xkb_get_state(core_kbd())?.reply()?;
        Ok((u8::from(s.group), s.mods))
    }

    fn shift_keycodes(&self) -> &[u8] {
        let per = self.modmap.len() / 8;
        &self.modmap[..per]
    }

    fn spare_keycodes_in_use(&self) -> Vec<u8> {
        self.spares.iter().map(|s| s.keycode).collect()
    }

    fn fake_key(&self, keycode: u8, down: bool) -> anyhow::Result<()> {
        let t = if down {
            KEY_PRESS_EVENT
        } else {
            KEY_RELEASE_EVENT
        };
        self.conn.xtest_fake_input(t, keycode, 0, NONE, 0, 0, 0)?;
        Ok(())
    }

    fn tap(&self, keycode: u8) -> anyhow::Result<()> {
        self.fake_key(keycode, true)?;
        self.fake_key(keycode, false)
    }

    fn fake_button(&self, button: u8, down: bool) -> anyhow::Result<()> {
        let t = if down {
            BUTTON_PRESS_EVENT
        } else {
            BUTTON_RELEASE_EVENT
        };
        self.conn.xtest_fake_input(t, button, 0, NONE, 0, 0, 0)?;
        Ok(())
    }

    /// Bind `keysym` to a spare keycode (reusing an existing binding when
    /// possible) and make sure the server has processed it. Never blocks for
    /// long: if rate-limited or no slot is old enough, the event is dropped.
    fn bind_spare(&mut self, keysym: u32) -> anyhow::Result<Spare> {
        let now = Instant::now();
        if let Some(s) = self.spares.iter_mut().find(|s| s.keysym == keysym) {
            s.last_used = now;
            return Ok(Spare::Bound(s.keycode));
        }
        if !self.bind_limiter.try_take_at(now) {
            log::debug!("fd-input: spare binding rate limit hit, dropping keysym {keysym:#x}");
            return Ok(Spare::Dropped);
        }
        let in_use = self.spare_keycodes_in_use();
        let free = self
            .spare_candidates
            .iter()
            .copied()
            // Still unbound in the current map (nobody else grabbed it meanwhile).
            .find(|kc| !in_use.contains(kc) && self.keymap.is_unbound(*kc));
        let idx = match free {
            Some(kc) if self.spares.len() < MAX_SPARE_SLOTS => {
                self.spares.push(SpareSlot {
                    keycode: kc,
                    keysym: 0,
                    last_used: now,
                    pinned: false,
                });
                self.spares.len() - 1
            }
            _ => {
                let lru = self
                    .spares
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| !s.pinned && now.duration_since(s.last_used) >= MIN_REBIND_AGE)
                    .min_by_key(|(_, s)| s.last_used)
                    .map(|(i, _)| i);
                match lru {
                    Some(i) => i,
                    None => {
                        log::debug!("fd-input: no spare keycode free right now, dropping keysym {keysym:#x}");
                        return Ok(Spare::Dropped);
                    }
                }
            }
        };
        let kc = self.spares[idx].keycode;
        let s = &mut self.spares[idx];
        s.keysym = keysym;
        s.last_used = now;
        // Record before binding so a crash in between still gets cleaned up.
        self.save_state();
        self.conn
            .change_keyboard_mapping(1, kc, 2, &[keysym, keysym])?;
        // Round trip: the server has applied the mapping before our fake key press.
        self.conn.sync()?;
        log::debug!("fd-input: bound keysym {keysym:#x} to spare keycode {kc}");
        Ok(Spare::Bound(kc))
    }

    /// Restore idle (or, with `force`, all unpinned) spare bindings to NoSymbol.
    fn restore_spares(&mut self, force: bool) -> anyhow::Result<()> {
        let now = Instant::now();
        let mut restored = false;
        let mut keep = Vec::with_capacity(self.spares.len());
        for s in std::mem::take(&mut self.spares) {
            if !s.pinned && (force || now.duration_since(s.last_used) >= SPARE_IDLE) {
                self.conn
                    .change_keyboard_mapping(1, s.keycode, 2, &[0, 0])?;
                restored = true;
            } else {
                keep.push(s);
            }
        }
        self.spares = keep;
        if restored {
            self.conn.sync()?;
            self.save_state();
        }
        Ok(())
    }

    fn set_pinned(&mut self, keycode: u8, pinned: bool) {
        if let Some(s) = self.spares.iter_mut().find(|s| s.keycode == keycode) {
            s.pinned = pinned;
            s.last_used = Instant::now();
        }
    }

    fn mouse_move(&self, x: u16, y: u16) -> anyhow::Result<()> {
        let px = keysym::norm_to_pixel(x, self.width);
        let py = keysym::norm_to_pixel(y, self.height);
        self.conn
            .xtest_fake_input(MOTION_NOTIFY_EVENT, 0, 0, self.root, px, py, 0)?;
        Ok(())
    }

    fn mouse_button(&mut self, button: MouseButton, down: bool) -> anyhow::Result<()> {
        let b: u8 = match button {
            MouseButton::Left => 1,
            MouseButton::Middle => 2,
            MouseButton::Right => 3,
            MouseButton::Back => 8,
            MouseButton::Forward => 9,
        };
        let bit = 1u16 << b;
        let held = self.held_buttons & bit != 0;
        if down == held {
            return Ok(()); // duplicate press / release of an unpressed button
        }
        self.fake_button(b, down)?;
        if down {
            self.held_buttons |= bit;
        } else {
            self.held_buttons &= !bit;
        }
        Ok(())
    }

    fn scroll(&self, dx: i16, dy: i16) -> anyhow::Result<()> {
        for (delta, vertical) in [(dy, true), (dx, false)] {
            if let Some((button, n)) = keysym::scroll_plan(delta, vertical) {
                for _ in 0..n {
                    self.fake_button(button, true)?;
                    self.fake_button(button, false)?;
                }
            }
        }
        Ok(())
    }

    fn lookup_level0(&mut self, keysym: u32, group: u8) -> anyhow::Result<Option<u8>> {
        let exclude = self.spare_keycodes_in_use();
        if let Some(kc) = self.keymap.find_keysym_level0(keysym, group, &exclude) {
            return Ok(Some(kc));
        }
        // Cache may be stale (notify not yet seen): refresh once.
        self.refresh_keymap()?;
        let exclude = self.spare_keycodes_in_use();
        Ok(self.keymap.find_keysym_level0(keysym, group, &exclude))
    }

    fn key(&mut self, keysym: u32, down: bool) -> anyhow::Result<()> {
        if keysym == 0 {
            return Ok(());
        }
        if !down {
            match self.held_keys.remove(&keysym) {
                Some(h) => {
                    self.fake_key(h.keycode, false)?;
                    if h.spare {
                        self.set_pinned(h.keycode, false);
                    }
                }
                None => log::debug!("fd-input: release of unheld keysym {keysym:#x} ignored"),
            }
            return Ok(());
        }
        if let Some(h) = self.held_keys.get(&keysym) {
            // Repeat while held: press again on the same keycode.
            return self.fake_key(h.keycode, true);
        }
        if keysym::keysym_forbidden(keysym) {
            log::warn!("fd-input: refusing forbidden keysym {keysym:#x}");
            return Ok(());
        }
        if self.held_keys.len() >= MAX_HELD_KEYS {
            log::warn!("fd-input: too many held keys, ignoring keysym {keysym:#x}");
            return Ok(());
        }
        let (group, _) = self.xkb_state()?;
        let held = match self.lookup_level0(keysym, group)? {
            Some(kc) => HeldKey {
                keycode: kc,
                spare: false,
            },
            None => {
                if !keysym::keysym_allowed_for_binding(keysym) {
                    log::warn!(
                        "fd-input: keysym {keysym:#x} not on keyboard and not allowed for binding"
                    );
                    return Ok(());
                }
                match self.bind_spare(keysym)? {
                    Spare::Bound(kc) => {
                        self.set_pinned(kc, true);
                        HeldKey {
                            keycode: kc,
                            spare: true,
                        }
                    }
                    Spare::Dropped => return Ok(()),
                }
            }
        };
        self.fake_key(held.keycode, true)?;
        self.held_keys.insert(keysym, held);
        Ok(())
    }

    /// Shift keycodes the injector itself holds down (never the local user's).
    fn our_held_shift_keycodes(&self) -> Vec<u8> {
        self.held_keys
            .iter()
            .filter(|(ks, h)| {
                **ks == XK_SHIFT_L
                    || **ks == XK_SHIFT_R
                    || self.shift_keycodes().contains(&h.keycode)
            })
            .map(|(_, h)| h.keycode)
            .collect()
    }

    fn text(&mut self, ch: char) -> anyhow::Result<()> {
        let Some(ks) = keysym::char_to_keysym(ch) else {
            log::debug!("fd-input: ignoring untypeable char {:?}", ch);
            return Ok(());
        };
        let (group, mods) = self.xkb_state()?;
        let exclude = self.spare_keycodes_in_use();
        let mut found = self.keymap.find_for_text(ch, ks, group, &exclude);
        if found.is_none() && self.spares.iter().all(|s| s.keysym != ks) {
            self.refresh_keymap()?;
            let exclude = self.spare_keycodes_in_use();
            found = self.keymap.find_for_text(ch, ks, group, &exclude);
        }
        if let Some((kc, level)) = found {
            let shift_held = mods.contains(ModMask::SHIFT);
            let lock = mods.contains(ModMask::LOCK);
            let action = keysym::plan_shift(
                level,
                shift_held,
                lock,
                self.keymap.is_alpha_pair(kc, group),
            );
            match action {
                ShiftAction::None => return self.tap(kc),
                ShiftAction::Press => {
                    if let Some(skc) = self.shift_keycodes().iter().copied().find(|&k| k != 0) {
                        self.fake_key(skc, true)?;
                        self.tap(kc)?;
                        return self.fake_key(skc, false);
                    }
                    // No Shift key mapped: fall back to a spare binding.
                }
                ShiftAction::Release => {
                    let ours = self.our_held_shift_keycodes();
                    // Only if *all* shift comes from keys we hold can we lift it;
                    // a physically held local Shift is never touched.
                    let keys = self.conn.query_keymap()?.reply()?.keys;
                    let any_other_down = self.shift_keycodes().iter().any(|&k| {
                        k != 0 && !ours.contains(&k) && keys[k as usize / 8] & (1 << (k % 8)) != 0
                    });
                    if !ours.is_empty() && !any_other_down {
                        for &k in &ours {
                            self.fake_key(k, false)?;
                        }
                        self.tap(kc)?;
                        for &k in &ours {
                            self.fake_key(k, true)?;
                        }
                        return Ok(());
                    }
                    // Shift held locally / latched: spare binding is level-independent.
                }
            }
        }
        // Not on the active layout (or level unreachable): bind to a spare
        // keycode. Both levels carry the same keysym, so Shift does not matter.
        match self.bind_spare(ks)? {
            Spare::Bound(kc) => self.tap(kc),
            Spare::Dropped => Ok(()),
        }
    }
}

impl InputInjector for XTestInjector {
    fn inject(&mut self, ev: &InputEvent) -> anyhow::Result<()> {
        self.poll_events()?;
        if !self.spares.is_empty() {
            self.restore_spares(false)?;
        }
        let r = match *ev {
            InputEvent::MouseMove { x, y } => self.mouse_move(x, y),
            InputEvent::MouseButton { button, down } => self.mouse_button(button, down),
            InputEvent::Scroll { dx, dy } => self.scroll(dx, dy),
            InputEvent::Key { keysym, down } => self.key(keysym, down),
            InputEvent::Text { ch } => self.text(ch),
        };
        self.conn.flush()?;
        r
    }

    fn release_all(&mut self) -> anyhow::Result<()> {
        // Best effort: try everything even if one step fails, report the first error.
        let mut first_err: Option<anyhow::Error> = None;
        let mut note = |r: anyhow::Result<()>| {
            if let Err(e) = r {
                first_err.get_or_insert(e);
            }
        };
        for (_, h) in std::mem::take(&mut self.held_keys) {
            note(self.fake_key(h.keycode, false));
        }
        for b in 1..16u8 {
            if self.held_buttons & (1 << b) != 0 {
                note(self.fake_button(b, false));
            }
        }
        self.held_buttons = 0;
        // A spare binding used a moment ago may not have been read by the
        // focused client yet; give it a short grace period before restoring.
        if let Some(newest) = self.spares.iter().map(|s| s.last_used).max() {
            let grace = Duration::from_millis(200);
            let age = newest.elapsed();
            if age < grace {
                std::thread::sleep(grace - age);
            }
        }
        // Key releases must be processed before the keycodes lose their keysyms.
        note(self.conn.sync().map_err(Into::into));
        for s in &mut self.spares {
            s.pinned = false;
        }
        note(self.restore_spares(true));
        note(self.conn.flush().map_err(Into::into));
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn set_screen_size(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
    }
}

impl Drop for XTestInjector {
    fn drop(&mut self) {
        if let Err(e) = self.release_all() {
            log::warn!("fd-input: release_all on drop failed: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip() {
        let dir = std::env::temp_dir().join(format!("fd-input-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.state");
        let now = Instant::now();
        let spares = vec![
            SpareSlot {
                keycode: 248,
                keysym: 0x0100_0416,
                last_used: now,
                pinned: false,
            },
            SpareSlot {
                keycode: 230,
                keysym: 0x6c1,
                last_used: now,
                pinned: true,
            },
        ];
        write_state(&p, &spares).unwrap();
        let meta = std::fs::metadata(&p).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(parse_state(&text), vec![(248, 0x0100_0416), (230, 0x6c1)]);
        write_state(&p, &[]).unwrap();
        assert!(!p.exists());
        write_state(&p, &[]).unwrap(); // removing a missing file is fine
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(parse_state("garbage\n12\n7 zz\n"), vec![]);
    }
}
