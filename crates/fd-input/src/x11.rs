//! X11 input injection through the XTest extension (x11rb, pure Rust).
//!
//! Text that the current keymap cannot type (e.g. Cyrillic on a US layout) is
//! typed by temporarily binding the keysym to a spare, unused keycode via
//! ChangeKeyboardMapping (the xdotool technique). Bindings are kept for a short
//! while (and reused if the same character comes again) because X clients
//! re-read the keymap lazily after MappingNotify: restoring immediately after
//! the key press would race with them and they might see NoSymbol.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use fd_proto::{InputEvent, MouseButton};
use x11rb::connection::{Connection, RequestConnection as _};
use x11rb::protocol::xproto::{
    ConnectionExt as _, KeyButMask, Window, BUTTON_PRESS_EVENT, BUTTON_RELEASE_EVENT, KEY_PRESS_EVENT,
    KEY_RELEASE_EVENT, MOTION_NOTIFY_EVENT,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::NONE;

use crate::keysym::{self, Keymap, ShiftAction};
use crate::InputInjector;

/// Remote can hold at most this many distinct keys at once.
const MAX_HELD_KEYS: usize = 16;
/// At most this many spare keycodes are borrowed for unmapped keysyms.
const MAX_SPARE_SLOTS: usize = 32;
/// Never rebind a spare keycode sooner than this after it was last typed:
/// clients re-read the keymap lazily after MappingNotify and must still see
/// the old binding when they decode the earlier key press.
const MIN_REBIND_AGE: Duration = Duration::from_millis(300);
/// A spare binding unused for this long is restored to NoSymbol.
const SPARE_IDLE: Duration = Duration::from_secs(2);

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

pub struct XTestInjector {
    conn: RustConnection,
    root: Window,
    width: u32,
    height: u32,
    keymap: Keymap,
    keymap_dirty: bool,
    /// GetModifierMapping keycodes, 8 rows of `keycodes_per_modifier`.
    modmap: Vec<u8>,
    /// Spare keycodes (no keysyms, not modifiers) seen at the first keymap load.
    spare_candidates: Vec<u8>,
    spares: Vec<SpareSlot>,
    held_keys: HashMap<u32, HeldKey>,
    /// Bitmask of held buttons (bit n = button n).
    held_buttons: u16,
}

impl XTestInjector {
    pub fn open(width: u32, height: u32) -> anyhow::Result<Self> {
        let (conn, screen_num) = RustConnection::connect(None).context("fd-input: cannot connect to X display")?;
        if conn
            .extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)?
            .is_none()
        {
            bail!("fd-input: X server has no XTEST extension");
        }
        let v = conn.xtest_get_version(2, 2)?.reply()?;
        log::debug!("XTEST {}.{}", v.major_version, v.minor_version);
        let root = conn
            .setup()
            .roots
            .get(screen_num)
            .context("fd-input: X screen not found")?
            .root;
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
            held_keys: HashMap::new(),
            held_buttons: 0,
        };
        me.refresh_keymap()?;
        me.spare_candidates = me.keymap.spare_keycodes(&me.modmap);
        log::debug!("fd-input: {} spare keycodes available", me.spare_candidates.len());
        Ok(me)
    }

    fn refresh_keymap(&mut self) -> anyhow::Result<()> {
        let setup = self.conn.setup();
        let (min, max) = (setup.min_keycode, setup.max_keycode);
        let km = self.conn.get_keyboard_mapping(min, max - min + 1)?.reply()?;
        self.keymap = Keymap::new(min, km.keysyms_per_keycode as usize, km.keysyms);
        self.modmap = self.conn.get_modifier_mapping()?.reply()?.keycodes;
        self.keymap_dirty = false;
        // Drop spare slots whose binding was overwritten by someone else (e.g. a
        // layout switch rewrote the whole map): we must not "restore" them.
        let keymap = &self.keymap;
        self.spares.retain(|s| {
            let ok = keymap.row(s.keycode).first() == Some(&s.keysym);
            if !ok {
                log::debug!("fd-input: spare keycode {} binding lost", s.keycode);
            }
            ok
        });
        Ok(())
    }

    /// Drain pending events; a MappingNotify invalidates the keymap cache.
    fn poll_events(&mut self) -> anyhow::Result<()> {
        while let Some(ev) = self.conn.poll_for_event()? {
            match ev {
                Event::MappingNotify(_) => self.keymap_dirty = true,
                Event::Error(e) => log::warn!("fd-input: X error: {e:?}"),
                _ => {}
            }
        }
        if self.keymap_dirty {
            self.refresh_keymap()?;
        }
        Ok(())
    }

    fn shift_keycodes(&self) -> &[u8] {
        let per = self.modmap.len() / 8;
        &self.modmap[..per]
    }

    fn spare_keycodes_in_use(&self) -> Vec<u8> {
        self.spares.iter().map(|s| s.keycode).collect()
    }

    fn fake_key(&self, keycode: u8, down: bool) -> anyhow::Result<()> {
        let t = if down { KEY_PRESS_EVENT } else { KEY_RELEASE_EVENT };
        self.conn.xtest_fake_input(t, keycode, 0, NONE, 0, 0, 0)?;
        Ok(())
    }

    fn fake_button(&self, button: u8, down: bool) -> anyhow::Result<()> {
        let t = if down { BUTTON_PRESS_EVENT } else { BUTTON_RELEASE_EVENT };
        self.conn.xtest_fake_input(t, button, 0, NONE, 0, 0, 0)?;
        Ok(())
    }

    fn set_mapping(&self, keycode: u8, keysym: u32) -> anyhow::Result<()> {
        self.conn.change_keyboard_mapping(1, keycode, 2, &[keysym, keysym])?;
        Ok(())
    }

    /// Bind `keysym` to a spare keycode (reusing an existing binding when
    /// possible) and make sure the server has processed it.
    fn bind_spare(&mut self, keysym: u32) -> anyhow::Result<u8> {
        let now = Instant::now();
        if let Some(s) = self.spares.iter_mut().find(|s| s.keysym == keysym) {
            s.last_used = now;
            return Ok(s.keycode);
        }
        let in_use = self.spare_keycodes_in_use();
        let free = self
            .spare_candidates
            .iter()
            .copied()
            // Still unbound in the current map (nobody else grabbed it meanwhile).
            .find(|kc| !in_use.contains(kc) && self.keymap.row(*kc).iter().all(|&s| s == 0));
        let idx = match free {
            Some(kc) if self.spares.len() < MAX_SPARE_SLOTS => {
                self.spares.push(SpareSlot { keycode: kc, keysym: 0, last_used: now, pinned: false });
                self.spares.len() - 1
            }
            _ => self
                .spares
                .iter()
                .enumerate()
                .filter(|(_, s)| !s.pinned)
                .min_by_key(|(_, s)| s.last_used)
                .map(|(i, _)| i)
                .context("fd-input: no spare keycode available to type this character")?,
        };
        let age = self.spares[idx].last_used.elapsed();
        if self.spares[idx].keysym != 0 && age < MIN_REBIND_AGE {
            std::thread::sleep(MIN_REBIND_AGE - age);
        }
        let kc = self.spares[idx].keycode;
        self.set_mapping(kc, keysym)?;
        // Round trip: the server has applied the mapping before our fake key press.
        self.conn.sync()?;
        let s = &mut self.spares[idx];
        s.keysym = keysym;
        s.last_used = now;
        log::debug!("fd-input: bound keysym {keysym:#x} to spare keycode {kc}");
        Ok(kc)
    }

    /// Restore idle (or, with `force`, all unpinned) spare bindings to NoSymbol.
    fn restore_spares(&mut self, force: bool) -> anyhow::Result<()> {
        let now = Instant::now();
        let mut restored = false;
        let mut keep = Vec::with_capacity(self.spares.len());
        for s in std::mem::take(&mut self.spares) {
            if !s.pinned && (force || now.duration_since(s.last_used) >= SPARE_IDLE) {
                self.conn.change_keyboard_mapping(1, s.keycode, 2, &[0, 0])?;
                restored = true;
            } else {
                keep.push(s);
            }
        }
        self.spares = keep;
        if restored {
            self.conn.flush()?;
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
        self.conn.xtest_fake_input(MOTION_NOTIFY_EVENT, 0, 0, self.root, px, py, 0)?;
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

    fn lookup_keysym(&mut self, keysym: u32) -> anyhow::Result<Option<u8>> {
        let exclude = self.spare_keycodes_in_use();
        if let Some(kc) = self.keymap.find_keysym(keysym, &exclude) {
            return Ok(Some(kc));
        }
        // Cache may be stale (MappingNotify not yet seen): refresh once.
        self.refresh_keymap()?;
        let exclude = self.spare_keycodes_in_use();
        Ok(self.keymap.find_keysym(keysym, &exclude))
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
            // Auto-repeat from the viewer: press again on the same keycode.
            return self.fake_key(h.keycode, true);
        }
        if self.held_keys.len() >= MAX_HELD_KEYS {
            log::warn!("fd-input: too many held keys, ignoring keysym {keysym:#x}");
            return Ok(());
        }
        let held = match self.lookup_keysym(keysym)? {
            Some(kc) => HeldKey { keycode: kc, spare: false },
            None => {
                let kc = self.bind_spare(keysym)?;
                self.set_pinned(kc, true);
                HeldKey { keycode: kc, spare: true }
            }
        };
        self.fake_key(held.keycode, true)?;
        self.held_keys.insert(keysym, held);
        Ok(())
    }

    fn text(&mut self, ch: char) -> anyhow::Result<()> {
        let Some(ks) = keysym::char_to_keysym(ch) else {
            log::debug!("fd-input: ignoring untypeable char {:?}", ch);
            return Ok(());
        };
        let exclude = self.spare_keycodes_in_use();
        let mut found = self.keymap.find_for_text(ch, ks, &exclude);
        if found.is_none() && self.spares.iter().all(|s| s.keysym != ks) {
            self.refresh_keymap()?;
            let exclude = self.spare_keycodes_in_use();
            found = self.keymap.find_for_text(ch, ks, &exclude);
        }
        if let Some((kc, level)) = found {
            let ptr = self.conn.query_pointer(self.root)?.reply()?;
            let shift_held = ptr.mask.contains(KeyButMask::SHIFT);
            let lock = ptr.mask.contains(KeyButMask::LOCK);
            let action = keysym::plan_shift(level, shift_held, lock, self.keymap.is_alpha_pair(kc));
            let shift_kc = self.shift_keycodes().iter().copied().find(|&k| k != 0);
            match (action, shift_kc) {
                (ShiftAction::None, _) => {
                    self.fake_key(kc, true)?;
                    self.fake_key(kc, false)?;
                    return Ok(());
                }
                (ShiftAction::Press, Some(skc)) => {
                    self.fake_key(skc, true)?;
                    self.fake_key(kc, true)?;
                    self.fake_key(kc, false)?;
                    self.fake_key(skc, false)?;
                    return Ok(());
                }
                (ShiftAction::Release, _) => {
                    let keys = self.conn.query_keymap()?.reply()?.keys;
                    let down: Vec<u8> = self
                        .shift_keycodes()
                        .iter()
                        .copied()
                        .filter(|&k| k != 0 && keys[k as usize / 8] & (1 << (k % 8)) != 0)
                        .collect();
                    if !down.is_empty() {
                        for &k in &down {
                            self.fake_key(k, false)?;
                        }
                        self.fake_key(kc, true)?;
                        self.fake_key(kc, false)?;
                        for &k in &down {
                            self.fake_key(k, true)?;
                        }
                        return Ok(());
                    }
                    // Shift is latched/locked some other way: fall back to a spare binding.
                }
                (ShiftAction::Press, None) => {} // no Shift key mapped: fall back
            }
        }
        // Not typeable with the current layout: bind to a spare keycode. Both
        // levels carry the same keysym, so Shift state does not matter.
        let kc = self.bind_spare(ks)?;
        self.fake_key(kc, true)?;
        self.fake_key(kc, false)?;
        Ok(())
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
        for (_, h) in std::mem::take(&mut self.held_keys) {
            self.fake_key(h.keycode, false)?;
        }
        for b in 1..16u8 {
            if self.held_buttons & (1 << b) != 0 {
                self.fake_button(b, false)?;
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
        // Make sure key releases are processed before the keycodes lose their keysyms.
        self.conn.sync()?;
        for s in &mut self.spares {
            s.pinned = false;
        }
        self.restore_spares(true)?;
        self.conn.flush()?;
        Ok(())
    }
}

impl Drop for XTestInjector {
    fn drop(&mut self) {
        if let Err(e) = self.release_all() {
            log::warn!("fd-input: release_all on drop failed: {e:#}");
        }
    }
}
