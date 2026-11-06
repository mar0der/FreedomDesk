//! Pure, platform-independent helpers: keysym <-> char conversion, pointer
//! normalisation, scroll clamping, shift-level planning and a core-protocol
//! style keymap table. Everything here is unit tested without an X server.

/// Maximum wheel notches injected for a single `Scroll` event (per axis).
pub const MAX_SCROLL_NOTCHES: u32 = 20;

pub const XK_RETURN: u32 = 0xff0d;
pub const XK_TAB: u32 = 0xff09;

/// Map a character to an X11 keysym (`None` for control characters we refuse to type).
pub fn char_to_keysym(ch: char) -> Option<u32> {
    let cp = ch as u32;
    match ch {
        '\n' | '\r' => Some(XK_RETURN),
        '\t' => Some(XK_TAB),
        _ if (0x20..=0x7e).contains(&cp) || (0xa0..=0xff).contains(&cp) => Some(cp),
        // Remaining C0/C1 controls and DEL: nothing sensible to type.
        _ if cp < 0x20 || (0x7f..=0x9f).contains(&cp) => None,
        _ => Some(0x0100_0000 | cp),
    }
}

/// Legacy X11 Cyrillic keysyms 0x6c0..=0x6df (lower case, KOI8-R order).
/// 0x6e0..=0x6ff are the same letters in upper case.
const CYRILLIC_KOI8: [char; 32] = [
    'ю', 'а', 'б', 'ц', 'д', 'е', 'ф', 'г', 'х', 'и', 'й', 'к', 'л', 'м', 'н', 'о', //
    'п', 'я', 'р', 'с', 'т', 'у', 'ж', 'в', 'ь', 'ы', 'з', 'ш', 'э', 'щ', 'ч', 'ъ',
];

/// Best-effort keysym -> printable character (used to match keymap entries
/// against a requested character). Covers Latin-1, Unicode keysyms and the
/// legacy Cyrillic block (relevant for Bulgarian layouts).
pub fn keysym_to_char(ks: u32) -> Option<char> {
    match ks {
        0x20..=0x7e | 0xa0..=0xff => char::from_u32(ks),
        0x0100_0100..=0x0110_ffff => char::from_u32(ks & 0x00ff_ffff),
        0x6a3 => Some('ё'),
        0x6b3 => Some('Ё'),
        0x6c0..=0x6df => Some(CYRILLIC_KOI8[(ks - 0x6c0) as usize]),
        0x6e0..=0x6ff => CYRILLIC_KOI8[(ks - 0x6e0) as usize].to_uppercase().next(),
        _ => None,
    }
}

/// Normalised 0..=65535 coordinate -> pixel in 0..size-1.
pub fn norm_to_pixel(v: u16, size: u32) -> i16 {
    if size == 0 {
        return 0;
    }
    let px = (v as u64 * (size as u64 - 1)) / u16::MAX as u64;
    px.min(i16::MAX as u64) as i16
}

/// X core buttons and notch count for one scroll axis value.
/// `vertical`: positive = up (button 4), negative = down (5).
/// horizontal: positive = right (7), negative = left (6).
pub fn scroll_plan(delta: i16, vertical: bool) -> Option<(u8, u32)> {
    if delta == 0 {
        return None;
    }
    let n = (delta.unsigned_abs() as u32).min(MAX_SCROLL_NOTCHES);
    let button = match (vertical, delta > 0) {
        (true, true) => 4,
        (true, false) => 5,
        (false, false) => 6,
        (false, true) => 7,
    };
    Some((button, n))
}

/// What to do with Shift around a key press to reach the desired level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftAction {
    None,
    /// Press Shift_L around the key.
    Press,
    /// Temporarily release the currently held Shift key(s).
    Release,
}

/// `level`: 0 or 1 (column in the keymap row). `alpha_pair`: the key is a
/// lower/upper case letter pair so Caps Lock inverts the level.
pub fn plan_shift(level: usize, shift_held: bool, lock: bool, alpha_pair: bool) -> ShiftAction {
    let current = shift_held ^ (lock && alpha_pair);
    if current == (level == 1) {
        ShiftAction::None
    } else if shift_held {
        ShiftAction::Release
    } else {
        ShiftAction::Press
    }
}

/// May a Key event make us bind this keysym to a spare keycode?
/// Printable characters, the 0xff00 function/navigation/modifier/keypad block
/// and legacy national character sets are allowed; everything else (notably
/// the XF86 0x1008FExx VT-switch / ungrab / kill-client keysyms, 0xfedx
/// Terminate_Server & co, dead keys and other vendor keysyms) is refused.
pub fn keysym_allowed_for_binding(ks: u32) -> bool {
    matches!(ks,
        0x20..=0x7e | 0xa0..=0xff            // Latin-1
        | 0x1a1..=0x1ff                       // Latin-2
        | 0x2a1..=0x2fe                       // Latin-3
        | 0x3a2..=0x3fe                       // Latin-4
        | 0x4a1..=0x4df                       // Katakana
        | 0x5ac..=0x5f2                       // Arabic
        | 0x6a1..=0x6ff                       // Cyrillic
        | 0x7a1..=0x7f9                       // Greek
        | 0xcdf..=0xcfa                       // Hebrew
        | 0xda1..=0xdf9                       // Thai
        | 0x13bc..=0x13be                     // Latin-9 extras
        | 0x20a0..=0x20ac                     // currency
        | 0xff08..=0xffff                     // TTY, navigation, keypad, F-keys, modifiers, Delete
        | 0x0100_00a0..=0x0110_ffff) // Unicode keysyms
}

/// Keysyms we never press, even if they sit on a real key at level 0.
pub fn keysym_forbidden(ks: u32) -> bool {
    matches!(ks, 0xfe00..=0xfeff | 0x1008_fe00..=0x1008_feff)
}

/// Token bucket limiting how often new spare-keycode bindings are made.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    per_sec: f64,
    burst: f64,
    tokens: f64,
    last: std::time::Instant,
}

impl RateLimiter {
    pub fn new(per_sec: f64, burst: f64) -> Self {
        Self {
            per_sec,
            burst,
            tokens: burst,
            last: std::time::Instant::now(),
        }
    }

    pub fn try_take_at(&mut self, now: std::time::Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.per_sec).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn try_take(&mut self) -> bool {
        self.try_take_at(std::time::Instant::now())
    }
}

/// What XKB does when the active group exceeds a key's group count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutOfRange {
    #[default]
    Wrap,
    Clamp,
    Redirect(u8),
}

/// One key: per group, the keysyms per shift level.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Key {
    pub groups: Vec<Vec<u32>>,
    pub out_of_range: OutOfRange,
}

impl Key {
    pub fn new(groups: Vec<Vec<u32>>) -> Self {
        Self {
            groups,
            out_of_range: OutOfRange::Wrap,
        }
    }

    /// Build from an XKB KeySymMap (group_info, width, flat syms).
    pub fn from_xkb(group_info: u8, width: u8, syms: &[u32]) -> Self {
        let n = (group_info & 0x0f) as usize;
        let w = width as usize;
        let groups = if w == 0 {
            Vec::new()
        } else {
            syms.chunks(w).take(n).map(<[u32]>::to_vec).collect()
        };
        let out_of_range = match group_info & 0xc0 {
            0x40 => OutOfRange::Clamp,
            0x80 => OutOfRange::Redirect((group_info >> 4) & 0x03),
            _ => OutOfRange::Wrap,
        };
        Self {
            groups,
            out_of_range,
        }
    }

    /// Group index XKB actually uses for this key when `active` is locked.
    pub fn effective_group(&self, active: u8) -> Option<usize> {
        let n = self.groups.len();
        if n == 0 {
            return None;
        }
        let a = active as usize;
        Some(if a < n {
            a
        } else {
            match self.out_of_range {
                OutOfRange::Wrap => a % n,
                OutOfRange::Clamp => n - 1,
                OutOfRange::Redirect(g) if (g as usize) < n => g as usize,
                OutOfRange::Redirect(_) => 0,
            }
        })
    }

    pub fn sym(&self, active: u8, level: usize) -> u32 {
        self.effective_group(active)
            .and_then(|g| self.groups[g].get(level).copied())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.groups.iter().flatten().all(|&s| s == 0)
    }
}

/// XKB keyboard mapping (keysyms per keycode, per group, per level).
#[derive(Debug, Clone, Default)]
pub struct Keymap {
    pub min_keycode: u8,
    pub keys: Vec<Key>,
}

impl Keymap {
    pub fn new(min_keycode: u8, keys: Vec<Key>) -> Self {
        Self { min_keycode, keys }
    }

    pub fn keycodes(&self) -> impl Iterator<Item = u8> + '_ {
        (0..self.keys.len()).filter_map(move |i| u8::try_from(self.min_keycode as usize + i).ok())
    }

    pub fn key(&self, kc: u8) -> Option<&Key> {
        kc.checked_sub(self.min_keycode)
            .and_then(|i| self.keys.get(i as usize))
    }

    fn sym(&self, kc: u8, group: u8, level: usize) -> u32 {
        self.key(kc).map(|k| k.sym(group, level)).unwrap_or(0)
    }

    /// Keycode + level (0 or 1) typing `ch` (keysym `ks`) in the active group.
    /// Prefers level 0. Keycodes in `exclude` are skipped.
    pub fn find_for_text(
        &self,
        ch: char,
        ks: u32,
        group: u8,
        exclude: &[u8],
    ) -> Option<(u8, usize)> {
        for level in 0..2 {
            for kc in self.keycodes() {
                if exclude.contains(&kc) {
                    continue;
                }
                let s = self.sym(kc, group, level);
                if s != 0 && (s == ks || keysym_to_char(s) == Some(ch)) {
                    return Some((kc, level));
                }
            }
        }
        None
    }

    /// Keycode producing exactly `ks` at level 0 (unshifted) of the active group.
    pub fn find_keysym_level0(&self, ks: u32, group: u8, exclude: &[u8]) -> Option<u8> {
        if ks == 0 {
            return None;
        }
        self.keycodes()
            .find(|kc| !exclude.contains(kc) && self.sym(*kc, group, 0) == ks)
    }

    /// Lower/upper case letter pair at levels 0/1 (Caps Lock affects it).
    pub fn is_alpha_pair(&self, kc: u8, group: u8) -> bool {
        match (
            keysym_to_char(self.sym(kc, group, 0)),
            keysym_to_char(self.sym(kc, group, 1)),
        ) {
            (Some(a), Some(b)) => {
                a != b && a.is_lowercase() && a.to_uppercase().eq(std::iter::once(b))
            }
            _ => false,
        }
    }

    /// True if `kc` currently carries exactly our spare binding of `ks`.
    pub fn holds_binding(&self, kc: u8, ks: u32) -> bool {
        self.key(kc).is_some_and(|k| {
            k.groups.first().and_then(|g| g.first()) == Some(&ks)
                && k.groups.iter().flatten().all(|&s| s == ks || s == 0)
        })
    }

    pub fn is_unbound(&self, kc: u8) -> bool {
        self.key(kc).is_some_and(Key::is_empty)
    }

    /// Keycodes with no keysyms at all and not used as modifiers, highest first.
    pub fn spare_keycodes(&self, modifier_keycodes: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = self
            .keycodes()
            .filter(|&kc| kc > 8 && self.is_unbound(kc) && !modifier_keycodes.contains(&kc))
            .collect();
        v.reverse();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chars_to_keysyms() {
        assert_eq!(char_to_keysym('a'), Some(0x61));
        assert_eq!(char_to_keysym(' '), Some(0x20));
        assert_eq!(char_to_keysym('~'), Some(0x7e));
        assert_eq!(char_to_keysym('é'), Some(0xe9));
        assert_eq!(char_to_keysym('\u{a0}'), Some(0xa0));
        assert_eq!(char_to_keysym('Ж'), Some(0x0100_0416));
        assert_eq!(char_to_keysym('€'), Some(0x0100_20ac));
        assert_eq!(char_to_keysym('\n'), Some(XK_RETURN));
        assert_eq!(char_to_keysym('\t'), Some(XK_TAB));
        assert_eq!(char_to_keysym('\u{7}'), None);
        assert_eq!(char_to_keysym('\u{7f}'), None);
        assert_eq!(char_to_keysym('\u{85}'), None);
    }

    #[test]
    fn keysyms_to_chars() {
        assert_eq!(keysym_to_char(0x61), Some('a'));
        assert_eq!(keysym_to_char(0x0100_0416), Some('Ж'));
        assert_eq!(keysym_to_char(0x6c1), Some('а')); // Cyrillic_a
        assert_eq!(keysym_to_char(0x6e1), Some('А')); // Cyrillic_A
        assert_eq!(keysym_to_char(0x6d6), Some('ж')); // Cyrillic_zhe
        assert_eq!(keysym_to_char(0x6f6), Some('Ж'));
        assert_eq!(keysym_to_char(0x6df), Some('ъ'));
        assert_eq!(keysym_to_char(XK_RETURN), None);
        assert_eq!(keysym_to_char(0), None);
        for ch in "Здравей, мамо! ёЁ ѝ € é ~".chars() {
            assert_eq!(
                keysym_to_char(char_to_keysym(ch).unwrap()),
                Some(ch),
                "{ch}"
            );
        }
    }

    #[test]
    fn normalisation() {
        assert_eq!(norm_to_pixel(0, 3840), 0);
        assert_eq!(norm_to_pixel(u16::MAX, 3840), 3839);
        assert_eq!(norm_to_pixel(u16::MAX, 2160), 2159);
        assert_eq!(norm_to_pixel(32768, 3840), 1919);
        assert_eq!(norm_to_pixel(1234, 0), 0);
        assert_eq!(norm_to_pixel(u16::MAX, 1), 0);
        assert_eq!(norm_to_pixel(u16::MAX, 100_000), i16::MAX);
    }

    #[test]
    fn scroll_clamping() {
        assert_eq!(scroll_plan(0, true), None);
        assert_eq!(scroll_plan(1, true), Some((4, 1)));
        assert_eq!(scroll_plan(-3, true), Some((5, 3)));
        assert_eq!(scroll_plan(2, false), Some((7, 2)));
        assert_eq!(scroll_plan(-1, false), Some((6, 1)));
        assert_eq!(scroll_plan(i16::MAX, true), Some((4, MAX_SCROLL_NOTCHES)));
        assert_eq!(scroll_plan(i16::MIN, false), Some((6, MAX_SCROLL_NOTCHES)));
    }

    #[test]
    fn shift_planning() {
        use ShiftAction::*;
        assert_eq!(plan_shift(0, false, false, true), None);
        assert_eq!(plan_shift(1, false, false, true), Press);
        assert_eq!(plan_shift(1, true, false, true), None);
        assert_eq!(plan_shift(0, true, false, true), Release);
        // Caps Lock on a letter inverts.
        assert_eq!(plan_shift(1, false, true, true), None);
        assert_eq!(plan_shift(0, false, true, true), Press);
        assert_eq!(plan_shift(0, true, true, true), None);
        // Caps Lock does not affect non-letters.
        assert_eq!(plan_shift(1, false, true, false), Press);
    }

    fn test_map() -> Keymap {
        let k = |g: &[&[u32]]| Key::new(g.iter().map(|l| l.to_vec()).collect());
        Keymap::new(
            8,
            vec![
                k(&[]),                               // 8 (never a spare)
                k(&[&[0x61, 0x41]]),                  // 9: a A, one group (wraps)
                k(&[&[0x31, 0x21], &[0x31, 0x22]]),   // 10: 1 ! / 1 "
                k(&[&[0x62, 0x42], &[0x6c2, 0x6e2]]), // 11: b B / Cyrillic be BE
                k(&[]),                               // 12: spare
                k(&[&[XK_RETURN]]),                   // 13
                k(&[&[0xffe1]]),                      // 14: Shift_L
                k(&[]),                               // 15: spare but a modifier
                k(&[&[0x38, 0x2a, 0x5b]]),            // 16: 8 * [ (AltGr level 3)
                k(&[&[0xffbe], &[0xffbe]]),           // 17: F1
            ],
        )
    }

    #[test]
    fn keymap_lookup() {
        let m = test_map();
        assert_eq!(m.find_for_text('a', 0x61, 0, &[]), Some((9, 0)));
        assert_eq!(m.find_for_text('A', 0x41, 0, &[]), Some((9, 1)));
        // One-group key wraps into group 2.
        assert_eq!(m.find_for_text('a', 0x61, 1, &[]), Some((9, 0)));
        assert_eq!(m.find_for_text('!', 0x21, 0, &[]), Some((10, 1)));
        assert_eq!(m.find_for_text('!', 0x21, 1, &[]), None);
        assert_eq!(m.find_for_text('"', 0x22, 1, &[]), Some((10, 1)));
        assert_eq!(m.find_for_text('\n', XK_RETURN, 1, &[]), Some((13, 0)));
        // Per-group letters: only the active group counts.
        assert_eq!(m.find_for_text('b', 0x62, 0, &[]), Some((11, 0)));
        assert_eq!(m.find_for_text('b', 0x62, 1, &[]), None);
        assert_eq!(m.find_for_text('б', 0x0100_0431, 1, &[]), Some((11, 0)));
        assert_eq!(m.find_for_text('Б', 0x0100_0411, 1, &[]), Some((11, 1)));
        assert_eq!(m.find_for_text('б', 0x0100_0431, 0, &[]), None);
        // AltGr level is never used directly.
        assert_eq!(m.find_for_text('[', 0x5b, 0, &[]), None);
        assert_eq!(m.find_for_text('a', 0x61, 0, &[9]), None);

        assert_eq!(m.find_keysym_level0(0x61, 0, &[]), Some(9));
        assert_eq!(m.find_keysym_level0(0x41, 0, &[]), None); // shifted level
        assert_eq!(m.find_keysym_level0(0x5b, 0, &[]), None); // '[' on AltGr+8
        assert_eq!(m.find_keysym_level0(0x6c2, 1, &[]), Some(11));
        assert_eq!(m.find_keysym_level0(0x6c2, 0, &[]), None);
        assert_eq!(m.find_keysym_level0(0xffe1, 1, &[]), Some(14));
        assert_eq!(m.find_keysym_level0(0, 0, &[]), None);

        assert!(m.is_alpha_pair(9, 0));
        assert!(m.is_alpha_pair(11, 1));
        assert!(!m.is_alpha_pair(10, 0));
        assert_eq!(m.spare_keycodes(&[15]), vec![12]);
        assert!(m.key(200).is_none());
        assert!(m.key(7).is_none());
    }

    #[test]
    fn xkb_key_parsing_and_groups() {
        let k = Key::from_xkb(2, 2, &[0x61, 0x41, 0x6c6, 0x6e6]);
        assert_eq!(k.groups, vec![vec![0x61, 0x41], vec![0x6c6, 0x6e6]]);
        assert_eq!(k.sym(0, 0), 0x61);
        assert_eq!(k.sym(1, 1), 0x6e6);
        assert_eq!(k.sym(2, 0), 0x61); // wrap
        let c = Key::from_xkb(0x40 | 2, 1, &[1, 2]);
        assert_eq!(c.effective_group(3), Some(1)); // clamp
        let r = Key::from_xkb(0x80 | 0x10 | 2, 1, &[1, 2]);
        assert_eq!(r.effective_group(3), Some(1)); // redirect to group 1
        assert_eq!(Key::from_xkb(0, 0, &[]).effective_group(0), None);

        let m = Keymap::new(
            8,
            vec![Key::new(vec![]), Key::new(vec![vec![0x6c1, 0x6c1]])],
        );
        assert!(m.holds_binding(9, 0x6c1));
        assert!(!m.holds_binding(9, 0x6c2));
        assert!(!m.holds_binding(8, 0x6c1));
        assert!(m.is_unbound(8));
    }

    #[test]
    fn keysym_policy() {
        for ks in [
            0x61,
            0xe9,
            0x6c1,
            0x7e1,
            0xff0d,
            0xffbe,
            0xffe1,
            0xff95,
            0xffff,
            0x0100_0416,
        ] {
            assert!(keysym_allowed_for_binding(ks), "{ks:#x}");
        }
        for ks in [
            0,
            0x1f,
            0x7f,
            0xfe50,
            0xfed5,
            0x1008_fe01,
            0x1008_fe20,
            0x1008_ff13,
            0xff00,
            0x0100_0001,
        ] {
            assert!(!keysym_allowed_for_binding(ks), "{ks:#x}");
        }
        assert!(keysym_forbidden(0xfed5));
        assert!(keysym_forbidden(0x1008_fe01));
        assert!(!keysym_forbidden(0xffbe));
    }

    #[test]
    fn rate_limit() {
        use std::time::{Duration, Instant};
        let t0 = Instant::now();
        let mut r = RateLimiter::new(20.0, 20.0);
        let mut n = (0..100).filter(|_| r.try_take_at(t0)).count();
        assert_eq!(n, 20);
        assert!(!r.try_take_at(t0 + Duration::from_millis(10)));
        n = (0..100)
            .filter(|_| r.try_take_at(t0 + Duration::from_millis(1060)))
            .count();
        assert_eq!(n, 20);
    }
}
