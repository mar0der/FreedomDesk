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

/// Copy of the core keyboard mapping (GetKeyboardMapping).
#[derive(Debug, Clone, Default)]
pub struct Keymap {
    pub min_keycode: u8,
    pub per: usize,
    pub syms: Vec<u32>,
}

impl Keymap {
    pub fn new(min_keycode: u8, per: usize, syms: Vec<u32>) -> Self {
        Self { min_keycode, per, syms }
    }

    pub fn keycodes(&self) -> impl Iterator<Item = u8> + '_ {
        let n = self.syms.len().checked_div(self.per).unwrap_or(0);
        (0..n).filter_map(move |i| u8::try_from(self.min_keycode as usize + i).ok())
    }

    pub fn row(&self, kc: u8) -> &[u32] {
        if self.per == 0 || kc < self.min_keycode {
            return &[];
        }
        let start = (kc - self.min_keycode) as usize * self.per;
        self.syms.get(start..start + self.per).unwrap_or(&[])
    }

    fn col(&self, kc: u8, c: usize) -> u32 {
        self.row(kc).get(c).copied().unwrap_or(0)
    }

    /// True if the key types the same thing whatever XKB group is active
    /// (group 2 columns empty or equal to group 1). We cannot see the active
    /// group without XKB, so keys that differ per group are not used directly.
    fn group_consistent(&self, kc: u8) -> bool {
        let r = self.row(kc);
        if r.len() < 4 {
            return true;
        }
        (r[2] == 0 && r[3] == 0) || (r[2] == r[0] && r[3] == r[1])
    }

    /// Find a keycode + level (0/1) that types `ch` (keysym `ks`).
    /// Prefers level 0. Keycodes in `exclude` are skipped.
    pub fn find_for_text(&self, ch: char, ks: u32, exclude: &[u8]) -> Option<(u8, usize)> {
        for level in 0..2 {
            for kc in self.keycodes() {
                if exclude.contains(&kc) {
                    continue;
                }
                let s = self.col(kc, level);
                if s != 0 && (s == ks || keysym_to_char(s) == Some(ch)) && self.group_consistent(kc) {
                    return Some((kc, level));
                }
            }
        }
        None
    }

    /// Find a keycode producing exactly `ks` in any column (column 0 first).
    pub fn find_keysym(&self, ks: u32, exclude: &[u8]) -> Option<u8> {
        if ks == 0 {
            return None;
        }
        for c in 0..self.per {
            for kc in self.keycodes() {
                if !exclude.contains(&kc) && self.col(kc, c) == ks {
                    return Some(kc);
                }
            }
        }
        None
    }

    /// Lower/upper case letter pair in columns 0/1 (Caps Lock affects it).
    pub fn is_alpha_pair(&self, kc: u8) -> bool {
        match (keysym_to_char(self.col(kc, 0)), keysym_to_char(self.col(kc, 1))) {
            (Some(a), Some(b)) => a != b && a.is_lowercase() && a.to_uppercase().eq(std::iter::once(b)),
            _ => false,
        }
    }

    /// Keycodes with no keysyms at all and not used as modifiers, highest first.
    pub fn spare_keycodes(&self, modifier_keycodes: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = self
            .keycodes()
            .filter(|&kc| kc > 8 && self.row(kc).iter().all(|&s| s == 0) && !modifier_keycodes.contains(&kc))
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
            assert_eq!(keysym_to_char(char_to_keysym(ch).unwrap()), Some(ch), "{ch}");
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
        // min keycode 8, 4 syms per keycode.
        let rows: &[[u32; 4]] = &[
            [0, 0, 0, 0],                // 8 (never used as spare)
            [0x61, 0x41, 0x61, 0x41],    // 9: a A (same in both groups)
            [0x31, 0x21, 0, 0],          // 10: 1 !
            [0x62, 0x42, 0x6c2, 0x6e2],  // 11: b B / Cyrillic be BE (differs per group)
            [0, 0, 0, 0],                // 12: spare
            [XK_RETURN, 0, XK_RETURN, 0],// 13
            [0xffe1, 0, 0xffe1, 0],      // 14: Shift_L
            [0, 0, 0, 0],                // 15: spare but a modifier
            [0x6c1, 0x6e1, 0x6c1, 0x6e1],// 16: Cyrillic a in both groups
        ];
        Keymap::new(8, 4, rows.iter().flatten().copied().collect())
    }

    #[test]
    fn keymap_lookup() {
        let m = test_map();
        assert_eq!(m.find_for_text('a', 0x61, &[]), Some((9, 0)));
        assert_eq!(m.find_for_text('A', 0x41, &[]), Some((9, 1)));
        assert_eq!(m.find_for_text('!', 0x21, &[]), Some((10, 1)));
        assert_eq!(m.find_for_text('\n', XK_RETURN, &[]), Some((13, 0)));
        // Group-dependent key is not used directly.
        assert_eq!(m.find_for_text('b', 0x62, &[]), None);
        assert_eq!(m.find_for_text('б', 0x0100_0431, &[]), None);
        // Legacy Cyrillic keysym matched by character.
        assert_eq!(m.find_for_text('а', 0x0100_0430, &[]), Some((16, 0)));
        assert_eq!(m.find_for_text('А', 0x0100_0410, &[]), Some((16, 1)));
        assert_eq!(m.find_for_text('a', 0x61, &[9]), None);
        assert_eq!(m.find_for_text('ж', 0x0100_0436, &[]), None);

        assert_eq!(m.find_keysym(0x41, &[]), Some(9));
        assert_eq!(m.find_keysym(0xffe1, &[]), Some(14));
        assert_eq!(m.find_keysym(0x6c2, &[]), Some(11));
        assert_eq!(m.find_keysym(0, &[]), None);
        assert_eq!(m.find_keysym(0x1234, &[]), None);

        assert!(m.is_alpha_pair(9));
        assert!(m.is_alpha_pair(16));
        assert!(!m.is_alpha_pair(10));
        assert_eq!(m.spare_keycodes(&[15]), vec![12]);
        assert!(m.row(200).is_empty());
    }
}
