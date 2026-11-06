//! egui keys → X11 keysyms (the wire key namespace, see fd-proto).

use eframe::egui::Key;

pub const SHIFT_L: u32 = 0xffe1;
pub const CONTROL_L: u32 = 0xffe3;
pub const ALT_L: u32 = 0xffe9;
pub const SUPER_L: u32 = 0xffeb;

/// Keys that never produce text: always forwarded as key events.
pub fn special(key: Key) -> Option<u32> {
    use Key::*;
    Some(match key {
        ArrowLeft => 0xff51,
        ArrowUp => 0xff52,
        ArrowRight => 0xff53,
        ArrowDown => 0xff54,
        Escape => 0xff1b,
        Tab => 0xff09,
        Backspace => 0xff08,
        Enter => 0xff0d,
        Insert => 0xff63,
        Delete => 0xffff,
        Home => 0xff50,
        End => 0xff57,
        PageUp => 0xff55,
        PageDown => 0xff56,
        F1 => 0xffbe,
        F2 => 0xffbf,
        F3 => 0xffc0,
        F4 => 0xffc1,
        F5 => 0xffc2,
        F6 => 0xffc3,
        F7 => 0xffc4,
        F8 => 0xffc5,
        F9 => 0xffc6,
        F10 => 0xffc7,
        F11 => 0xffc8,
        F12 => 0xffc9,
        _ => return None,
    })
}

/// Text-producing keys. Forwarded as key events only when a shortcut
/// modifier (Ctrl/Alt/Cmd) is held; otherwise the `Text` event types them.
pub fn character(key: Key) -> Option<u32> {
    use Key::*;
    let c = match key {
        A => 'a', B => 'b', C => 'c', D => 'd', E => 'e', F => 'f', G => 'g', H => 'h',
        I => 'i', J => 'j', K => 'k', L => 'l', M => 'm', N => 'n', O => 'o', P => 'p',
        Q => 'q', R => 'r', S => 's', T => 't', U => 'u', V => 'v', W => 'w', X => 'x',
        Y => 'y', Z => 'z',
        Num0 => '0', Num1 => '1', Num2 => '2', Num3 => '3', Num4 => '4',
        Num5 => '5', Num6 => '6', Num7 => '7', Num8 => '8', Num9 => '9',
        Space => ' ', Colon => ':', Comma => ',', Backslash => '\\', Slash => '/',
        Pipe => '|', Questionmark => '?', Exclamationmark => '!', OpenBracket => '[',
        CloseBracket => ']', OpenCurlyBracket => '{', CloseCurlyBracket => '}',
        Backtick => '`', Minus => '-', Period => '.', Plus => '+', Equals => '=',
        Semicolon => ';', Quote => '\'',
        _ => return None,
    };
    Some(c as u32) // ASCII keysyms equal their code points
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basics() {
        assert_eq!(special(Key::Enter), Some(0xff0d));
        assert_eq!(character(Key::C), Some(0x63));
        assert_eq!(special(Key::C), None);
        assert_eq!(character(Key::Enter), None);
    }
}
