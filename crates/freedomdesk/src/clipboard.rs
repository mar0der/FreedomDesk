//! Text clipboard sync (opt-in; see docs/clipboard.md for the threat model).
//!
//! The pure logic ([`sanitize`], [`Engine`]) is backend-agnostic and unit-tested
//! with a fake clipboard. [`SystemClipboard`] wraps `arboard` for real use.
//!
//! Clipboard contents are never logged: callers log byte lengths only.

use anyhow::{anyhow, Result};
use fd_proto::{caps, CLIPBOARD_MAX_BYTES};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How often the local clipboard is checked for changes.
pub const POLL_EVERY: Duration = Duration::from_millis(500);

/// The OS clipboard, as seen by the sync logic.
pub trait ClipboardBackend: Send {
    /// Current text, or `None` when empty / not text.
    fn get_text(&mut self) -> Result<Option<String>>;
    fn set_text(&mut self, text: &str) -> Result<()>;
}

impl ClipboardBackend for Box<dyn ClipboardBackend> {
    fn get_text(&mut self) -> Result<Option<String>> {
        (**self).get_text()
    }
    fn set_text(&mut self, text: &str) -> Result<()> {
        (**self).set_text(text)
    }
}

/// `arboard`-backed clipboard (X11 on Linux, NSPasteboard on macOS, Win32 on Windows).
pub struct SystemClipboard(arboard::Clipboard);

impl SystemClipboard {
    pub fn new() -> Result<Self> {
        Ok(Self(arboard::Clipboard::new().map_err(|e| anyhow!("opening clipboard: {e}"))?))
    }
}

impl ClipboardBackend for SystemClipboard {
    fn get_text(&mut self) -> Result<Option<String>> {
        match self.0.get_text() {
            Ok(t) => Ok(Some(t)),
            // Empty or non-text contents are normal, not errors.
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(anyhow!("reading clipboard: {e}")),
        }
    }
    fn set_text(&mut self, text: &str) -> Result<()> {
        self.0.set_text(text.to_owned()).map_err(|e| anyhow!("writing clipboard: {e}"))
    }
}

/// Capability bits the viewer offers in `Hello`.
pub fn viewer_offer(enabled: bool) -> u32 {
    if enabled {
        caps::KNOWN
    } else {
        0
    }
}

/// What the host grants for a session: nothing unless `--clipboard`; a view-only
/// session (flag, or input injection unavailable) never lets the viewer write
/// the host clipboard. Returns the negotiated bits for `Welcome`.
pub fn host_negotiate(hello_caps: u32, enabled: bool, can_inject: bool) -> u32 {
    let offer = match (enabled, can_inject) {
        (false, _) => 0,
        (true, true) => caps::KNOWN,
        (true, false) => caps::CLIPBOARD_TO_VIEWER,
    };
    caps::negotiate(hello_caps, offer)
}

/// Engine permissions `(may_send, may_apply)` for the host side of a negotiated session.
pub fn host_perms(negotiated: u32) -> (bool, bool) {
    (negotiated & caps::CLIPBOARD_TO_VIEWER != 0, negotiated & caps::CLIPBOARD_TO_HOST != 0)
}

/// Engine permissions `(may_send, may_apply)` for the viewer side.
pub fn viewer_perms(negotiated: u32) -> (bool, bool) {
    let (s, a) = host_perms(negotiated);
    (a, s)
}

/// Make received (or locally read) text safe to paste: `None` if it must be
/// dropped. Oversized text is dropped, never truncated (a cut-off command is
/// worse than none). `\r\n`/`\r` become `\n`; NUL, ESC and other control
/// characters (except `\n` and `\t`) are removed; empty results are dropped.
pub fn sanitize(text: &str) -> Option<String> {
    if text.len() > CLIPBOARD_MAX_BYTES {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\n' | '\t' => out.push(c),
            c if c.is_control() => {}
            // Bidi overrides can disguise pasted commands.
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {}
            c => out.push(c),
        }
    }
    if out.trim().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn digest(text: &str) -> u64 {
    let mut h = DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

/// One side's sync state: polls the local clipboard, applies remote text, and
/// suppresses echoes so the two sides never ping-pong.
pub struct Engine<B> {
    backend: B,
    /// Digest of the clipboard content last seen locally or written by us.
    last: Option<u64>,
    primed: bool,
    may_send: bool,
    may_apply: bool,
}

impl<B: ClipboardBackend> Engine<B> {
    /// `may_send`: local changes go to the peer. `may_apply`: peer text may overwrite ours.
    pub fn new(backend: B, may_send: bool, may_apply: bool) -> Self {
        Self { backend, last: None, primed: false, may_send, may_apply }
    }

    /// Check the local clipboard; returns sanitized text that is new and should be sent.
    /// The first call only records the pre-existing content (it is never sent).
    pub fn poll(&mut self) -> Option<String> {
        let current = match self.backend.get_text() {
            Ok(t) => t,
            Err(e) => {
                log::debug!("clipboard poll: {e:#}");
                return None;
            }
        };
        let d = current.as_deref().map(digest);
        if !self.primed {
            self.primed = true;
            self.last = d;
            return None;
        }
        if d == self.last {
            return None;
        }
        self.last = d;
        if !self.may_send {
            return None;
        }
        sanitize(&current?)
    }

    /// Write text received from the peer. Returns the byte length written, or
    /// `None` when refused (not allowed, too big, empty, or backend failure).
    pub fn apply(&mut self, text: &str) -> Option<usize> {
        if !self.may_apply {
            return None;
        }
        let clean = sanitize(text)?;
        if let Err(e) = self.backend.set_text(&clean) {
            log::warn!("{e:#}");
            return None;
        }
        // Remember what we wrote so the next poll does not echo it back.
        self.last = Some(digest(&clean));
        self.primed = true;
        Some(clean.len())
    }
}

pub type SharedEngine = Arc<Mutex<Engine<Box<dyn ClipboardBackend>>>>;

/// Open the system clipboard for a session. `None` (with a warning) if unavailable.
pub fn open_engine(may_send: bool, may_apply: bool) -> Option<SharedEngine> {
    match SystemClipboard::new() {
        Ok(c) => Some(Arc::new(Mutex::new(Engine::new(Box::new(c) as Box<dyn ClipboardBackend>, may_send, may_apply)))),
        Err(e) => {
            log::warn!("clipboard sync unavailable: {e:#}");
            None
        }
    }
}

/// Sets the flag when dropped: ties a poller's lifetime to a session scope, so
/// it also stops on early returns and when the session object is dropped.
pub struct StopOnDrop(pub Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Poll in a background thread until `stop` is set; `send` gets each new local
/// text and returns false when the session is gone.
pub fn spawn_poller(
    engine: SharedEngine,
    stop: Arc<AtomicBool>,
    mut send: impl FnMut(String) -> bool + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new().name("clipboard".into()).spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            let new = engine.lock().ok().and_then(|mut e| e.poll());
            if let Some(text) = new {
                if !send(text) {
                    return;
                }
            }
            std::thread::sleep(POLL_EVERY);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poller_stops_when_scope_drops() {
        let fake = Fake::default();
        let engine: SharedEngine = Arc::new(Mutex::new(Engine::new(Box::new(fake) as Box<dyn ClipboardBackend>, true, true)));
        let stop = Arc::new(AtomicBool::new(false));
        let guard = StopOnDrop(stop.clone());
        let h = spawn_poller(engine, stop.clone(), |_| true).unwrap();
        drop(guard);
        assert!(stop.load(Ordering::SeqCst));
        h.join().unwrap(); // returns within one poll period
    }

    /// In-memory clipboard; the `Arc` lets tests play the role of "another app".
    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<Option<String>>>);
    impl Fake {
        fn user_copies(&self, t: &str) {
            *self.0.lock().unwrap() = Some(t.to_string());
        }
        fn contents(&self) -> Option<String> {
            self.0.lock().unwrap().clone()
        }
    }
    impl ClipboardBackend for Fake {
        fn get_text(&mut self) -> Result<Option<String>> {
            Ok(self.contents())
        }
        fn set_text(&mut self, t: &str) -> Result<()> {
            self.user_copies(t);
            Ok(())
        }
    }

    #[test]
    fn session_negotiation_matrix() {
        let all = caps::KNOWN;
        // old viewer (caps 0) or host without --clipboard: nothing, in every combination
        assert_eq!(host_negotiate(0, true, true), 0);
        assert_eq!(host_negotiate(viewer_offer(true), false, true), 0);
        assert_eq!(host_negotiate(viewer_offer(false), true, true), 0);
        // both opt in
        assert_eq!(host_negotiate(viewer_offer(true), true, true), all);
        // view-only host: viewer can receive but never write
        let n = host_negotiate(viewer_offer(true), true, false);
        assert_eq!(n, caps::CLIPBOARD_TO_VIEWER);
        assert_eq!(host_perms(n), (true, false));
        assert_eq!(viewer_perms(n), (false, true));
        // old host answers Welcome with caps 0: viewer syncs nothing
        assert_eq!(viewer_perms(0), (false, false));
        assert_eq!(host_perms(all), (true, true));
    }

    #[test]
    fn sanitize_rules() {
        assert_eq!(sanitize("a\r\nb\rc").as_deref(), Some("a\nb\nc"));
        assert_eq!(sanitize("x\0y\x1b[31mz\x7f").as_deref(), Some("xy[31mz"));
        assert_eq!(sanitize("tab\there").as_deref(), Some("tab\there"));
        assert_eq!(sanitize("a\u{202e}b").as_deref(), Some("ab"));
        assert_eq!(sanitize("здравей 🌍").as_deref(), Some("здравей 🌍"));
        assert_eq!(sanitize(""), None);
        assert_eq!(sanitize(" \n\t\0"), None);
    }

    #[test]
    fn size_cap_drops_instead_of_truncating() {
        assert!(sanitize(&"a".repeat(CLIPBOARD_MAX_BYTES)).is_some());
        assert_eq!(sanitize(&"a".repeat(CLIPBOARD_MAX_BYTES + 1)), None);
        // The cap counts UTF-8 bytes, not chars.
        assert_eq!(sanitize(&"ж".repeat(CLIPBOARD_MAX_BYTES / 2 + 1)), None);
        let fake = Fake::default();
        let mut e = Engine::new(fake.clone(), true, true);
        assert_eq!(e.apply(&"a".repeat(CLIPBOARD_MAX_BYTES + 1)), None);
        assert_eq!(fake.contents(), None);
        e.poll();
        fake.user_copies(&"a".repeat(CLIPBOARD_MAX_BYTES + 1));
        assert_eq!(e.poll(), None);
    }

    #[test]
    fn existing_clipboard_is_not_sent_at_start() {
        let fake = Fake::default();
        fake.user_copies("password from before the session");
        let mut e = Engine::new(fake.clone(), true, true);
        assert_eq!(e.poll(), None);
        assert_eq!(e.poll(), None);
        fake.user_copies("new");
        assert_eq!(e.poll().as_deref(), Some("new"));
        assert_eq!(e.poll(), None); // unchanged
    }

    #[test]
    fn echo_is_suppressed() {
        let fake = Fake::default();
        let mut e = Engine::new(fake.clone(), true, true);
        e.poll();
        assert_eq!(e.apply("from peer"), Some(9));
        assert_eq!(fake.contents().as_deref(), Some("from peer"));
        assert_eq!(e.poll(), None, "text we just wrote must not go back");
        // A genuine later copy of different text is sent...
        fake.user_copies("mine");
        assert_eq!(e.poll().as_deref(), Some("mine"));
        // ...and the peer may legitimately send the same text again later.
        assert_eq!(e.apply("from peer"), Some(9));
        assert_eq!(e.poll(), None);
    }

    #[test]
    fn two_sides_do_not_ping_pong() {
        let (fa, fb) = (Fake::default(), Fake::default());
        let mut a = Engine::new(fa.clone(), true, true);
        let mut b = Engine::new(fb.clone(), true, true);
        a.poll();
        b.poll();
        fa.user_copies("hello\r\nworld");
        let mut transfers = 0;
        for _ in 0..10 {
            if let Some(t) = a.poll() {
                transfers += 1;
                b.apply(&t);
            }
            if let Some(t) = b.poll() {
                transfers += 1;
                a.apply(&t);
            }
        }
        assert_eq!(transfers, 1);
        assert_eq!(fb.contents().as_deref(), Some("hello\nworld"));
    }

    #[test]
    fn direction_flags_are_enforced() {
        // View-only host: may send its clipboard, must never write it.
        let fake = Fake::default();
        fake.user_copies("host secret");
        let mut host = Engine::new(fake.clone(), true, false);
        assert_eq!(host.poll(), None);
        assert_eq!(host.apply("evil"), None);
        assert_eq!(fake.contents().as_deref(), Some("host secret"));
        fake.user_copies("changed");
        assert_eq!(host.poll().as_deref(), Some("changed"));

        // Receive-only side never sends local changes.
        let mut rx = Engine::new(fake.clone(), false, true);
        rx.poll();
        fake.user_copies("local");
        assert_eq!(rx.poll(), None);
        assert_eq!(rx.apply("ok"), Some(2));
    }

    struct Broken;
    impl ClipboardBackend for Broken {
        fn get_text(&mut self) -> Result<Option<String>> {
            Err(anyhow!("no display"))
        }
        fn set_text(&mut self, _: &str) -> Result<()> {
            Err(anyhow!("no display"))
        }
    }

    #[test]
    fn backend_errors_are_not_fatal() {
        let mut e = Engine::new(Broken, true, true);
        assert_eq!(e.poll(), None);
        assert_eq!(e.apply("x"), None);
    }
}
