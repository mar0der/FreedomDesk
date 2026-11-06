//! Viewer: connect, verify the host key, show the screen, forward input.

use crate::{keymap, load_identity};
use anyhow::{anyhow, bail, Context, Result};
use eframe::egui;
use fd_crypto::{normalize_fingerprint, KnownHosts, PinCheck, SecureReader, SecureWriter};
use fd_proto::{HostMsg, InputEvent, MouseButton, ViewerMsg, DEFAULT_PORT, NORM_MAX, PROTOCOL_VERSION};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(clap::Args)]
pub struct ViewArgs {
    /// Host to connect to: name or IP, optionally :port (e.g. the21th or 100.116.143.66:47801).
    host: String,
    /// Expected host fingerprint. Strongly recommended on first connect.
    #[arg(long)]
    expect_fingerprint: Option<String>,
    /// No window: receive and decode frames, print stats, exit (for tests/CI).
    #[arg(long)]
    headless: bool,
    /// Headless: stop after this many decoded frames.
    #[arg(long, default_value_t = 150)]
    frames: u64,
    /// Name shown to the host user in the consent prompt.
    #[arg(long)]
    name: Option<String>,
    /// Trust and pin an unknown host key without asking (non-interactive use).
    #[arg(long)]
    trust_new: bool,
}

struct Connected {
    reader: SecureReader,
    writer: SecureWriter,
    host_name: String,
    host_fingerprint: String,
    video_size: (u32, u32),
}

pub fn run(dir: &Path, args: ViewArgs) -> Result<()> {
    let conn = connect(dir, &args)?;
    if args.headless {
        headless(conn, args.frames)
    } else {
        gui(conn)
    }
}

fn split_host(s: &str) -> (String, u16) {
    // [v6]:port, v4:port, name:port, or bare host.
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once("]:") {
            if let Ok(p) = p.parse() {
                return (h.to_string(), p);
            }
        }
        return (rest.trim_end_matches(']').to_string(), DEFAULT_PORT);
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => match p.parse() {
            Ok(p) => (h.to_string(), p),
            Err(_) => (s.to_string(), DEFAULT_PORT),
        },
        _ => (s.to_string(), DEFAULT_PORT),
    }
}

fn connect(dir: &Path, args: &ViewArgs) -> Result<Connected> {
    let identity = load_identity(dir)?;
    let (host, port) = split_host(&args.host);
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}"))?
        .next()
        .ok_or_else(|| anyhow!("{host} did not resolve"))?;
    eprintln!("Connecting to {addr} …");
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).with_context(|| format!("connecting to {addr}"))?;
    let mut session = fd_crypto::connect(stream, &identity).context("secure handshake")?;
    let host_fp = session.remote_fingerprint();

    // Key pinning: explicit expectation first, then trust-on-first-use.
    if let Some(exp) = &args.expect_fingerprint {
        if normalize_fingerprint(exp) != normalize_fingerprint(&host_fp) {
            bail!("HOST KEY MISMATCH: expected {exp}, host presented {host_fp}. Refusing to connect.");
        }
    }
    let label = format!("{host}:{port}");
    let kh_path = dir.join("known_hosts");
    let mut kh = KnownHosts::load(&kh_path)?;
    match kh.check(&label, &session.remote_public) {
        PinCheck::Match => {}
        PinCheck::Unknown => {
            let aliases = kh.labels_for(&session.remote_public);
            if !aliases.is_empty() {
                eprintln!("Host key already pinned as: {} (same machine, new name).", aliases.join(", "));
            }
            if args.expect_fingerprint.is_none() && aliases.is_empty() && !args.trust_new {
                eprintln!("First connection to {label}. Host fingerprint:\n\n    {host_fp}\n");
                eprintln!("Compare it with `freedomdesk id` on the host (read it out over the phone).");
                if !confirm("Trust this host and remember its key? [y/N] ")? {
                    bail!("not trusted; nothing was sent to the host (use --expect-fingerprint or --trust-new)");
                }
            }
            kh.pin(&label, &session.remote_public)?;
            eprintln!("Pinned {label} = {host_fp}");
        }
        PinCheck::Mismatch { pinned_fingerprint } => bail!(
            "HOST KEY CHANGED for {label}!\n  pinned:    {pinned_fingerprint}\n  presented: {host_fp}\n\
             This could be an attack. If the host really was reinstalled, remove its line from {} and reconnect.",
            kh_path.display()
        ),
    }

    let viewer_name = args.name.clone().unwrap_or_else(|| {
        let user = std::env::var("USER").unwrap_or_else(|_| "someone".into());
        format!("{user}@{}", crate::host::hostname())
    });
    session.writer.send(&fd_proto::encode(&ViewerMsg::Hello { protocol: PROTOCOL_VERSION, viewer_name })?)?;
    eprintln!("Secure channel up (host {host_fp}). Waiting for the host to allow the session …");

    session.reader.set_timeout(Some(Duration::from_secs(330)))?;
    let reply: HostMsg = fd_proto::decode(&session.reader.recv().context("waiting for host")?)?;
    session.reader.set_timeout(None)?;
    match reply {
        HostMsg::Welcome { protocol, host_name, screen_width, screen_height, video_width, video_height } => {
            let host_name = clean(&host_name);
            if protocol != PROTOCOL_VERSION {
                bail!("host speaks protocol {protocol}, we speak {PROTOCOL_VERSION}");
            }
            eprintln!("Allowed. {host_name}: screen {screen_width}x{screen_height}, video {video_width}x{video_height}");
            Ok(Connected {
                reader: session.reader,
                writer: session.writer,
                host_name,
                host_fingerprint: host_fp,
                video_size: (video_width, video_height),
            })
        }
        HostMsg::Denied { reason } => bail!("host denied the session: {}", clean(&reason)),
        other => bail!("unexpected first message from host: {other:?}"),
    }
}

/// Ask a yes/no question on the terminal. Non-interactive stdin = no.
fn confirm(prompt: &str) -> Result<bool> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn clean(s: &str) -> String {
    crate::consent::sanitize(s, 120)
}

fn now_us(t0: Instant) -> u64 {
    t0.elapsed().as_micros() as u64
}

/// Writer thread: drains the outgoing queue, pings once a second.
fn spawn_writer(mut writer: SecureWriter, rx: Receiver<ViewerMsg>, t0: Instant) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last_ping = Instant::now() - Duration::from_secs(5);
        loop {
            let msg = match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(m) => Some(m),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => {
                    let _ = writer.send(&fd_proto::encode(&ViewerMsg::Bye).unwrap_or_default());
                    writer.shutdown();
                    return;
                }
            };
            let mut out = Vec::new();
            out.extend(msg);
            if last_ping.elapsed() >= Duration::from_secs(1) {
                last_ping = Instant::now();
                out.push(ViewerMsg::Ping { ts_us: now_us(t0) });
            }
            for m in out {
                let bye = m == ViewerMsg::Bye;
                let ok = fd_proto::encode(&m).and_then(|b| writer.send(&b)).is_ok();
                if !ok || bye {
                    writer.shutdown();
                    return;
                }
            }
        }
    })
}

#[derive(Default)]
struct Stats {
    frames: u64,
    bytes: u64,
    rtt_ms: Option<f64>,
}

/// Decoder that, after an error, drops P-frames until a keyframe arrives and
/// rate-limits keyframe requests (no request storms on a lossy link).
struct GatedDecoder {
    dec: fd_codec::VideoDecoder,
    need_keyframe: bool,
    last_request: Option<Instant>,
}

const MAX_DIM: u32 = 8192;

impl GatedDecoder {
    fn new() -> Result<Self> {
        Ok(Self { dec: fd_codec::VideoDecoder::new()?, need_keyframe: false, last_request: None })
    }

    fn decode(&mut self, data: &[u8], keyframe: bool, tx: &Sender<ViewerMsg>) -> Option<fd_codec::DecodedFrame> {
        if self.need_keyframe && !keyframe {
            self.request(tx);
            return None;
        }
        match self.dec.decode(data) {
            Ok(Some(f)) if f.width <= MAX_DIM && f.height <= MAX_DIM => {
                self.need_keyframe = false;
                Some(f)
            }
            Ok(Some(f)) => {
                log::warn!("ignoring oversized picture {}x{}", f.width, f.height);
                None
            }
            Ok(None) => None,
            Err(e) => {
                log::warn!("decode: {e:#}; waiting for keyframe");
                self.need_keyframe = true;
                self.request(tx);
                None
            }
        }
    }

    fn request(&mut self, tx: &Sender<ViewerMsg>) {
        if self.last_request.is_none_or(|t| t.elapsed() >= Duration::from_millis(500)) {
            self.last_request = Some(Instant::now());
            let _ = tx.send(ViewerMsg::RequestKeyframe);
        }
    }
}

// ---------------------------------------------------------------- headless

fn headless(conn: Connected, want: u64) -> Result<()> {
    let t0 = Instant::now();
    let (tx, rx) = mpsc::channel();
    let shutdown = conn.writer.shutdown_handle()?;
    let wt = spawn_writer(conn.writer, rx, t0);
    let mut reader = conn.reader;
    reader.set_timeout(Some(Duration::from_secs(10)))?;
    let mut dec = GatedDecoder::new()?;
    let mut st = Stats::default();
    let mut dims = (0, 0);
    let start = Instant::now();
    let mut first_frame = None;
    while st.frames < want {
        let msg: HostMsg = fd_proto::decode(&reader.recv()?)?;
        match msg {
            HostMsg::Video { data, keyframe, .. } => {
                st.bytes += data.len() as u64;
                if let Some(f) = dec.decode(&data, keyframe, &tx) {
                    dims = (f.width, f.height);
                    st.frames += 1;
                    first_frame.get_or_insert_with(|| start.elapsed());
                }
            }
            HostMsg::Pong { ts_us } => st.rtt_ms = Some((now_us(t0).saturating_sub(ts_us)) as f64 / 1000.0),
            HostMsg::Bye { reason } => bail!("host ended session: {}", clean(&reason)),
            other => log::debug!("ignoring {other:?}"),
        }
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "OK host={} fp={} decoded={} frames {}x{} in {:.2}s ({:.1} fps), first frame {:.0} ms, avg {:.1} KB/frame, {:.2} Mbit/s, rtt {}",
        conn.host_name,
        conn.host_fingerprint,
        st.frames,
        dims.0,
        dims.1,
        secs,
        st.frames as f64 / secs,
        first_frame.unwrap_or_default().as_secs_f64() * 1000.0,
        st.bytes as f64 / st.frames.max(1) as f64 / 1024.0,
        st.bytes as f64 * 8.0 / secs / 1e6,
        st.rtt_ms.map(|r| format!("{r:.1} ms")).unwrap_or_else(|| "n/a".into()),
    );
    let _ = tx.send(ViewerMsg::Bye);
    drop(tx);
    let _ = wt.join();
    shutdown.shutdown();
    Ok(())
}

// ---------------------------------------------------------------- GUI

struct Latest {
    frame: Option<fd_codec::DecodedFrame>,
    stats: Stats,
    ended: Option<String>,
}

fn spawn_reader(mut reader: SecureReader, latest: Arc<Mutex<Latest>>, tx: Sender<ViewerMsg>, ctx: egui::Context, t0: Instant) {
    std::thread::spawn(move || {
        let result = (|| -> Result<String> {
            let mut dec = GatedDecoder::new()?;
            loop {
                let msg: HostMsg = fd_proto::decode(&reader.recv()?)?;
                match msg {
                    HostMsg::Video { data, keyframe, .. } => {
                        let n = data.len() as u64;
                        if let Some(f) = dec.decode(&data, keyframe, &tx) {
                            let mut l = latest.lock().unwrap();
                            l.frame = Some(f);
                            l.stats.frames += 1;
                            l.stats.bytes += n;
                            drop(l);
                            ctx.request_repaint();
                        }
                    }
                    HostMsg::Pong { ts_us } => {
                        latest.lock().unwrap().stats.rtt_ms = Some(now_us(t0).saturating_sub(ts_us) as f64 / 1000.0);
                    }
                    HostMsg::Bye { reason } => return Ok(clean(&reason)),
                    other => log::debug!("ignoring {other:?}"),
                }
            }
        })();
        let why = match result {
            Ok(r) => format!("Session ended: {r}"),
            Err(e) => format!("Disconnected: {e:#}"),
        };
        latest.lock().unwrap().ended = Some(why);
        ctx.request_repaint();
    });
}

#[derive(Default, Clone, Copy, PartialEq)]
struct Mods {
    shift: bool,
    ctrl: bool,
    alt: bool,
    sup: bool,
}

impl From<egui::Modifiers> for Mods {
    fn from(m: egui::Modifiers) -> Self {
        // macOS Cmd acts as Ctrl on the (Linux/Windows) host, so Cmd+C/V/T do what a Mac user expects.
        // Super isn't reported by egui on Linux/Windows; reserved for a future "send Super" toolbar action.
        Self { shift: m.shift, ctrl: m.ctrl || m.mac_cmd, alt: m.alt, sup: false }
    }
}

struct ViewerApp {
    tx: Sender<ViewerMsg>,
    latest: Arc<Mutex<Latest>>,
    texture: Option<egui::TextureHandle>,
    video_size: (u32, u32),
    title_base: String,
    image_rect: egui::Rect,
    last_pos: Option<(u16, u16)>,
    mods: Mods,
    buttons_down: Vec<egui::PointerButton>,
    scroll_acc: egui::Vec2,
    last_title: Instant,
    fps_mark: (Instant, u64),
    fps: f64,
    ended: Option<String>,
}

impl ViewerApp {
    fn send(&self, ev: InputEvent) {
        if self.ended.is_none() {
            let _ = self.tx.send(ViewerMsg::Input(ev));
        }
    }

    fn sync_mods(&mut self, want: Mods) {
        let pairs = [
            (self.mods.shift, want.shift, keymap::SHIFT_L),
            (self.mods.ctrl, want.ctrl, keymap::CONTROL_L),
            (self.mods.alt, want.alt, keymap::ALT_L),
            (self.mods.sup, want.sup, keymap::SUPER_L),
        ];
        for (have, want, keysym) in pairs {
            if have != want {
                self.send(InputEvent::Key { keysym, down: want });
            }
        }
        self.mods = want;
    }

    fn tap(&self, keysym: u32) {
        self.send(InputEvent::Key { keysym, down: true });
        self.send(InputEvent::Key { keysym, down: false });
    }

    fn norm(&self, p: egui::Pos2) -> Option<(u16, u16)> {
        let r = self.image_rect;
        if r.width() <= 0.0 || !r.contains(p) {
            return None;
        }
        let x = ((p.x - r.min.x) / r.width()).clamp(0.0, 1.0);
        let y = ((p.y - r.min.y) / r.height()).clamp(0.0, 1.0);
        Some(((x * NORM_MAX as f32).round() as u16, (y * NORM_MAX as f32).round() as u16))
    }

    fn handle_input(&mut self, ctx: &egui::Context) {
        let (events, frame_mods) = ctx.input(|i| (i.events.clone(), i.modifiers));
        for ev in events {
            match ev {
                egui::Event::PointerMoved(p) => {
                    if let Some(n) = self.norm(p) {
                        if self.last_pos != Some(n) {
                            self.last_pos = Some(n);
                            self.send(InputEvent::MouseMove { x: n.0, y: n.1 });
                        }
                    }
                }
                egui::Event::PointerButton { pos, button, pressed, modifiers } => {
                    let Some(b) = map_button(button) else { continue };
                    if pressed {
                        let Some(n) = self.norm(pos) else { continue };
                        self.sync_mods(modifiers.into());
                        self.send(InputEvent::MouseMove { x: n.0, y: n.1 });
                        self.buttons_down.push(button);
                        self.send(InputEvent::MouseButton { button: b, down: true });
                    } else if let Some(i) = self.buttons_down.iter().position(|x| *x == button) {
                        self.buttons_down.swap_remove(i);
                        self.send(InputEvent::MouseButton { button: b, down: false });
                    }
                }
                egui::Event::MouseWheel { unit, delta, modifiers } => {
                    self.sync_mods(modifiers.into());
                    let scale = match unit {
                        egui::MouseWheelUnit::Line => 1.0,
                        egui::MouseWheelUnit::Point => 1.0 / 50.0,
                        egui::MouseWheelUnit::Page => 10.0,
                    };
                    self.scroll_acc += delta * scale;
                    let dx = self.scroll_acc.x.trunc();
                    let dy = self.scroll_acc.y.trunc();
                    if dx != 0.0 || dy != 0.0 {
                        self.scroll_acc -= egui::vec2(dx, dy);
                        self.send(InputEvent::Scroll { dx: dx as i16, dy: dy as i16 });
                    }
                }
                // Only modifiers are ever *held* on the host. Every other key is a
                // press+release tap on key-down (and on each auto-repeat), and
                // key-ups are ignored: no stuck keys if Ctrl is released first or
                // the link stalls, and no double auto-repeat.
                egui::Event::Key { key, pressed: true, modifiers, .. } => {
                    self.sync_mods(modifiers.into());
                    let shortcut = modifiers.ctrl || modifiers.alt || modifiers.mac_cmd;
                    if let Some(ks) = keymap::special(key) {
                        self.tap(ks);
                    } else if let Some(ks) = keymap::character(key).filter(|_| shortcut) {
                        self.tap(ks);
                    }
                }
                egui::Event::Text(t) => {
                    if !(frame_mods.ctrl || frame_mods.alt || frame_mods.mac_cmd) {
                        for ch in t.chars() {
                            self.send(InputEvent::Text { ch });
                        }
                    }
                }
                // egui turns Ctrl/Cmd+C/X/V into these instead of key events.
                egui::Event::Copy => self.shortcut_tap('c', frame_mods),
                egui::Event::Cut => self.shortcut_tap('x', frame_mods),
                egui::Event::Paste(_) => self.shortcut_tap('v', frame_mods),
                egui::Event::WindowFocused(false) => self.release_everything(),
                _ => {}
            }
        }
        self.sync_mods(frame_mods.into());
    }

    fn shortcut_tap(&mut self, c: char, m: egui::Modifiers) {
        let mut want: Mods = m.into();
        if !want.ctrl && !want.sup {
            want.ctrl = true;
        }
        self.sync_mods(want);
        self.tap(c as u32);
    }

    fn release_everything(&mut self) {
        self.sync_mods(Mods::default());
        for b in std::mem::take(&mut self.buttons_down) {
            if let Some(b) = map_button(b) {
                self.send(InputEvent::MouseButton { button: b, down: false });
            }
        }
    }
}

fn map_button(b: egui::PointerButton) -> Option<MouseButton> {
    Some(match b {
        egui::PointerButton::Primary => MouseButton::Left,
        egui::PointerButton::Secondary => MouseButton::Right,
        egui::PointerButton::Middle => MouseButton::Middle,
        egui::PointerButton::Extra1 => MouseButton::Back,
        egui::PointerButton::Extra2 => MouseButton::Forward,
    })
}

impl eframe::App for ViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Pull the newest decoded frame.
        let (frame, ended, total, rtt) = {
            let mut l = self.latest.lock().unwrap();
            (l.frame.take(), l.ended.clone(), l.stats.frames, l.stats.rtt_ms)
        };
        if let Some(f) = frame {
            self.video_size = (f.width, f.height);
            let img = egui::ColorImage::from_rgba_unmultiplied([f.width as usize, f.height as usize], &f.rgba);
            match &mut self.texture {
                Some(t) => t.set(img, egui::TextureOptions::LINEAR),
                None => self.texture = Some(ctx.load_texture("remote", img, egui::TextureOptions::LINEAR)),
            }
        }
        if ended.is_some() && self.ended.is_none() {
            self.ended = ended;
        }

        if self.ended.is_none() {
            self.handle_input(ctx);
        }

        egui::CentralPanel::default().frame(egui::Frame::NONE.fill(egui::Color32::BLACK)).show(ctx, |ui| {
            let avail = ui.max_rect();
            let (vw, vh) = (self.video_size.0.max(1) as f32, self.video_size.1.max(1) as f32);
            let scale = (avail.width() / vw).min(avail.height() / vh);
            let size = egui::vec2(vw * scale, vh * scale);
            self.image_rect = egui::Rect::from_center_size(avail.center(), size);
            ui.allocate_rect(avail, egui::Sense::click_and_drag());
            if let Some(t) = &self.texture {
                ui.painter().image(
                    t.id(),
                    self.image_rect,
                    egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                    egui::Color32::WHITE,
                );
            } else {
                ui.painter().text(avail.center(), egui::Align2::CENTER_CENTER, "Waiting for video …", egui::FontId::proportional(20.0), egui::Color32::GRAY);
            }
            if let Some(msg) = &self.ended {
                ui.painter().rect_filled(avail, 0.0, egui::Color32::from_black_alpha(160));
                ui.painter().text(avail.center(), egui::Align2::CENTER_CENTER, msg, egui::FontId::proportional(20.0), egui::Color32::WHITE);
            }
        });

        // Title bar doubles as the status line (no focusable widgets to steal keys).
        if self.last_title.elapsed() >= Duration::from_secs(1) {
            let (t, n) = self.fps_mark;
            self.fps = (total - n) as f64 / t.elapsed().as_secs_f64();
            self.fps_mark = (Instant::now(), total);
            self.last_title = Instant::now();
            let rtt = rtt.map(|r| format!("{r:.0} ms")).unwrap_or_else(|| "–".into());
            let state = if self.ended.is_some() { " — disconnected" } else { "" };
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!(
                "{} — {:.0} fps — rtt {rtt}{state}",
                self.title_base, self.fps
            )));
        }
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

impl Drop for ViewerApp {
    fn drop(&mut self) {
        let _ = self.tx.send(ViewerMsg::Bye);
    }
}

fn gui(conn: Connected) -> Result<()> {
    let t0 = Instant::now();
    let (tx, rx) = mpsc::channel();
    let shutdown = conn.writer.shutdown_handle()?;
    let wt = spawn_writer(conn.writer, rx, t0);
    let latest = Arc::new(Mutex::new(Latest { frame: None, stats: Stats::default(), ended: None }));
    let (vw, vh) = conn.video_size;
    let title_base = format!("FreedomDesk — {} [{}]", conn.host_name, conn.host_fingerprint);
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(&title_base)
            .with_inner_size([(vw as f32).min(1600.0), (vh as f32).min(900.0)]),
        ..Default::default()
    };
    let reader = conn.reader;
    let r = eframe::run_native(
        "freedomdesk-viewer",
        opts,
        Box::new(move |cc| {
            cc.egui_ctx.options_mut(|o| o.zoom_with_keyboard = false);
            spawn_reader(reader, latest.clone(), tx.clone(), cc.egui_ctx.clone(), t0);
            Ok(Box::new(ViewerApp {
                tx,
                latest,
                texture: None,
                video_size: (vw, vh),
                title_base,
                image_rect: egui::Rect::NOTHING,
                last_pos: None,
                mods: Mods::default(),
                buttons_down: Vec::new(),
                scroll_acc: egui::Vec2::ZERO,
                last_title: Instant::now(),
                fps_mark: (Instant::now(), 0),
                fps: 0.0,
                ended: None,
            }))
        }),
    );
    // Window closed: ViewerApp dropped → Bye queued → writer exits.
    let _ = wt.join();
    shutdown.shutdown();
    r.map_err(|e| anyhow!("viewer window: {e}"))
}

#[cfg(test)]
mod tests {
    use super::split_host;
    #[test]
    fn host_parsing() {
        assert_eq!(split_host("the21th"), ("the21th".into(), fd_proto::DEFAULT_PORT));
        assert_eq!(split_host("10.0.0.1:99"), ("10.0.0.1".into(), 99));
        assert_eq!(split_host("[fd7a::1]:5"), ("fd7a::1".into(), 5));
        assert_eq!(split_host("fd7a::1"), ("fd7a::1".into(), fd_proto::DEFAULT_PORT));
    }
}
