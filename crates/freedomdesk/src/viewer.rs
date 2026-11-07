//! Viewer: connect, verify the host key, show the screen, forward input.

use crate::{keymap, load_identity};
use anyhow::{anyhow, bail, Context, Result};
use eframe::egui;
use fd_crypto::{normalize_fingerprint, KnownHosts, PinCheck, SecureReader, SecureWriter};
use fd_proto::{HostMsg, InputEvent, MouseButton, Rect, ViewerMsg, DEFAULT_PORT, NORM_MAX, PROTOCOL_VERSION};
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
    /// Headless: also stop after this many seconds (0 = no limit). The host only
    /// sends frames when the screen changes, so a static desktop yields few frames.
    #[arg(long, default_value_t = 0.0)]
    seconds: f64,
    /// Name shown to the host user in the consent prompt.
    #[arg(long)]
    name: Option<String>,
    /// Trust and pin an unknown host key without asking (non-interactive use).
    #[arg(long)]
    trust_new: bool,
    /// Headless latency probe: move the HOST's pointer N times and measure
    /// input→pointer-echo and input→next-video-frame latency. Moves the real pointer!
    #[arg(long, default_value_t = 0)]
    probe_input: u32,
}

pub struct Connected {
    reader: SecureReader,
    writer: SecureWriter,
    pub host_name: String,
    pub host_fingerprint: String,
    video_size: (u32, u32),
    screen_size: (u32, u32),
}

impl Connected {
    pub fn video_size(&self) -> (u32, u32) {
        self.video_size
    }
}

/// What to connect to. Shared by the CLI and the GUI launcher.
pub struct ConnectOpts {
    pub host: String,
    pub expect_fingerprint: Option<String>,
    pub name: Option<String>,
}

/// First connection to a host whose key we have never seen.
pub struct TrustPrompt {
    pub label: String,
    pub fingerprint: String,
}

/// How `connect` talks to the user: terminal or GUI.
pub trait ConnectUi {
    fn status(&mut self, msg: &str);
    /// Unknown host key and no expected fingerprint: may we pin it?
    fn trust(&mut self, prompt: &TrustPrompt) -> bool;
    /// Called once the socket exists, so a GUI can abort a pending connect.
    fn cancel_handle(&mut self, _h: fd_crypto::ShutdownHandle) {}
}

struct TermUi {
    trust_new: bool,
}

impl ConnectUi for TermUi {
    fn status(&mut self, msg: &str) {
        eprintln!("{msg}");
    }
    fn trust(&mut self, p: &TrustPrompt) -> bool {
        if self.trust_new {
            return true;
        }
        eprintln!("First connection to {}. Host fingerprint:\n\n    {}\n", p.label, p.fingerprint);
        eprintln!("Compare it with `freedomdesk id` on the host (read it out over the phone).");
        confirm("Trust this host and remember its key? [y/N] ").unwrap_or(false)
    }
}

pub fn run(dir: &Path, args: ViewArgs) -> Result<()> {
    let opts = ConnectOpts { host: args.host.clone(), expect_fingerprint: args.expect_fingerprint.clone(), name: args.name.clone() };
    let conn = connect(dir, &opts, &mut TermUi { trust_new: args.trust_new })?;
    if args.headless {
        headless(conn, args.frames, args.seconds, args.probe_input)
    } else {
        crate::launcher::run_gui(dir, Some(conn))
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

pub fn connect(dir: &Path, args: &ConnectOpts, ui: &mut dyn ConnectUi) -> Result<Connected> {
    let identity = load_identity(dir)?;
    let (host, port) = split_host(args.host.trim());
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}"))?
        .next()
        .ok_or_else(|| anyhow!("{host} did not resolve"))?;
    ui.status(&format!("Connecting to {addr} …"));
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).with_context(|| format!("connecting to {addr}"))?;
    if let Ok(s) = stream.try_clone() {
        ui.cancel_handle(fd_crypto::ShutdownHandle::from(s));
    }
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
                ui.status(&format!("Host key already pinned as: {} (same machine, new name).", aliases.join(", ")));
            }
            if args.expect_fingerprint.is_none()
                && aliases.is_empty()
                && !ui.trust(&TrustPrompt { label: label.clone(), fingerprint: host_fp.clone() })
            {
                bail!("host not trusted; nothing was sent to it");
            }
            kh.pin(&label, &session.remote_public)?;
            ui.status(&format!("Pinned {label} = {host_fp}"));
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
    ui.status("Secure channel up. Waiting for the host to allow the session …");

    session.reader.set_timeout(Some(Duration::from_secs(330)))?;
    let reply: HostMsg = fd_proto::decode(&session.reader.recv().context("waiting for host")?)?;
    session.reader.set_timeout(None)?;
    match reply {
        HostMsg::Welcome { protocol, host_name, screen_width, screen_height, video_width, video_height } => {
            let host_name = clean(&host_name);
            if protocol != PROTOCOL_VERSION {
                bail!("host speaks protocol {protocol}, we speak {PROTOCOL_VERSION}");
            }
            ui.status(&format!("Allowed. {host_name}: screen {screen_width}x{screen_height}, video {video_width}x{video_height}"));
            Ok(Connected {
                reader: session.reader,
                writer: session.writer,
                host_name,
                host_fingerprint: host_fp,
                video_size: (video_width, video_height),
                screen_size: (screen_width, screen_height),
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

/// Input-latency probe state for headless mode.
struct Probe {
    left: u32,
    i: u32,
    screen: (u32, u32),
    /// Expected host pointer position, when the move was sent, echo/video seen.
    cur: Option<((i32, i32), Instant, bool, bool)>,
    echo_ms: Vec<f64>,
    video_ms: Vec<f64>,
}

impl Probe {
    fn next(&mut self, tx: &Sender<ViewerMsg>) {
        if self.left == 0 {
            self.cur = None;
            return;
        }
        self.left -= 1;
        self.i += 1;
        let f = if self.i.is_multiple_of(2) { 0.3 } else { 0.7 } + (self.i % 7) as f32 * 0.01;
        let n = (f * NORM_MAX as f32) as u16;
        let px = |full: u32| (n as u64 * (full.max(1) - 1) as u64 / NORM_MAX as u64) as i32;
        self.cur = Some(((px(self.screen.0), px(self.screen.1)), Instant::now(), false, false));
        let _ = tx.send(ViewerMsg::Input(InputEvent::MouseMove { x: n, y: n }));
    }

    fn on_event(&mut self, cursor: Option<(i32, i32)>, video: bool, tx: &Sender<ViewerMsg>) {
        let Some((target, t, echoed, seen)) = self.cur.as_mut() else { return };
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        if let Some((x, y)) = cursor {
            if !*echoed && (x - target.0).abs() <= 3 && (y - target.1).abs() <= 3 {
                *echoed = true;
                self.echo_ms.push(ms);
            }
        }
        if video && !*seen {
            *seen = true;
            self.video_ms.push(ms);
        }
        // Next move once both arrived, or after 1 s for whichever never comes.
        if (*echoed && *seen) || ms > 1000.0 {
            self.next(tx);
        }
    }

    fn done(&self) -> bool {
        self.left == 0 && self.cur.is_none()
    }

    fn report(&self) -> String {
        fn stats(v: &[f64]) -> String {
            if v.is_empty() {
                return "n/a".into();
            }
            let mut v = v.to_vec();
            v.sort_by(|a, b| a.total_cmp(b));
            format!("median {:.1} ms, p90 {:.1} ms (n={})", v[v.len() / 2], v[(v.len() * 9 / 10).min(v.len() - 1)], v.len())
        }
        format!("input→pointer echo: {}; input→next video frame: {}", stats(&self.echo_ms), stats(&self.video_ms))
    }
}

fn headless(conn: Connected, want: u64, seconds: f64, probe_moves: u32) -> Result<()> {
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
    let mut probe = (probe_moves > 0).then(|| Probe {
        left: probe_moves,
        i: 0,
        screen: conn.screen_size,
        cur: None,
        echo_ms: Vec::new(),
        video_ms: Vec::new(),
    });
    let mut probe_started = false;
    loop {
        let time_up = seconds > 0.0 && start.elapsed().as_secs_f64() >= seconds;
        match &probe {
            Some(p) if probe_started && p.done() => break,
            Some(_) if time_up => break,
            Some(_) => {}
            None if st.frames >= want || time_up => break,
            None => {}
        }
        let msg: HostMsg = fd_proto::decode(&reader.recv()?)?;
        match msg {
            HostMsg::Video { data, keyframe, .. } => {
                st.bytes += data.len() as u64;
                if let Some(f) = dec.decode(&data, keyframe, &tx) {
                    dims = (f.width, f.height);
                    st.frames += 1;
                    first_frame.get_or_insert_with(|| start.elapsed());
                    if let Some(p) = probe.as_mut() {
                        if !probe_started {
                            probe_started = true;
                            p.next(&tx);
                        } else {
                            p.on_event(None, true, &tx);
                        }
                    }
                }
            }
            HostMsg::CursorPos { x, y, .. } => {
                if let Some(p) = probe.as_mut().filter(|_| probe_started) {
                    p.on_event(Some((x, y)), false, &tx);
                }
            }
            HostMsg::Pong { ts_us } => {
                st.rtt_ms = Some((now_us(t0).saturating_sub(ts_us)) as f64 / 1000.0);
                if let Some(p) = probe.as_mut().filter(|_| probe_started) {
                    p.on_event(None, false, &tx); // lets the 1 s fallback fire
                }
            }
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
    if let Some(p) = &probe {
        println!("PROBE {}", p.report());
    }
    let _ = tx.send(ViewerMsg::Bye);
    drop(tx);
    let _ = wt.join();
    shutdown.shutdown();
    Ok(())
}

// ---------------------------------------------------------------- GUI

struct CursorImg {
    width: u32,
    height: u32,
    xhot: u32,
    yhot: u32,
    rgba: Vec<u8>,
}

#[derive(Default)]
struct Latest {
    /// Newest decoded picture, the screen region it shows, and the screen size.
    frame: Option<(fd_codec::DecodedFrame, Rect, (u32, u32))>,
    cursor_shape: Option<CursorImg>,
    cursor_pos: Option<(i32, i32, bool)>,
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
                    HostMsg::Video { data, keyframe, region, screen_width, screen_height, .. } => {
                        let n = data.len() as u64;
                        let fits = |o: u32, l: u32, full: u32| o.checked_add(l).is_some_and(|e| e <= full) && l > 0;
                        if screen_width == 0
                            || screen_height == 0
                            || screen_width > 16384
                            || screen_height > 16384
                            || !fits(region.x, region.w, screen_width)
                            || !fits(region.y, region.h, screen_height)
                        {
                            log::warn!("ignoring video with invalid region {region:?} of {screen_width}x{screen_height}");
                            continue;
                        }
                        if let Some(f) = dec.decode(&data, keyframe, &tx) {
                            let mut l = latest.lock().unwrap();
                            l.frame = Some((f, region, (screen_width, screen_height)));
                            l.stats.frames += 1;
                            l.stats.bytes += n;
                            drop(l);
                            ctx.request_repaint();
                        }
                    }
                    HostMsg::CursorShape { width, height, xhot, yhot, rgba, .. } => {
                        if width > 0 && height > 0 && width <= 256 && height <= 256 && rgba.len() == (width * height * 4) as usize {
                            latest.lock().unwrap().cursor_shape = Some(CursorImg { width, height, xhot, yhot, rgba });
                            ctx.request_repaint();
                        }
                    }
                    HostMsg::CursorPos { x, y, visible } => {
                        latest.lock().unwrap().cursor_pos = Some((x, y, visible));
                        ctx.request_repaint();
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

/// Viewer-only shortcuts are Ctrl+Alt (Control+Option on a Mac) + key/scroll; never forwarded.
/// Windows reports AltGr as Ctrl+Alt, so there the chord is Ctrl+Alt+Shift (AltGr typing must work).
fn is_view_hotkey(m: egui::Modifiers) -> bool {
    m.ctrl && m.alt && !m.mac_cmd && (!cfg!(windows) || m.shift)
}

/// Maps between the window (egui points) and the remote screen (pixels).
#[derive(Clone, Copy)]
struct ViewXf {
    rect: egui::Rect,
    /// Points per remote pixel.
    scale: f32,
    /// Remote pixel shown at the centre of `rect`.
    center: egui::Pos2,
}

impl ViewXf {
    fn to_view(self, p: egui::Pos2) -> egui::Pos2 {
        self.rect.center() + (p - self.center) * self.scale
    }
    fn to_screen(self, p: egui::Pos2) -> egui::Pos2 {
        self.center + (p - self.rect.center()) / self.scale
    }
}

const EDGE_PAN_ZONE: f32 = 28.0;
const EDGE_PAN_SPEED: f32 = 1200.0; // points per second at the very edge
const VIEW_SEND_INTERVAL: Duration = Duration::from_millis(150);

pub struct ViewerApp {
    tx: Sender<ViewerMsg>,
    latest: Arc<Mutex<Latest>>,
    texture: Option<egui::TextureHandle>,
    tex_region: Rect,
    screen: (u32, u32),
    cursor_tex: Option<(egui::TextureHandle, egui::Vec2, egui::Vec2)>, // texture, size px, hotspot px
    remote_cursor: Option<(i32, i32, bool)>,
    /// 1.0 = whole screen fits the window.
    zoom: f32,
    center: egui::Pos2,
    xf: ViewXf,
    toolbar_rect: egui::Rect,
    last_view_sent: Option<(u16, u16, u16, u16, u32, u32)>,
    last_view_time: Instant,
    pending_move: Option<(u16, u16)>,
    last_pos: Option<(u16, u16)>,
    mods: Mods,
    buttons_down: Vec<egui::PointerButton>,
    scroll_acc: egui::Vec2,
    zoom_acc: f32,
    title_base: String,
    last_title: Instant,
    fps_mark: (Instant, u64),
    fps: f64,
    ended: Option<String>,
    /// Writer thread; handed to `CLOSERS` on drop so the Bye still goes out.
    writer: Option<std::thread::JoinHandle<()>>,
    /// User asked to leave the session (toolbar / "Back" button).
    leave: bool,
}

/// Writer threads of closed sessions; joined before the process exits so the
/// host gets a clean Bye.
static CLOSERS: Mutex<Vec<std::thread::JoinHandle<()>>> = Mutex::new(Vec::new());

pub fn join_closers() {
    let hs: Vec<_> = std::mem::take(&mut *CLOSERS.lock().unwrap());
    for h in hs {
        let _ = h.join();
    }
}

impl ViewerApp {
    fn send(&self, ev: InputEvent) {
        if self.ended.is_none() {
            let _ = self.tx.send(ViewerMsg::Input(ev));
        }
    }

    fn flush_move(&mut self) {
        if let Some(n) = self.pending_move.take() {
            if self.last_pos != Some(n) {
                self.last_pos = Some(n);
                self.send(InputEvent::MouseMove { x: n.0, y: n.1 });
            }
        }
    }

    fn sync_mods(&mut self, want: Mods) {
        self.flush_move();
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

    fn screen_size(&self) -> egui::Vec2 {
        egui::vec2(self.screen.0.max(1) as f32, self.screen.1.max(1) as f32)
    }

    /// Recompute the transform for the window rect, clamping zoom and pan.
    fn layout(&mut self, rect: egui::Rect) {
        let s = self.screen_size();
        let fit = (rect.width() / s.x).min(rect.height() / s.y).max(1e-4);
        self.zoom = self.zoom.clamp(1.0, self.max_zoom(fit));
        let scale = fit * self.zoom;
        let half = rect.size() / (2.0 * scale);
        let clamp_axis = |c: f32, h: f32, full: f32| if 2.0 * h >= full { full / 2.0 } else { c.clamp(h, full - h) };
        self.center = egui::pos2(clamp_axis(self.center.x, half.x, s.x), clamp_axis(self.center.y, half.y, s.y));
        self.xf = ViewXf { rect, scale, center: self.center };
    }

    fn max_zoom(&self, fit: f32) -> f32 {
        // Up to 8 physical pixels per remote pixel.
        (8.0 / fit).max(1.0)
    }

    fn zoom_at(&mut self, factor: f32, anchor: egui::Pos2) {
        let before = self.xf.to_screen(anchor);
        self.zoom *= factor;
        self.layout(self.xf.rect);
        // Keep the remote point under the anchor where it was.
        self.center = before - (anchor - self.xf.rect.center()) / self.xf.scale;
        self.layout(self.xf.rect);
    }

    fn zoom_fit(&mut self) {
        self.zoom = 1.0;
        self.layout(self.xf.rect);
    }

    /// One remote pixel per physical display pixel.
    fn zoom_100(&mut self, ppp: f32) {
        let s = self.screen_size();
        let r = self.xf.rect;
        let fit = (r.width() / s.x).min(r.height() / s.y).max(1e-4);
        let anchor = r.center();
        let target = (1.0 / ppp) / fit;
        self.zoom_at(target / self.zoom, anchor);
    }

    /// Normalised remote position under a window point, if it is on the remote screen.
    fn norm(&self, p: egui::Pos2) -> Option<(u16, u16)> {
        if !self.xf.rect.contains(p) || self.toolbar_rect.contains(p) {
            return None;
        }
        let sp = self.xf.to_screen(p);
        let s = self.screen_size();
        if sp.x < 0.0 || sp.y < 0.0 || sp.x >= s.x || sp.y >= s.y {
            return None;
        }
        let n = |v: f32, full: f32| ((v / (full - 1.0).max(1.0)).clamp(0.0, 1.0) * NORM_MAX as f32).round() as u16;
        Some((n(sp.x, s.x), n(sp.y, s.y)))
    }

    /// Tell the host which part of the screen we show and at how many physical pixels.
    fn update_view_request(&mut self, ppp: f32) {
        let s = self.screen_size();
        let a = self.xf.to_screen(self.xf.rect.min);
        let b = self.xf.to_screen(self.xf.rect.max);
        let x0 = a.x.clamp(0.0, s.x);
        let y0 = a.y.clamp(0.0, s.y);
        let x1 = b.x.clamp(0.0, s.x);
        let y1 = b.y.clamp(0.0, s.y);
        let n = |v: f32, full: f32| ((v / full).clamp(0.0, 1.0) * NORM_MAX as f32).round() as u16;
        let phys = |px: f32| (((px * self.xf.scale * ppp) / 16.0).round() as u32 * 16).clamp(64, 3840);
        let want = (n(x0, s.x), n(y0, s.y), n(x1 - x0, s.x), n(y1 - y0, s.y), phys(x1 - x0), phys(y1 - y0).min(2160));
        if self.last_view_sent != Some(want) && self.last_view_time.elapsed() >= VIEW_SEND_INTERVAL && self.ended.is_none() {
            self.last_view_sent = Some(want);
            self.last_view_time = Instant::now();
            let _ = self.tx.send(ViewerMsg::SetView {
                x: want.0,
                y: want.1,
                w: want.2,
                h: want.3,
                max_width: want.4,
                max_height: want.5,
            });
        }
    }

    fn handle_input(&mut self, ctx: &egui::Context) {
        let (events, frame_mods, ppp) = ctx.input(|i| (i.events.clone(), i.modifiers, i.pixels_per_point));
        for ev in events {
            match ev {
                egui::Event::PointerMoved(p) => {
                    // Coalesced: only the latest position this frame is sent.
                    if let Some(n) = self.norm(p) {
                        self.pending_move = Some(n);
                    }
                }
                egui::Event::PointerButton { pos, button, pressed, modifiers } => {
                    let Some(b) = map_button(button) else { continue };
                    if pressed {
                        let Some(n) = self.norm(pos) else { continue };
                        self.sync_mods(modifiers.into());
                        self.pending_move = Some(n);
                        self.flush_move();
                        self.buttons_down.push(button);
                        self.send(InputEvent::MouseButton { button: b, down: true });
                    } else if let Some(i) = self.buttons_down.iter().position(|x| *x == button) {
                        self.flush_move();
                        self.buttons_down.swap_remove(i);
                        self.send(InputEvent::MouseButton { button: b, down: false });
                    }
                }
                egui::Event::MouseWheel { unit, delta, modifiers } => {
                    let scale = match unit {
                        egui::MouseWheelUnit::Line => 1.0,
                        egui::MouseWheelUnit::Point => 1.0 / 50.0,
                        egui::MouseWheelUnit::Page => 10.0,
                    };
                    let pointer = ctx.input(|i| i.pointer.latest_pos()).unwrap_or(self.xf.rect.center());
                    log::trace!("wheel {delta:?} {unit:?} mods={modifiers:?}");
                    if is_view_hotkey(modifiers) {
                        self.zoom_acc += delta.y * scale;
                        let notches = self.zoom_acc.trunc();
                        if notches != 0.0 {
                            self.zoom_acc -= notches;
                            self.zoom_at(1.15f32.powf(notches), pointer);
                        }
                        continue;
                    }
                    if self.norm(pointer).is_none() {
                        continue;
                    }
                    self.sync_mods(modifiers.into());
                    self.scroll_acc += delta * scale;
                    let dx = self.scroll_acc.x.trunc();
                    let dy = self.scroll_acc.y.trunc();
                    if dx != 0.0 || dy != 0.0 {
                        self.scroll_acc -= egui::vec2(dx, dy);
                        self.send(InputEvent::Scroll { dx: dx as i16, dy: dy as i16 });
                    }
                }
                // Trackpad pinch: always a viewer zoom.
                egui::Event::Zoom(f) => {
                    let pointer = ctx.input(|i| i.pointer.latest_pos()).unwrap_or(self.xf.rect.center());
                    self.zoom_at(f, pointer);
                }
                // Only modifiers are ever *held* on the host. Every other key is a
                // press+release tap on key-down (and on each auto-repeat), and
                // key-ups are ignored: no stuck keys if Ctrl is released first or
                // the link stalls, and no double auto-repeat.
                egui::Event::Key { key, pressed: true, modifiers, .. } => {
                    if is_view_hotkey(modifiers) && self.view_hotkey(key, ppp) {
                        continue;
                    }
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
                        self.flush_move();
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
        self.flush_move();
    }

    /// Ctrl+Alt + 0 / 1 / = / - / arrows. Returns true if consumed.
    fn view_hotkey(&mut self, key: egui::Key, ppp: f32) -> bool {
        use egui::Key::*;
        let c = self.xf.rect.center();
        let step = self.xf.rect.size() / (4.0 * self.xf.scale);
        match key {
            Num0 => self.zoom_fit(),
            Num1 => self.zoom_100(ppp),
            Plus | Equals => self.zoom_at(1.25, c),
            Minus => self.zoom_at(0.8, c),
            // Arrows pan only while zoomed; otherwise Ctrl+Alt+arrows go to the host (workspaces).
            ArrowLeft if self.zoom > 1.0001 => self.center.x -= step.x,
            ArrowRight if self.zoom > 1.0001 => self.center.x += step.x,
            ArrowUp if self.zoom > 1.0001 => self.center.y -= step.y,
            ArrowDown if self.zoom > 1.0001 => self.center.y += step.y,
            _ => return false,
        }
        self.layout(self.xf.rect);
        true
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

    /// While zoomed in, holding the pointer near a window edge scrolls the view.
    fn edge_pan(&mut self, ctx: &egui::Context) -> bool {
        if self.zoom <= 1.0001 {
            return false;
        }
        let Some(p) = ctx.input(|i| i.pointer.latest_pos()) else { return false };
        let r = self.xf.rect;
        if !r.contains(p) || self.toolbar_rect.contains(p) {
            return false;
        }
        let depth = |d: f32| ((EDGE_PAN_ZONE - d) / EDGE_PAN_ZONE).clamp(0.0, 1.0);
        let mut dir = egui::vec2(depth(r.right() - p.x) - depth(p.x - r.left()), depth(r.bottom() - p.y) - depth(p.y - r.top()));
        // Reaching for the toolbar must not scroll the view up.
        if dir.y < 0.0 && self.toolbar_rect.is_positive() && self.toolbar_rect.x_range().contains(p.x) {
            dir.y = 0.0;
        }
        if dir == egui::Vec2::ZERO {
            return false;
        }
        let dt = ctx.input(|i| i.stable_dt).min(0.1);
        let before = self.center;
        self.center += dir * EDGE_PAN_SPEED * dt / self.xf.scale;
        self.layout(r);
        self.center != before
    }

    fn sync_textures(&mut self, ctx: &egui::Context) -> (u64, Option<f64>) {
        let (frame, shape, cursor, ended, total, rtt) = {
            let mut l = self.latest.lock().unwrap();
            (l.frame.take(), l.cursor_shape.take(), l.cursor_pos.take(), l.ended.clone(), l.stats.frames, l.stats.rtt_ms)
        };
        if let Some((f, region, screen)) = frame {
            self.tex_region = region;
            if screen != self.screen {
                self.screen = screen;
            }
            let img = egui::ColorImage::from_rgba_unmultiplied([f.width as usize, f.height as usize], &f.rgba);
            match &mut self.texture {
                Some(t) => t.set(img, egui::TextureOptions::LINEAR),
                None => self.texture = Some(ctx.load_texture("remote", img, egui::TextureOptions::LINEAR)),
            }
        }
        if let Some(c) = shape {
            let img = egui::ColorImage::from_rgba_unmultiplied([c.width as usize, c.height as usize], &c.rgba);
            let tex = ctx.load_texture("cursor", img, egui::TextureOptions::LINEAR);
            self.cursor_tex = Some((tex, egui::vec2(c.width as f32, c.height as f32), egui::vec2(c.xhot as f32, c.yhot as f32)));
        }
        if cursor.is_some() {
            self.remote_cursor = cursor;
        }
        if ended.is_some() && self.ended.is_none() {
            self.ended = ended;
        }
        (total, rtt)
    }

    fn paint(&mut self, ui: &mut egui::Ui) {
        let painter = ui.painter_at(self.xf.rect);
        if let Some(t) = &self.texture {
            let r = self.tex_region;
            let a = self.xf.to_view(egui::pos2(r.x as f32, r.y as f32));
            let b = self.xf.to_view(egui::pos2(r.x as f32 + r.w as f32, r.y as f32 + r.h as f32));
            painter.image(t.id(), egui::Rect::from_min_max(a, b), egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)), egui::Color32::WHITE);
        } else {
            painter.text(self.xf.rect.center(), egui::Align2::CENTER_CENTER, "Waiting for video …", egui::FontId::proportional(20.0), egui::Color32::GRAY);
        }

        // Cursor: drawn locally at the local pointer while it is over the remote
        // screen (zero-latency feel), otherwise at the host's reported position.
        let local = ui.ctx().input(|i| i.pointer.latest_pos()).filter(|p| self.norm(*p).is_some());
        let remote_visible = self.remote_cursor.is_none_or(|c| c.2);
        if let Some((tex, size, hot)) = &self.cursor_tex {
            let cs = self.xf.scale.clamp(0.3, 1.0);
            let at = match (local, self.remote_cursor) {
                (Some(p), _) => Some(p),
                (None, Some((x, y, true))) => Some(self.xf.to_view(egui::pos2(x as f32, y as f32))),
                _ => None,
            };
            if let Some(p) = at.filter(|_| remote_visible) {
                let min = p - *hot * cs;
                painter.image(tex.id(), egui::Rect::from_min_size(min, *size * cs), egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)), egui::Color32::WHITE);
            }
            if local.is_some() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::None);
            }
        }

        if self.ended.is_some() {
            painter.rect_filled(self.xf.rect, 0.0, egui::Color32::from_black_alpha(160));
        }
    }

    /// Small zoom bar that appears when the pointer is near the top edge.
    fn toolbar(&mut self, ctx: &egui::Context, ppp: f32) {
        let near_top = ctx
            .input(|i| i.pointer.latest_pos())
            .is_some_and(|p| p.y - self.xf.rect.top() < 48.0 || self.toolbar_rect.contains(p));
        if !near_top {
            self.toolbar_rect = egui::Rect::NOTHING;
            return;
        }
        let resp = egui::Area::new(egui::Id::new("fd-toolbar"))
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 6.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::popup(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let clicked = |r: egui::Response| {
                            let c = r.clicked();
                            r.surrender_focus(); // never keep keyboard focus: keys go to the host
                            c
                        };
                        if clicked(ui.button("Fit")) {
                            self.zoom_fit();
                        }
                        if clicked(ui.button("1:1")) {
                            self.zoom_100(ppp);
                        }
                        if clicked(ui.button("−")) {
                            let c = self.xf.rect.center();
                            self.zoom_at(0.8, c);
                        }
                        if clicked(ui.button("+")) {
                            let c = self.xf.rect.center();
                            self.zoom_at(1.25, c);
                        }
                        if clicked(ui.button("Disconnect")) {
                            self.leave = true;
                        }
                        let real = self.xf.scale * ppp * 100.0;
                        ui.label(format!("{real:.0}%"));
                        ui.weak("Ctrl+Alt+scroll / pinch · Ctrl+Alt+0 fit · Ctrl+Alt+1 1:1");
                    });
                });
            });
        self.toolbar_rect = resp.response.rect.expand(4.0);
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

impl ViewerApp {
    /// Start the session threads for an established connection.
    pub fn start(conn: Connected, ctx: &egui::Context) -> Result<ViewerApp> {
        let t0 = Instant::now();
        let (tx, rx) = mpsc::channel();
        let wt = spawn_writer(conn.writer, rx, t0);
        let latest = Arc::new(Mutex::new(Latest::default()));
        spawn_reader(conn.reader, latest.clone(), tx.clone(), ctx.clone(), t0);
        let (vw, vh) = conn.video_size;
        let screen = conn.screen_size;
        let full = Rect { x: 0, y: 0, w: screen.0, h: screen.1 };
        let rect = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(vw as f32, vh as f32));
        Ok(ViewerApp {
            tx,
            latest,
            texture: None,
            tex_region: full,
            screen,
            cursor_tex: None,
            remote_cursor: None,
            zoom: 1.0,
            center: egui::pos2(screen.0 as f32 / 2.0, screen.1 as f32 / 2.0),
            xf: ViewXf { rect, scale: 1.0, center: egui::Pos2::ZERO },
            toolbar_rect: egui::Rect::NOTHING,
            last_view_sent: None,
            last_view_time: Instant::now() - VIEW_SEND_INTERVAL,
            pending_move: None,
            last_pos: None,
            mods: Mods::default(),
            buttons_down: Vec::new(),
            scroll_acc: egui::Vec2::ZERO,
            zoom_acc: 0.0,
            title_base: format!("FreedomDesk — {} [{}]", conn.host_name, conn.host_fingerprint),
            last_title: Instant::now() - Duration::from_secs(2),
            fps_mark: (Instant::now(), 0),
            fps: 0.0,
            ended: None,
            writer: Some(wt),
            leave: false,
        })
    }

    /// Draw one frame. Returns true when the user wants to leave the session.
    pub fn show(&mut self, ctx: &egui::Context) -> bool {
        let ppp = ctx.pixels_per_point();
        let (total, rtt) = self.sync_textures(ctx);
        let rect = ctx.available_rect();
        self.layout(rect);
        let view_before = (self.xf.scale, self.xf.center);
        if self.ended.is_none() {
            self.handle_input(ctx);
        }
        let panning = self.edge_pan(ctx);
        // If zoom/pan moved the picture under a still mouse, move the host pointer too.
        if (self.xf.scale, self.xf.center) != view_before && self.ended.is_none() {
            if let Some(n) = ctx.input(|i| i.pointer.latest_pos()).and_then(|p| self.norm(p)) {
                self.pending_move = Some(n);
                self.flush_move();
            }
        }
        self.update_view_request(ppp);

        egui::CentralPanel::default().frame(egui::Frame::NONE.fill(egui::Color32::BLACK)).show(ctx, |ui| {
            ui.allocate_rect(ui.max_rect(), egui::Sense::click_and_drag());
            self.paint(ui);
        });
        if self.ended.is_none() {
            self.toolbar(ctx, ppp);
        } else {
            self.ended_panel(ctx);
        }

        // Title bar doubles as the status line.
        if self.last_title.elapsed() >= Duration::from_secs(1) {
            let (t, n) = self.fps_mark;
            self.fps = (total - n) as f64 / t.elapsed().as_secs_f64();
            self.fps_mark = (Instant::now(), total);
            self.last_title = Instant::now();
            let rtt = rtt.map(|r| format!("{r:.0} ms")).unwrap_or_else(|| "–".into());
            let state = if self.ended.is_some() { " — disconnected" } else { "" };
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!(
                "{} — {:.0}% — {:.0} fps — rtt {rtt}{state}",
                self.title_base,
                self.xf.scale * ppp * 100.0,
                self.fps
            )));
        }
        if panning {
            ctx.request_repaint();
        } else {
            ctx.request_repaint_after(if self.last_view_sent.is_some() { Duration::from_millis(200) } else { Duration::from_millis(50) });
        }
        self.leave
    }

    /// After the session ended: explain why and offer a way back.
    fn ended_panel(&mut self, ctx: &egui::Context) {
        let msg = self.ended.clone().unwrap_or_default();
        egui::Area::new(egui::Id::new("fd-ended"))
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::popup(ui.style()).inner_margin(16.0).show(ui, |ui| {
                    ui.set_max_width(480.0);
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new(msg).size(16.0));
                        ui.add_space(8.0);
                        if ui.button("Back to machines").clicked() {
                            self.leave = true;
                        }
                    });
                });
            });
    }
}

impl Drop for ViewerApp {
    fn drop(&mut self) {
        let _ = self.tx.send(ViewerMsg::Bye);
        if let Some(h) = self.writer.take() {
            CLOSERS.lock().unwrap().push(h);
        }
    }
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
