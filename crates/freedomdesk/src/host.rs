//! Host agent: accept a viewer, ask consent, stream the screen, inject input.

use crate::{consent, load_identity, netpolicy};
use anyhow::{anyhow, bail, Context, Result};
use fd_crypto::{normalize_fingerprint, SecureWriter, Session};
use crate::clipboard;
use fd_proto::{HostMsg, Rect, ViewerMsg, DEFAULT_PORT, NORM_MAX, PROTOCOL_VERSION};
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(clap::Args, Clone)]
pub struct HostArgs {
    /// IP or IP:port to listen on. Default: this machine's Tailscale IPv4.
    #[arg(long)]
    bind: Option<String>,
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
    /// Allow listening on 0.0.0.0 / public addresses (NOT recommended).
    #[arg(long)]
    allow_public_bind: bool,
    /// Viewer fingerprint allowed WITHOUT a consent prompt (unattended). Repeatable.
    #[arg(long = "unattended-viewer", value_name = "FINGERPRINT")]
    unattended: Vec<String>,
    /// Seconds to wait for the local user to Allow before denying.
    #[arg(long, default_value_t = 30)]
    consent_timeout: u64,
    /// Stream the screen but ignore all remote input.
    #[arg(long)]
    view_only: bool,
    /// Allow text clipboard sync with a viewer that also asks for it (off by
    /// default). A view-only session never lets the viewer write this clipboard.
    #[arg(long)]
    clipboard: bool,
    #[arg(long, default_value_t = 30.0)]
    fps: f32,
    #[arg(long, default_value_t = 1920)]
    max_width: u32,
    #[arg(long, default_value_t = 1080)]
    max_height: u32,
    /// Target video bitrate in kbit/s.
    #[arg(long, default_value_t = 6000)]
    bitrate_kbps: u32,
    /// Draw the pointer into the video instead of sending it separately
    /// (legacy behaviour; for latency comparisons).
    #[arg(long, hide = true)]
    cursor_in_video: bool,
    /// Exit after the first session ends (useful for tests).
    #[arg(long)]
    once: bool,
    /// (internal, used by `freedomdesk service`) Read the identity key from stdin
    /// instead of <config>/identity.key.
    #[arg(long, hide = true)]
    identity_stdin: bool,
    /// Audit log file; `-` = log to stderr (journald under the service).
    /// Default: <config>/audit.log
    #[arg(long, value_name = "PATH")]
    audit_log: Option<PathBuf>,
}

struct Shared {
    args: HostArgs,
    identity: fd_crypto::Identity,
    host_name: String,
    audit_path: PathBuf,
    config_dir: PathBuf,
    busy: AtomicBool,
    /// Set by SIGINT/SIGTERM: every session winds down (releasing held keys).
    shutting_down: AtomicBool,
    /// Socket of the active session, so a signal can unblock its threads.
    active_socket: Mutex<Option<fd_crypto::ShutdownHandle>>,
    /// Connections that have not yet been authorised (handshake / Hello / consent).
    pre_auth: AtomicUsize,
    /// After a denied/timed-out prompt, no new prompts for this IP until the instant.
    prompt_cooldown: Mutex<HashMap<IpAddr, Instant>>,
}

/// Unauthorised connections allowed at once; extra ones are dropped immediately.
const MAX_PRE_AUTH: usize = 8;
/// Hello must arrive this fast and be this small.
const HELLO_DEADLINE: Duration = Duration::from_secs(10);
const HELLO_MAX: usize = 4096;
/// How long an IP must wait for another consent prompt after a Deny/timeout.
const PROMPT_COOLDOWN: Duration = Duration::from_secs(60);

pub fn run(dir: &Path, args: HostArgs) -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("hosting is Linux-only for now (macOS/Windows hosts are milestone M7); this build can view other machines");
    }
    let identity = if args.identity_stdin {
        use std::io::Read;
        let mut text = zeroize::Zeroizing::new(String::new());
        std::io::stdin().take(4096).read_to_string(&mut text).context("reading identity from stdin")?;
        fd_crypto::Identity::from_text(&text)?
    } else {
        load_identity(dir)?
    };
    let addr = netpolicy::resolve_bind(args.bind.as_deref(), args.port, args.allow_public_bind)?;
    let listener = TcpListener::bind(addr).with_context(|| format!("listening on {addr}"))?;
    let host_name = hostname();
    println!("FreedomDesk host “{host_name}” listening on {addr}");
    println!("Host fingerprint: {}", identity.fingerprint());
    println!("Viewer command:   freedomdesk view {addr}");
    if !args.unattended.is_empty() {
        println!("Unattended viewers (no consent prompt): {}", args.unattended.join(", "));
    }
    let listed = crate::authorized::load(dir);
    if !listed.is_empty() {
        println!("Authorised viewers file: {} entr{} (re-read on each connection)", listed.len(), if listed.len() == 1 { "y" } else { "ies" });
    }
    let once = args.once;
    let audit_path = args.audit_log.clone().unwrap_or_else(|| dir.join("audit.log"));
    let shared = Arc::new(Shared {
        args,
        identity,
        host_name,
        audit_path,
        config_dir: dir.to_path_buf(),
        busy: AtomicBool::new(false),
        shutting_down: AtomicBool::new(false),
        active_socket: Mutex::new(None),
        pre_auth: AtomicUsize::new(0),
        prompt_cooldown: Mutex::new(HashMap::new()),
    });
    {
        // Graceful stop: end the session (input thread releases held keys/buttons), then exit.
        let shared = shared.clone();
        ctrlc::set_handler(move || {
            if shared.shutting_down.swap(true, Ordering::SeqCst) {
                std::process::exit(130); // second signal: give up waiting
            }
            log::info!("stopping …");
            if let Ok(g) = shared.active_socket.lock() {
                if let Some(h) = g.as_ref() {
                    h.shutdown(); // unblocks send/recv; input thread then releases held keys
                }
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while shared.busy.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            std::process::exit(0);
        })
        .context("installing signal handler")?;
    }
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log::warn!("accept: {e}");
                continue;
            }
        };
        let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        if shared.pre_auth.fetch_add(1, Ordering::SeqCst) >= MAX_PRE_AUTH {
            shared.pre_auth.fetch_sub(1, Ordering::SeqCst);
            log::warn!("dropping connection from {peer}: too many pending connections");
            drop(stream);
            continue;
        }
        let shared = shared.clone();
        let h = std::thread::Builder::new().name(format!("session {peer}")).spawn(move || {
            if let Err(e) = handle(&shared, stream) {
                log::warn!("session {peer}: {e:#}");
            }
        })?;
        if once {
            let _ = h.join();
            break;
        }
    }
    Ok(())
}

/// Decrements the pre-auth counter exactly once (on authorisation or on drop).
struct PreAuthSlot<'a>(Option<&'a AtomicUsize>);
impl PreAuthSlot<'_> {
    fn release(&mut self) {
        if let Some(c) = self.0.take() {
            c.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
impl Drop for PreAuthSlot<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

fn handle(shared: &Shared, stream: TcpStream) -> Result<()> {
    let mut slot = PreAuthSlot(Some(&shared.pre_auth));
    let peer = stream.peer_addr()?;
    log::info!("connection from {peer}");
    let mut session = fd_crypto::accept(stream, &shared.identity).context("handshake")?;
    let fp = session.remote_fingerprint();

    // `decode_viewer` also accepts an old viewer's Hello without capability bits.
    let hello: ViewerMsg =
        fd_proto::decode_viewer(&session.reader.recv_limited(HELLO_MAX, Some(Instant::now() + HELLO_DEADLINE))?)?;
    let ViewerMsg::Hello { protocol, viewer_name, caps: viewer_caps } = hello else {
        bail!("expected Hello");
    };
    let viewer_name = consent::sanitize(&viewer_name, 64);
    if protocol != PROTOCOL_VERSION {
        deny(&mut session.writer, &format!("protocol {protocol} unsupported (host speaks {PROTOCOL_VERSION})"))?;
        return Ok(());
    }

    let unattended = shared.args.unattended.iter().any(|a| normalize_fingerprint(a) == normalize_fingerprint(&fp))
        || crate::authorized::lookup(&shared.config_dir, &fp).is_some();
    if !unattended {
        let mut cd = shared.prompt_cooldown.lock().map_err(|_| anyhow!("poisoned"))?;
        cd.retain(|_, until| *until > Instant::now());
        if cd.contains_key(&peer.ip()) {
            drop(cd);
            deny(&mut session.writer, "too many recent requests; try again in a minute")?;
            return Ok(());
        }
    }

    // A previous session may still be tearing down (fast reconnect): give it a moment.
    let wait_until = Instant::now() + Duration::from_secs(3);
    while shared.busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        if Instant::now() > wait_until {
            deny(&mut session.writer, "host is already in a session")?;
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _busy = BusyGuard(&shared.busy);

    let started = Instant::now();
    let allowed = if unattended {
        log::info!("{viewer_name} [{fp}] allowed: unattended list");
        true
    } else {
        log::info!("asking local user to allow {viewer_name} [{fp}] from {peer}");
        consent::ask(&viewer_name, &fp, &peer.to_string(), Duration::from_secs(shared.args.consent_timeout))
    };
    if !allowed {
        if let Ok(mut cd) = shared.prompt_cooldown.lock() {
            cd.insert(peer.ip(), Instant::now() + PROMPT_COOLDOWN);
        }
        audit(shared, &peer, &viewer_name, &fp, "denied", Duration::ZERO);
        deny(&mut session.writer, "the host user did not allow the connection")?;
        return Ok(());
    }
    slot.release();

    let outcome = stream_session(shared, session, &viewer_name, viewer_caps);
    let how = match &outcome {
        Ok(()) => "ended".to_string(),
        Err(e) => format!("error: {e:#}"),
    };
    audit(shared, &peer, &viewer_name, &fp, &how, started.elapsed());
    outcome
}

struct BusyGuard<'a>(&'a AtomicBool);
impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn deny(w: &mut SecureWriter, reason: &str) -> Result<()> {
    log::info!("denying: {reason}");
    w.send(&fd_proto::encode(&HostMsg::Denied { reason: reason.into() })?)
}

/// A converted picture plus where on the screen it came from.
struct Pic {
    pic: fd_codec::I420Frame,
    /// Crop size (encoder source size).
    src: (u32, u32),
    /// Encoder output bounds the converter was built for.
    max: (u32, u32),
    region: Rect,
    screen: (u32, u32),
    /// Quality level the output size was chosen for (bitrate must match it).
    level: usize,
}

/// Single-slot "latest frame wins" hand-off from the capture thread to the encoder.
#[derive(Default)]
struct Slot {
    pic: Option<Pic>,
    closed: bool,
}

/// What the viewer asked to see (normalised region + physical output size).
#[derive(Clone, Copy, PartialEq, Eq)]
struct ViewReq {
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    max_w: u32,
    max_h: u32,
}

impl ViewReq {
    const FULL: ViewReq = ViewReq { x: 0, y: 0, w: NORM_MAX, h: NORM_MAX, max_w: u32::MAX, max_h: u32::MAX };
}

/// (crop size, output bounds, bitrate) an encoder was built for.
type EncKey = ((u32, u32), (u32, u32), u32);

/// Per-session counters shared by the session threads (for the periodic stats log).
#[derive(Default)]
struct Counters {
    inputs: AtomicU64,
    input_failed: AtomicU64,
    input_ignored: AtomicU64,
    views: AtomicU64,
    keyframe_requests: AtomicU64,
}

/// Quality ladder for slow / relayed links: (bitrate factor, output size factor).
/// Lower quality, never a frozen picture.
const QUALITY_LEVELS: [(f32, f32); 6] = [(1.0, 1.0), (0.6, 1.0), (0.4, 0.8), (0.25, 0.67), (0.15, 0.5), (0.08, 0.4)];
const MIN_BITRATE_BPS: u32 = 250_000;
/// Unsent data (in seconds of video at the current bitrate) that counts as congestion …
const CONGESTED_S: f64 = 0.15;
/// … for this long before we step down a level.
const CONGESTED_FOR: Duration = Duration::from_millis(500);
/// Below this the link keeps up; after `CALM_FOR` with frames flowing we step up.
const CALM_S: f64 = 0.03;
const CALM_FOR: Duration = Duration::from_secs(6);
/// Above this much unsent video, hold new frames (newest one is sent once it drains).
const GATE_S: f64 = 0.3;
const STATS_EVERY: Duration = Duration::from_secs(10);

fn level_bitrate(level: usize, base: u32) -> u32 {
    let level = level.min(QUALITY_LEVELS.len() - 1);
    ((base as f64 * QUALITY_LEVELS[level].0 as f64) as u32).max(MIN_BITRATE_BPS.min(base))
}

fn level_scale(level: usize) -> u32 {
    (QUALITY_LEVELS[level.min(QUALITY_LEVELS.len() - 1)].1 * 1000.0).round() as u32
}

/// Adaptive quality from the kernel send queue (no viewer cooperation needed).
struct Adapt {
    level: usize,
    changed: Instant,
    over_since: Option<Instant>,
    /// (since, frames sent at that point)
    calm_since: Option<(Instant, u64)>,
}

impl Adapt {
    fn new() -> Self {
        Self { level: 0, changed: Instant::now(), over_since: None, calm_since: None }
    }

    fn bitrate(&self, base: u32) -> u32 {
        level_bitrate(self.level, base)
    }

    fn scale_permille(&self) -> u32 {
        level_scale(self.level)
    }

    /// Feed one queue-delay sample; returns true if the level changed.
    fn update(&mut self, delay_s: f64, frames_sent: u64, now: Instant) -> bool {
        if delay_s > CONGESTED_S {
            self.calm_since = None;
            let since = *self.over_since.get_or_insert(now);
            if self.level + 1 < QUALITY_LEVELS.len()
                && now.duration_since(since) >= CONGESTED_FOR
                && now.duration_since(self.changed) >= Duration::from_secs(1)
            {
                self.level += 1;
                self.changed = now;
                self.over_since = None;
                return true;
            }
        } else if delay_s < CALM_S {
            self.over_since = None;
            let (since, f0) = *self.calm_since.get_or_insert((now, frames_sent));
            if self.level > 0
                && now.duration_since(since) >= CALM_FOR
                && frames_sent.saturating_sub(f0) >= 30
                && now.duration_since(self.changed) >= CALM_FOR
            {
                self.level -= 1;
                self.changed = now;
                self.calm_since = None;
                return true;
            }
        } else {
            self.over_since = None;
            self.calm_since = None;
        }
        false
    }
}

fn pack(w: u32, h: u32) -> u64 {
    ((w as u64) << 32) | h as u64
}

fn even_down(v: u32) -> u32 {
    v & !1
}

/// Screen-pixel crop for a view request: even-aligned, at least 64×64, inside the screen.
fn crop_rect(r: ViewReq, sw: u32, sh: u32) -> Rect {
    let scale = |v: u16, full: u32| (v as u64 * full as u64 / NORM_MAX as u64) as u32;
    let min_w = 64.min(sw);
    let min_h = 64.min(sh);
    let w = even_down(scale(r.w, sw).clamp(min_w, sw)).max(2);
    let h = even_down(scale(r.h, sh).clamp(min_h, sh)).max(2);
    let x = even_down(scale(r.x, sw).min(sw.saturating_sub(w)));
    let y = even_down(scale(r.y, sh).min(sh.saturating_sub(h)));
    Rect { x, y, w, h }
}

/// Encoder output bounds: the host's cap, reduced to what the viewer can show.
/// `scale_permille` < 1000 shrinks them further (adaptive quality).
fn out_bounds(args: &HostArgs, r: ViewReq, scale_permille: u32) -> (u32, u32) {
    let s = |v: u32| (v as u64 * scale_permille.min(1000) as u64 / 1000) as u32;
    let w = even_down(s(args.max_width.min(r.max_w)).max(64));
    let h = even_down(s(args.max_height.min(r.max_h)).max(64));
    (w, h)
}

fn stream_session(shared: &Shared, session: Session, viewer_name: &str, viewer_caps: u32) -> Result<()> {
    let args = &shared.args;
    let mut capturer = fd_capture::open_default().context("opening screen capture")?;
    // The viewer draws the pointer itself (instant feedback); keep it out of the video.
    capturer.set_draw_cursor(args.cursor_in_video);
    let (sw, sh) = capturer.size();
    let base_cfg = fd_codec::EncoderConfig {
        max_width: args.max_width,
        max_height: args.max_height,
        fps: args.fps.clamp(1.0, 120.0),
        bitrate_bps: args.bitrate_kbps.saturating_mul(1000),
    };
    let (vw, vh) = fd_codec::fit_size(sw, sh, args.max_width, args.max_height);
    let injector = if args.view_only {
        None
    } else {
        match fd_input::open_default(sw, sh) {
            Ok(i) => Some(i),
            Err(e) => {
                log::warn!("input injection unavailable ({e:#}); session is view-only");
                None
            }
        }
    };

    // Clipboard: only with --clipboard AND a viewer that asked; view-only never lets it write here.
    let negotiated = clipboard::host_negotiate(viewer_caps, args.clipboard, injector.is_some());
    let (clip_send, clip_apply) = clipboard::host_perms(negotiated);
    let clip_engine = if negotiated != 0 { clipboard::open_engine(clip_send, clip_apply) } else { None };
    // Only advertise what is actually usable (e.g. the clipboard could not be opened).
    let negotiated = if clip_engine.is_some() { negotiated } else { 0 };

    let Session { mut reader, writer, .. } = session;
    let shutdown = writer.shutdown_handle()?;
    if let Ok(mut g) = shared.active_socket.lock() {
        *g = Some(writer.shutdown_handle()?);
    }
    let writer = Arc::new(Mutex::new(writer));
    let send_on = |w: &Mutex<SecureWriter>, msg: &HostMsg| -> Result<()> {
        let bytes = fd_proto::encode(msg)?;
        w.lock().map_err(|_| anyhow!("writer poisoned"))?.send(&bytes)
    };
    send_on(&writer, &HostMsg::Welcome {
        protocol: PROTOCOL_VERSION,
        host_name: shared.host_name.clone(),
        screen_width: sw,
        screen_height: sh,
        video_width: vw,
        video_height: vh,
        caps: negotiated,
    })?;
    log::info!("session with {viewer_name} started: screen {sw}x{sh} → video ≤{vw}x{vh} @ {} fps", base_cfg.fps);

    let stop = Arc::new(AtomicBool::new(false));
    let want_keyframe = Arc::new(AtomicBool::new(true));
    let force_capture = Arc::new(AtomicBool::new(true));
    let screen_size = Arc::new(std::sync::atomic::AtomicU64::new(pack(sw, sh)));
    let view_req = Arc::new(Mutex::new(ViewReq::FULL));
    let counters = Arc::new(Counters::default());
    let quality_level = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let audit_path = shared.audit_path.clone();

    // Clipboard poller (host -> viewer).
    let clip_thread = match clip_engine.clone().filter(|_| clip_send) {
        Some(engine) => {
            let (writer, audit_path, name) = (writer.clone(), audit_path.clone(), viewer_name.to_string());
            Some(clipboard::spawn_poller(engine, stop.clone(), move |text| {
                let n = text.len();
                let ok = send_on(&writer, &HostMsg::Clipboard { text }).is_ok();
                if ok {
                    audit_clipboard(&audit_path, &name, "host_to_viewer", n);
                }
                ok
            })?)
        }
        None => None,
    };

    // Input / control thread.
    let input_thread = {
        let stop = stop.clone();
        let want_keyframe = want_keyframe.clone();
        let force_capture = force_capture.clone();
        let screen_size = screen_size.clone();
        let view_req = view_req.clone();
        let writer = writer.clone();
        let counters = counters.clone();
        let mut injector = injector;
        let (clip_engine, audit_path, viewer_name) = (clip_engine.clone(), audit_path.clone(), viewer_name.to_string());
        std::thread::Builder::new().name("host-input".into()).spawn(move || {
            let mut size = pack(sw, sh);
            let result = (|| -> Result<()> {
                loop {
                    let bytes = reader.recv()?;
                    match fd_proto::decode::<ViewerMsg>(&bytes)? {
                        ViewerMsg::Input(ev) => {
                            counters.inputs.fetch_add(1, Ordering::Relaxed);
                            if injector.is_none() {
                                counters.input_ignored.fetch_add(1, Ordering::Relaxed);
                            }
                            if let Some(inj) = injector.as_mut() {
                                let now = screen_size.load(Ordering::Relaxed);
                                if now != size {
                                    size = now;
                                    inj.set_screen_size((now >> 32) as u32, now as u32);
                                }
                                if let Err(e) = inj.inject(&ev) {
                                    counters.input_failed.fetch_add(1, Ordering::Relaxed);
                                    log::warn!("inject {ev:?}: {e:#}");
                                }
                            }
                        }
                        ViewerMsg::SetView { x, y, w, h, max_width, max_height } => {
                            let req = ViewReq {
                                x,
                                y,
                                w: w.max(1),
                                h: h.max(1),
                                max_w: max_width.clamp(64, 8192),
                                max_h: max_height.clamp(64, 8192),
                            };
                            let mut g = view_req.lock().map_err(|_| anyhow!("view poisoned"))?;
                            if *g != req {
                                counters.views.fetch_add(1, Ordering::Relaxed);
                                *g = req;
                                force_capture.store(true, Ordering::Relaxed);
                            }
                        }
                        ViewerMsg::RequestKeyframe => {
                            counters.keyframe_requests.fetch_add(1, Ordering::Relaxed);
                            want_keyframe.store(true, Ordering::Relaxed)
                        }
                        ViewerMsg::Ping { ts_us } => {
                            let b = fd_proto::encode(&HostMsg::Pong { ts_us })?;
                            writer.lock().map_err(|_| anyhow!("writer poisoned"))?.send(&b)?;
                        }
                        ViewerMsg::Bye => return Ok(()),
                        ViewerMsg::Clipboard { text } => {
                            // Only reachable for a viewer that negotiated it; anything else is dropped.
                            if let Some(n) = clip_engine.as_ref().and_then(|e| e.lock().ok()?.apply(&text)) {
                                audit_clipboard(&audit_path, &viewer_name, "viewer_to_host", n);
                            } else {
                                log::debug!("dropped viewer clipboard ({} bytes)", text.len());
                            }
                        }
                        ViewerMsg::Hello { .. } => bail!("unexpected Hello"),
                    }
                }
            })();
            if let Some(inj) = injector.as_mut() {
                let _ = inj.release_all();
            }
            stop.store(true, Ordering::SeqCst);
            result
        })?
    };

    // Capture + crop + convert (+ cursor) thread → slot → encode + send (this thread).
    let slot = Arc::new((Mutex::new(Slot::default()), std::sync::Condvar::new()));
    let (recycle_tx, recycle_rx) = std::sync::mpsc::channel::<fd_codec::I420Frame>();
    let capture_thread = {
        let stop = stop.clone();
        let slot = slot.clone();
        let force_capture = force_capture.clone();
        let screen_size = screen_size.clone();
        let view_req = view_req.clone();
        let writer = writer.clone();
        let base_cfg = base_cfg.clone();
        let args = args.clone();
        let quality_level = quality_level.clone();
        let viewer_name = viewer_name.to_string();
        let interval = Duration::from_secs_f32(1.0 / base_cfg.fps);
        std::thread::Builder::new().name("host-capture".into()).spawn(move || {
            let result = (|| -> Result<()> {
                let (mut sw, mut sh) = capturer.size();
                // (crop size, output bounds) the converter was built for.
                let mut conv_key = ((0u32, 0u32), (0u32, 0u32));
                let mut converter: Option<fd_codec::Converter> = None;
                let mut last_cursor: Option<(i32, i32, bool)> = None;
                let mut req = ViewReq::FULL;
                let mut last_adopt = Instant::now() - Duration::from_secs(1);
                let mut last_display_check: Option<Instant> = None;
                let mut display_dark = false;
                while !stop.load(Ordering::SeqCst) {
                    let tick = Instant::now();

                    // No lit monitor → the compositor repaints ~1×/s: say so in the log.
                    if last_display_check.is_none_or(|t| t.elapsed() >= STATS_EVERY) {
                        last_display_check = Some(tick);
                        let dark = capturer.active_outputs() == Some(0);
                        if dark && !display_dark {
                            log::warn!(
                                "session with {viewer_name}: no display output is active (monitor off or unplugged). \
                                 The desktop then repaints only ~1×/s, so video will be ~1 fps. \
                                 Fix: turn the monitor on, or pin a monitor (H1: scripts/h1-apply.sh --edid-connector, then restart GDM)"
                            );
                        } else if !dark && display_dark {
                            log::info!("session with {viewer_name}: a display output is active again");
                        }
                        display_dark = dark;
                    }

                    // Cursor channel: shape on change, position on change.
                    let cursor = if args.cursor_in_video {
                        None
                    } else {
                        capturer.cursor().unwrap_or_else(|e| {
                            log::debug!("cursor: {e:#}");
                            None
                        })
                    };
                    {
                        if let Some(ci) = cursor {
                            if let Some(shape) = ci.shape {
                                send_on(&writer, &HostMsg::CursorShape {
                                    serial: ci.serial,
                                    width: shape.width,
                                    height: shape.height,
                                    xhot: shape.xhot,
                                    yhot: shape.yhot,
                                    rgba: shape.rgba,
                                })?;
                            }
                            let pos = (ci.x, ci.y, ci.visible);
                            if last_cursor != Some(pos) {
                                last_cursor = Some(pos);
                                send_on(&writer, &HostMsg::CursorPos { x: ci.x, y: ci.y, visible: ci.visible })?;
                            }
                        }
                    }

                    // Adopt view changes at most 5×/s: each new size rebuilds converter+encoder (IDR).
                    let wanted = *view_req.lock().map_err(|_| anyhow!("view poisoned"))?;
                    if wanted != req && last_adopt.elapsed() >= Duration::from_millis(200) {
                        req = wanted;
                        last_adopt = Instant::now();
                        force_capture.store(true, Ordering::Relaxed); // new region: grab even if static
                    }
                    let crop = crop_rect(req, sw, sh);
                    let level = quality_level.load(Ordering::Relaxed);
                    let max = out_bounds(&args, req, level_scale(level));
                    let key = ((crop.w, crop.h), max);
                    if converter.is_none() || conv_key != key {
                        let cfg = fd_codec::EncoderConfig { max_width: max.0, max_height: max.1, ..base_cfg.clone() };
                        converter = Some(fd_codec::Converter::new(crop.w, crop.h, &cfg)?);
                        conv_key = key;
                        force_capture.store(true, Ordering::Relaxed);
                    }
                    let conv = converter.as_ref().expect("converter just set");

                    let grabbed = if force_capture.swap(false, Ordering::Relaxed) {
                        capturer.capture_ref().map(Some)
                    } else {
                        capturer.capture_if_changed()
                    };
                    match grabbed {
                        Ok(Some(frame)) => {
                            let sub = fd_capture::crop(frame, crop.x, crop.y, crop.w, crop.h);
                            let mut pic = recycle_rx
                                .try_iter()
                                .find(|p| (p.width(), p.height()) == conv.output_size())
                                .unwrap_or_else(|| conv.new_frame());
                            conv.convert(sub, &mut pic)?;
                            let (lock, cv) = &*slot;
                            let mut g = lock.lock().map_err(|_| anyhow!("slot poisoned"))?;
                            g.pic = Some(Pic { pic, src: (crop.w, crop.h), max, region: crop, screen: (sw, sh), level });
                            cv.notify_one();
                        }
                        Ok(None) => {}
                        Err(e) if e.downcast_ref::<fd_capture::ScreenResized>().is_some() => {
                            // xrandr may still be mid-change: retry briefly.
                            let mut tries = 0;
                            capturer = loop {
                                match fd_capture::open_default() {
                                    Ok(c) => break c,
                                    Err(e) if tries < 10 => {
                                        tries += 1;
                                        log::debug!("reopen capture: {e:#}; retrying");
                                        std::thread::sleep(Duration::from_millis(200));
                                    }
                                    Err(e) => return Err(e.context("reopening capture after resize")),
                                }
                            };
                            capturer.set_draw_cursor(args.cursor_in_video);
                            (sw, sh) = capturer.size();
                            screen_size.store(pack(sw, sh), Ordering::Relaxed);
                            converter = None;
                            force_capture.store(true, Ordering::Relaxed);
                            log::info!("screen resized to {sw}x{sh}");
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                    if let Some(rest) = interval.checked_sub(tick.elapsed()) {
                        std::thread::sleep(rest);
                    }
                }
                Ok(())
            })();
            stop.store(true, Ordering::SeqCst);
            let (lock, cv) = &*slot;
            if let Ok(mut g) = lock.lock() {
                g.closed = true;
            }
            cv.notify_all();
            result
        })?
    };

    let t0 = Instant::now();
    let mut seq = 0u64;
    let mut encoder: Option<(fd_codec::VideoEncoder, EncKey)> = None;
    let mut last: Option<Pic> = None;
    let mut pending = false;
    let mut kf_retries = 0u32;
    let mut adapt = Adapt::new();
    let mut total_bytes = 0u64;
    let mut held = 0u64;
    let mut max_queue = 0usize;
    // (when, frames, bytes, inputs, held) at the last stats line.
    let mut mark = (Instant::now(), 0u64, 0u64, 0u64, 0u64);
    let video_result = (|| -> Result<()> {
        loop {
            if stop.load(Ordering::SeqCst) || shared.shutting_down.load(Ordering::SeqCst) {
                return Ok(());
            }
            let fresh = {
                let (lock, cv) = &*slot;
                let g = lock.lock().map_err(|_| anyhow!("slot poisoned"))?;
                let (mut g, _) = cv
                    .wait_timeout_while(g, Duration::from_millis(100), |s| s.pic.is_none() && !s.closed)
                    .map_err(|_| anyhow!("slot poisoned"))?;
                if g.closed && g.pic.is_none() {
                    return Ok(());
                }
                g.pic.take()
            };
            let now = Instant::now();
            let queued = shutdown.queued_bytes();
            let bps = adapt.bitrate(base_cfg.bitrate_bps);
            let delay = queued.map_or(0.0, |q| q as f64 * 8.0 / bps as f64);
            max_queue = max_queue.max(queued.unwrap_or(0));
            if adapt.update(delay, seq, now) {
                quality_level.store(adapt.level, Ordering::Relaxed);
                log::info!(
                    "session with {viewer_name}: quality level {} ({} kbps, {}% size); send queue {:.0} ms",
                    adapt.level,
                    adapt.bitrate(base_cfg.bitrate_bps) / 1000,
                    adapt.scale_permille() / 10,
                    delay * 1000.0
                );
            }
            if now.duration_since(mark.0) >= STATS_EVERY {
                let secs = now.duration_since(mark.0).as_secs_f64();
                let inputs = counters.inputs.load(Ordering::Relaxed);
                log::info!(
                    "session with {viewer_name}: {:.1} fps, {:.0} kbps, quality {}, queue max {} KB, held {}, input {} (+{})",
                    (seq - mark.1) as f64 / secs,
                    (total_bytes - mark.2) as f64 * 8.0 / 1000.0 / secs,
                    adapt.level,
                    max_queue / 1024,
                    held - mark.4,
                    inputs,
                    inputs - mark.3,
                );
                mark = (now, seq, total_bytes, inputs, held);
                max_queue = 0;
            }

            let kf = want_keyframe.swap(false, Ordering::Relaxed);
            if let Some(p) = fresh {
                if pending {
                    held += 1; // a picture that never went out (slow link)
                }
                if let Some(old) = last.replace(p) {
                    let _ = recycle_tx.send(old.pic);
                }
                pending = true;
            }
            if !pending && !kf {
                continue; // nothing new on screen
            }
            // Link can't keep up: hold the newest picture until the queue drains.
            if delay > GATE_S {
                if kf {
                    want_keyframe.store(true, Ordering::Relaxed);
                }
                continue;
            }
            let Some(pic) = last.as_ref() else {
                // Keyframe wanted before anything was captured: ask for a full grab.
                want_keyframe.store(true, Ordering::Relaxed);
                force_capture.store(true, Ordering::Relaxed);
                continue;
            };
            pending = false;
            // Bitrate of the level this picture was sized for: one encoder rebuild (IDR) per step.
            let bps = level_bitrate(pic.level, base_cfg.bitrate_bps);
            let key = (pic.src, pic.max, bps);
            if encoder.as_ref().is_none_or(|(_, k)| *k != key) {
                let cfg = fd_codec::EncoderConfig { max_width: pic.max.0, max_height: pic.max.1, bitrate_bps: bps, ..base_cfg.clone() };
                encoder = Some((fd_codec::VideoEncoder::new(pic.src.0, pic.src.1, cfg)?, key));
            }
            let (enc, _) = encoder.as_mut().expect("encoder just set");
            match enc.encode_i420(&pic.pic, kf)? {
                Some(out) => {
                    kf_retries = 0;
                    seq += 1;
                    total_bytes += out.data.len() as u64;
                    send_on(&writer, &HostMsg::Video {
                        seq,
                        keyframe: out.keyframe,
                        ts_us: t0.elapsed().as_micros() as u64,
                        region: pic.region,
                        screen_width: pic.screen.0,
                        screen_height: pic.screen.1,
                        data: out.data,
                    })?;
                }
                // Rate control skipped the forced IDR: retry a few times, not forever.
                None if kf && kf_retries < 5 => {
                    kf_retries += 1;
                    want_keyframe.store(true, Ordering::Relaxed);
                }
                None => {}
            }
        }
    })();
    stop.store(true, Ordering::SeqCst);
    let capture_result = capture_thread.join().map_err(|_| anyhow!("capture thread panicked"))?;
    let video_result = video_result.and(capture_result);
    if video_result.is_ok() {
        let _ = send_on(&writer, &HostMsg::Bye { reason: "host ended session".into() });
    }
    shutdown.shutdown();
    if let Ok(mut g) = shared.active_socket.lock() {
        *g = None;
    }
    let input_result = input_thread.join().map_err(|_| anyhow!("input thread panicked"))?;
    if let Some(t) = clip_thread {
        let _ = t.join();
    }
    let secs = started.elapsed().as_secs_f64().max(0.001);
    log::info!(
        "session with {viewer_name} ended after {seq} frames in {secs:.0} s ({:.1} fps avg, {:.0} kbps avg); \
         input events {} ({} failed, {} ignored: view-only), view changes {}, keyframe requests {}, frames held for a slow link {held}, final quality level {}",
        seq as f64 / secs,
        total_bytes as f64 * 8.0 / 1000.0 / secs,
        counters.inputs.load(Ordering::Relaxed),
        counters.input_failed.load(Ordering::Relaxed),
        counters.input_ignored.load(Ordering::Relaxed),
        counters.views.load(Ordering::Relaxed),
        counters.keyframe_requests.load(Ordering::Relaxed),
        adapt.level,
    );
    // A viewer hanging up shows up as a read error on the input thread; that's a normal end.
    match (video_result, input_result) {
        (Err(e), _) if !is_disconnect(&e) => Err(e),
        _ => Ok(()),
    }
}


fn is_disconnect(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected
            )
        })
    })
}

/// One audit line per clipboard transfer: direction and size only, never the content.
fn audit_clipboard(path: &Path, viewer: &str, direction: &str, bytes: usize) {
    let line = format!(
        "{} viewer=\"{}\" clipboard={direction} bytes={bytes}\n",
        unix_time(),
        viewer.replace('"', "'")
    );
    write_audit(path, &line);
}

fn audit(shared: &Shared, peer: &SocketAddr, name: &str, fp: &str, outcome: &str, dur: Duration) {
    let line = format!(
        "{} peer={peer} viewer=\"{}\" fingerprint={fp} outcome=\"{}\" duration_s={}\n",
        unix_time(),
        name.replace('"', "'"),
        outcome.replace('"', "'"),
        dur.as_secs()
    );
    write_audit(&shared.audit_path, &line);
}

fn write_audit(path: &Path, line: &str) {
    if path.as_os_str() == "-" {
        log::info!(target: "audit", "{}", line.trim_end());
        return;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let r = opts
        .open(path)
        .and_then(|mut f| f.write_all(line.as_bytes()));
    if let Err(e) = r {
        log::warn!("audit log {}: {e}", path.display());
    }
}

fn unix_time() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn hostname() -> String {
    let from_cmd = || {
        // macOS/Windows have no /etc/hostname; `hostname` exists on all three.
        std::process::Command::new("hostname")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(from_cmd)
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|s| crate::consent::sanitize(&s, 64))
        .unwrap_or_else(|| "freedomdesk-host".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crop_is_even_inside_and_min_sized() {
        let full = crop_rect(ViewReq::FULL, 3840, 2160);
        assert_eq!(full, Rect { x: 0, y: 0, w: 3840, h: 2160 });
        let r = ViewReq { x: 65535, y: 65535, w: 10, h: 10, max_w: 100, max_h: 100 };
        let c = crop_rect(r, 3840, 2160);
        assert!(c.w >= 64 && c.h >= 64 && c.x + c.w <= 3840 && c.y + c.h <= 2160);
        assert!([c.x, c.y, c.w, c.h].iter().all(|v| v.is_multiple_of(2)));
        let half = ViewReq { x: 16384, y: 16384, w: 32768, h: 32768, max_w: 1, max_h: 1 };
        let c = crop_rect(half, 3841, 2161);
        assert!(c.x + c.w <= 3841 && c.y + c.h <= 2161);
    }

    #[test]
    fn adapt_steps_down_under_congestion_and_back_up_when_calm() {
        let t = Instant::now() + Duration::from_secs(10);
        let mut a = Adapt::new();
        assert_eq!(a.bitrate(6_000_000), 6_000_000);
        // A short spike (one IDR) does not change anything.
        assert!(!a.update(0.5, 0, t));
        assert!(!a.update(0.0, 0, t + Duration::from_millis(100)));
        // Sustained congestion: one level per second at most.
        assert!(!a.update(0.5, 0, t + Duration::from_millis(200)));
        assert!(a.update(0.5, 0, t + Duration::from_millis(800)));
        assert_eq!(a.level, 1);
        assert!(!a.update(0.5, 0, t + Duration::from_millis(1400)));
        assert!(a.update(0.5, 0, t + Duration::from_millis(1900)));
        assert_eq!(a.level, 2);
        assert!(a.scale_permille() < 1000 && a.bitrate(6_000_000) < 6_000_000);
        // Floors: never below the minimum bitrate / last level.
        let mut now = t + Duration::from_secs(3);
        for _ in 0..40 {
            now += Duration::from_millis(600);
            a.update(1.0, 0, now);
        }
        assert_eq!(a.level, QUALITY_LEVELS.len() - 1);
        assert!(a.bitrate(6_000_000) >= MIN_BITRATE_BPS);
        // Calm but idle (no frames sent): stay; calm with frames flowing: step up.
        assert!(!a.update(0.0, 100, now + Duration::from_secs(1)));
        assert!(!a.update(0.0, 100, now + Duration::from_secs(8)));
        assert!(!a.update(0.0, 120, now + Duration::from_secs(9)));
        assert!(a.update(0.0, 140, now + Duration::from_secs(10)));
        assert_eq!(a.level, QUALITY_LEVELS.len() - 2);
    }

    #[test]
    fn out_bounds_scale() {
        let full = ViewReq::FULL;
        #[derive(clap::Parser)]
        struct W {
            #[command(flatten)]
            a: HostArgs,
        }
        let args = <W as clap::Parser>::parse_from(["host"]).a;
        assert_eq!(out_bounds(&args, full, 1000), (1920, 1080));
        assert_eq!(out_bounds(&args, full, 500), (960, 540));
        assert_eq!(out_bounds(&args, full, 1), (64, 64));
    }
}
