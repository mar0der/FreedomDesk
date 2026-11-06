//! Host agent: accept a viewer, ask consent, stream the screen, inject input.

use crate::{consent, load_identity, netpolicy};
use anyhow::{anyhow, bail, Context, Result};
use fd_crypto::{normalize_fingerprint, SecureWriter, Session};
use fd_proto::{HostMsg, ViewerMsg, DEFAULT_PORT, PROTOCOL_VERSION};
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    #[arg(long, default_value_t = 30.0)]
    fps: f32,
    #[arg(long, default_value_t = 1920)]
    max_width: u32,
    #[arg(long, default_value_t = 1080)]
    max_height: u32,
    /// Target video bitrate in kbit/s.
    #[arg(long, default_value_t = 6000)]
    bitrate_kbps: u32,
    /// Exit after the first session ends (useful for tests).
    #[arg(long)]
    once: bool,
}

struct Shared {
    args: HostArgs,
    identity: fd_crypto::Identity,
    host_name: String,
    audit_path: PathBuf,
    busy: AtomicBool,
    /// Set by SIGINT/SIGTERM: every session winds down (releasing held keys).
    shutting_down: AtomicBool,
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
    let identity = load_identity(dir)?;
    let addr = netpolicy::resolve_bind(args.bind.as_deref(), args.port, args.allow_public_bind)?;
    let listener = TcpListener::bind(addr).with_context(|| format!("listening on {addr}"))?;
    let host_name = hostname();
    println!("FreedomDesk host “{host_name}” listening on {addr}");
    println!("Host fingerprint: {}", identity.fingerprint());
    println!("Viewer command:   freedomdesk view {addr}");
    if !args.unattended.is_empty() {
        println!("Unattended viewers (no consent prompt): {}", args.unattended.join(", "));
    }
    let once = args.once;
    let shared = Arc::new(Shared {
        args,
        identity,
        host_name,
        audit_path: dir.join("audit.log"),
        busy: AtomicBool::new(false),
        shutting_down: AtomicBool::new(false),
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

    let hello: ViewerMsg =
        fd_proto::decode(&session.reader.recv_limited(HELLO_MAX, Some(Instant::now() + HELLO_DEADLINE))?)?;
    let ViewerMsg::Hello { protocol, viewer_name } = hello else {
        bail!("expected Hello");
    };
    let viewer_name = consent::sanitize(&viewer_name, 64);
    if protocol != PROTOCOL_VERSION {
        deny(&mut session.writer, &format!("protocol {protocol} unsupported (host speaks {PROTOCOL_VERSION})"))?;
        return Ok(());
    }

    let unattended = shared
        .args
        .unattended
        .iter()
        .any(|a| normalize_fingerprint(a) == normalize_fingerprint(&fp));
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

    let outcome = stream_session(shared, session, &viewer_name);
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

fn stream_session(shared: &Shared, session: Session, viewer_name: &str) -> Result<()> {
    let args = &shared.args;
    let mut capturer = fd_capture::open_default().context("opening screen capture")?;
    let (sw, sh) = capturer.size();
    let cfg = fd_codec::EncoderConfig {
        max_width: args.max_width,
        max_height: args.max_height,
        fps: args.fps,
        bitrate_bps: args.bitrate_kbps.saturating_mul(1000),
    };
    let mut encoder = fd_codec::VideoEncoder::new(sw, sh, cfg).context("creating encoder")?;
    let (vw, vh) = encoder.output_size();
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

    let Session { mut reader, writer, .. } = session;
    let shutdown = writer.shutdown_handle()?;
    let writer = Arc::new(Mutex::new(writer));
    let send = |msg: &HostMsg| -> Result<()> {
        let bytes = fd_proto::encode(msg)?;
        writer.lock().map_err(|_| anyhow!("writer poisoned"))?.send(&bytes)
    };
    send(&HostMsg::Welcome {
        protocol: PROTOCOL_VERSION,
        host_name: shared.host_name.clone(),
        screen_width: sw,
        screen_height: sh,
        video_width: vw,
        video_height: vh,
    })?;
    log::info!("session with {viewer_name} started: screen {sw}x{sh} → video {vw}x{vh} @ {} fps", args.fps);

    let stop = Arc::new(AtomicBool::new(false));
    let want_keyframe = Arc::new(AtomicBool::new(true));

    // Input / control thread.
    let input_thread = {
        let stop = stop.clone();
        let want_keyframe = want_keyframe.clone();
        let writer = writer.clone();
        let mut injector = injector;
        std::thread::Builder::new().name("host-input".into()).spawn(move || {
            let result = (|| -> Result<()> {
                loop {
                    let bytes = reader.recv()?;
                    match fd_proto::decode::<ViewerMsg>(&bytes)? {
                        ViewerMsg::Input(ev) => {
                            if let Some(inj) = injector.as_mut() {
                                if let Err(e) = inj.inject(&ev) {
                                    log::warn!("inject {ev:?}: {e:#}");
                                }
                            }
                        }
                        ViewerMsg::RequestKeyframe => want_keyframe.store(true, Ordering::Relaxed),
                        ViewerMsg::Ping { ts_us } => {
                            let b = fd_proto::encode(&HostMsg::Pong { ts_us })?;
                            writer.lock().map_err(|_| anyhow!("writer poisoned"))?.send(&b)?;
                        }
                        ViewerMsg::Bye => return Ok(()),
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

    // Video loop.
    let interval = Duration::from_secs_f32(1.0 / args.fps.clamp(1.0, 120.0));
    let t0 = Instant::now();
    let mut seq = 0u64;
    let mut video_result = Ok(());
    while !stop.load(Ordering::SeqCst) && !shared.shutting_down.load(Ordering::SeqCst) {
        let tick = Instant::now();
        let r = (|| -> Result<()> {
            let frame = capturer.capture()?;
            let kf = want_keyframe.swap(false, Ordering::Relaxed);
            if let Some(enc) = encoder.encode(frame, kf)? {
                seq += 1;
                send(&HostMsg::Video {
                    seq,
                    keyframe: enc.keyframe,
                    ts_us: t0.elapsed().as_micros() as u64,
                    data: enc.data,
                })?;
            }
            Ok(())
        })();
        if let Err(e) = r {
            video_result = Err(e);
            break;
        }
        if let Some(rest) = interval.checked_sub(tick.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    stop.store(true, Ordering::SeqCst);
    if video_result.is_ok() {
        let _ = send(&HostMsg::Bye { reason: "host ended session".into() });
    }
    shutdown.shutdown();
    let input_result = input_thread.join().map_err(|_| anyhow!("input thread panicked"))?;
    log::info!("session with {viewer_name} ended after {seq} frames");
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

fn audit(shared: &Shared, peer: &SocketAddr, name: &str, fp: &str, outcome: &str, dur: Duration) {
    let line = format!(
        "{} peer={peer} viewer=\"{}\" fingerprint={fp} outcome=\"{}\" duration_s={}\n",
        unix_time(),
        name.replace('"', "'"),
        outcome.replace('"', "'"),
        dur.as_secs()
    );
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let r = opts
        .open(&shared.audit_path)
        .and_then(|mut f| f.write_all(line.as_bytes()));
    if let Err(e) = r {
        log::warn!("audit log {}: {e}", shared.audit_path.display());
    }
}

fn unix_time() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "freedomdesk-host".into())
}
