//! Computer control for AI agents: `freedomdesk agent <cmd>` (JSON on stdout) and
//! the operations behind `freedomdesk mcp`.
//!
//! Every call is one short session: connect (Noise, pinned host key), act,
//! disconnect. Nothing here weakens the viewer's trust model: a host must
//! already be pinned in `known_hosts`, or the caller must pass its fingerprint
//! (`--expect-fingerprint`); there is no implicit trust-on-first-use.

use crate::viewer::{self, ConnectOpts, ConnectUi, TrustPrompt};
use anyhow::{anyhow, bail, Context, Result};
use fd_crypto::{normalize_fingerprint, ShutdownHandle};
use fd_proto::{caps, HostMsg, InputEvent, MouseButton, ViewerMsg, NORM_MAX};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Kill switch: if this environment variable is set (non-empty, not `0`/`false`) or a
/// file with this name exists in the config dir, input tools are refused immediately.
pub const KILL_NAME: &str = "FREEDOMDESK_AGENT_KILL";
/// Longest text one `type` call accepts (characters).
pub const MAX_TYPE_CHARS: usize = 4096;
/// Pong timestamp marking our own sync pings (the writer thread uses small values).
const SYNC_TS: u64 = u64::MAX - 0xFD;

// ------------------------------------------------------------------ CLI

#[derive(clap::Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    cmd: AgentCmd,
    /// Expected host fingerprint. Required the first time a host is used (it is then pinned).
    #[arg(long, global = true)]
    expect_fingerprint: Option<String>,
    /// Seconds to wait for the first frame (host consent has its own, longer wait).
    #[arg(long, global = true, default_value_t = 30)]
    timeout: u64,
}

#[derive(clap::Subcommand)]
enum AgentCmd {
    /// List pinned hosts from known_hosts (no network).
    Machines,
    /// Capture the host screen as PNG (--out FILE, or base64 in the JSON).
    Screenshot {
        host: String,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Include the PNG as base64 in the JSON even when --out is given.
        #[arg(long)]
        base64: bool,
    },
    /// Click at screenshot pixel coordinates.
    Click {
        host: String,
        x: u32,
        y: u32,
        #[arg(long, default_value = "left")]
        button: String,
        #[arg(long)]
        double: bool,
    },
    /// Type text on the host (never type passwords through an agent).
    Type { host: String, text: String },
    /// Press a key combination, e.g. ctrl+alt+Delete, ctrl+c, Return, F5.
    Key { host: String, combo: String },
    /// Host clipboard (the host must run with --clipboard).
    Clipboard {
        #[command(subcommand)]
        op: ClipOp,
    },
    /// Connect and report screen size and capabilities.
    Status { host: String },
}

#[derive(clap::Subcommand)]
enum ClipOp {
    /// Wait for the host clipboard to change and print the new text.
    Get {
        host: String,
        /// Seconds to wait for a change.
        #[arg(long, default_value_t = 10)]
        wait: u64,
    },
    /// Replace the host clipboard (TEXT, or `-` to read stdin).
    Set { host: String, text: String },
}

/// Entry point of `freedomdesk agent`: prints one JSON object, returns the exit code.
pub fn run(dir: &Path, args: AgentArgs) -> i32 {
    let action = match args.cmd {
        AgentCmd::Machines => Ok(Action::Machines),
        AgentCmd::Screenshot { host, out, base64 } => Ok(Action::Screenshot { host, out, base64 }),
        AgentCmd::Click { host, x, y, button, double } => parse_button(&button).map(|button| Action::Click { host, x, y, button, double }),
        AgentCmd::Type { host, text } => Ok(Action::Type { host, text }),
        AgentCmd::Key { host, combo } => Ok(Action::Key { host, combo }),
        AgentCmd::Clipboard { op: ClipOp::Get { host, wait } } => Ok(Action::ClipboardGet { host, wait: Duration::from_secs(wait) }),
        AgentCmd::Clipboard { op: ClipOp::Set { host, text } } => read_text_arg(text).map(|text| Action::ClipboardSet { host, text }),
        AgentCmd::Status { host } => Ok(Action::Status { host }),
    };
    let result = action.and_then(|a| {
        if a.is_input() {
            if let Some(why) = kill_switch(dir) {
                audit(dir, "cli", &a, &format!("outcome=denied reason=\"{why}\""));
                bail!("{why}");
            }
        }
        let t = Target {
            dir,
            expect_fp: args.expect_fingerprint.clone(),
            allow: None,
            timeout: Duration::from_secs(args.timeout.max(1)),
            source: "cli",
        };
        let mut out = execute(&t, &a)?;
        // CLI screenshot: write the file / attach base64 (the MCP server returns an image instead).
        if let (Action::Screenshot { out: path, base64, .. }, Some(png)) = (&a, out.png.take()) {
            if let Some(p) = path {
                std::fs::write(p, &png).with_context(|| format!("writing {}", p.display()))?;
                out.json["path"] = json!(p.display().to_string());
            }
            if path.is_none() || *base64 {
                out.json["png_base64"] = json!(data_encoding::BASE64.encode(&png));
            }
            out.json["png_bytes"] = json!(png.len());
        }
        Ok(out.json)
    });
    match result {
        Ok(mut v) => {
            v["ok"] = json!(true);
            println!("{v}");
            0
        }
        Err(e) => {
            println!("{}", json!({"ok": false, "error": format!("{e:#}")}));
            1
        }
    }
}

fn read_text_arg(text: String) -> Result<String> {
    if text != "-" {
        return Ok(text);
    }
    use std::io::Read;
    let mut s = String::new();
    std::io::stdin().take(fd_proto::CLIPBOARD_MAX_BYTES as u64 + 1).read_to_string(&mut s)?;
    Ok(s)
}

pub fn parse_button(s: &str) -> Result<MouseButton> {
    match s.to_ascii_lowercase().as_str() {
        "left" => Ok(MouseButton::Left),
        "right" => Ok(MouseButton::Right),
        "middle" => Ok(MouseButton::Middle),
        other => bail!("unknown button {other:?} (use left, right or middle)"),
    }
}

// ------------------------------------------------------------------ actions

#[derive(Debug, Clone)]
pub enum Action {
    Machines,
    Screenshot { host: String, out: Option<PathBuf>, base64: bool },
    Click { host: String, x: u32, y: u32, button: MouseButton, double: bool },
    Type { host: String, text: String },
    Key { host: String, combo: String },
    ClipboardGet { host: String, wait: Duration },
    ClipboardSet { host: String, text: String },
    Status { host: String },
}

#[derive(Debug, Default)]
pub struct Output {
    pub json: Value,
    /// PNG bytes (screenshot only).
    pub png: Option<Vec<u8>>,
}

impl Action {
    pub fn host(&self) -> Option<&str> {
        match self {
            Action::Machines => None,
            Action::Screenshot { host, .. }
            | Action::Click { host, .. }
            | Action::Type { host, .. }
            | Action::Key { host, .. }
            | Action::ClipboardGet { host, .. }
            | Action::ClipboardSet { host, .. }
            | Action::Status { host } => Some(host),
        }
    }

    /// Tools that make the host do something (kill switch + `allow_input` apply).
    pub fn is_input(&self) -> bool {
        matches!(self, Action::Click { .. } | Action::Type { .. } | Action::Key { .. } | Action::ClipboardSet { .. })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Action::Machines => "machines",
            Action::Screenshot { .. } => "screenshot",
            Action::Click { .. } => "click",
            Action::Type { .. } => "type",
            Action::Key { .. } => "key",
            Action::ClipboardGet { .. } => "clipboard_get",
            Action::ClipboardSet { .. } => "clipboard_set",
            Action::Status { .. } => "status",
        }
    }

    /// Audit detail: sizes and positions only, never typed text or clipboard contents.
    fn audit_detail(&self) -> String {
        match self {
            Action::Click { x, y, button, double, .. } => format!("x={x} y={y} button={button:?} double={double}"),
            Action::Type { text, .. } => format!("chars={}", text.chars().count()),
            Action::Key { combo, .. } => match parse_combo(combo) {
                // A lone printable key could be one character of a password: not logged.
                Ok(c) if c.mods.is_empty() && c.printable => "key=<printable>".into(),
                Ok(_) => format!("combo={}", combo.replace(['"', '\n', ' '], "_")),
                Err(_) => "combo=<invalid>".into(),
            },
            Action::ClipboardSet { text, .. } => format!("bytes={}", text.len()),
            _ => String::new(),
        }
    }
}

/// How a call connects and what it may reach.
pub struct Target<'a> {
    pub dir: &'a Path,
    pub expect_fp: Option<String>,
    /// Allowed host fingerprints (normalised). `None` = unrestricted (the human's own CLI).
    pub allow: Option<Vec<String>>,
    pub timeout: Duration,
    /// "cli" or "mcp", for the audit log.
    pub source: &'static str,
}

/// Run one action and write one audit line (success or failure).
pub fn execute(t: &Target, a: &Action) -> Result<Output> {
    let r = do_execute(t, a);
    let outcome = match &r {
        Ok(_) => "outcome=ok".to_string(),
        Err(e) => format!("outcome=error reason=\"{}\"", format!("{e:#}").replace(['"', '\n'], "'")),
    };
    audit(t.dir, t.source, a, &outcome);
    r
}

fn do_execute(t: &Target, a: &Action) -> Result<Output> {
    match a {
        Action::Machines => Ok(Output { json: machines(t.dir, t.allow.as_deref())?, png: None }),
        Action::Screenshot { host, .. } => {
            let live = Live::connect(t, host, false)?;
            let (w, h, rgba) = live.screenshot(t.timeout)?;
            let png = encode_png(w, h, &rgba)?;
            let mut j = live.info();
            j["width"] = json!(w);
            j["height"] = json!(h);
            Ok(Output { json: j, png: Some(png) })
        }
        Action::Status { host } => {
            let live = Live::connect(t, host, true)?;
            let started = Instant::now();
            let rtt = live.sync(Duration::from_secs(5)).ok().map(|()| started.elapsed().as_secs_f64() * 1000.0);
            let first = live.wait_frame(Duration::from_secs(3)).ok();
            let mut j = live.info();
            j["rtt_ms"] = json!(rtt.map(|r| (r * 10.0).round() / 10.0));
            j["frame_received"] = json!(first.is_some());
            // The protocol carries neither "lock screen" nor "view-only". Say so, do not guess.
            j["login_or_lock_screen"] = json!("unknown");
            j["input_accepted"] = json!("unknown");
            j["note"] = json!("lock/login screen and view-only mode are not reported by the protocol; take a screenshot to see");
            Ok(Output { json: j, png: None })
        }
        Action::Click { host, x, y, button, double } => {
            let live = Live::connect(t, host, false)?;
            let (w, h) = live.frame_dims(t.timeout);
            if *x >= w || *y >= h {
                bail!("coordinates ({x},{y}) outside the {w}x{h} screenshot area");
            }
            live.send(ViewerMsg::Input(InputEvent::MouseMove { x: norm(*x, w), y: norm(*y, h) }))?;
            std::thread::sleep(Duration::from_millis(40));
            for _ in 0..if *double { 2 } else { 1 } {
                live.send(ViewerMsg::Input(InputEvent::MouseButton { button: *button, down: true }))?;
                std::thread::sleep(Duration::from_millis(30));
                live.send(ViewerMsg::Input(InputEvent::MouseButton { button: *button, down: false }))?;
                std::thread::sleep(Duration::from_millis(60));
            }
            live.sync(Duration::from_secs(5))?;
            Ok(Output {
                json: json!({"clicked": {"x": x, "y": y, "button": format!("{button:?}").to_lowercase(), "double": double}, "area": {"width": w, "height": h}}),
                png: None,
            })
        }
        Action::Type { host, text } => {
            if text.chars().count() > MAX_TYPE_CHARS {
                bail!("text longer than {MAX_TYPE_CHARS} characters; split it up");
            }
            let live = Live::connect(t, host, false)?;
            for ch in text.chars() {
                // Re-checked per character so the kill switch stops a long paste mid-way.
                if let Some(why) = kill_switch(t.dir) {
                    bail!("{why} (stopped after partial input)");
                }
                match ch {
                    '\n' | '\r' => live.tap(0xff0d)?,
                    '\t' => live.tap(0xff09)?,
                    c if c.is_control() => bail!("control character U+{:04X} cannot be typed", c as u32),
                    c => live.send(ViewerMsg::Input(InputEvent::Text { ch: c }))?,
                }
                std::thread::sleep(Duration::from_millis(3));
            }
            live.sync(Duration::from_secs(10))?;
            Ok(Output { json: json!({"typed_chars": text.chars().count()}), png: None })
        }
        Action::Key { host, combo } => {
            let c = parse_combo(combo)?;
            let live = Live::connect(t, host, false)?;
            for m in &c.mods {
                live.send(ViewerMsg::Input(InputEvent::Key { keysym: *m, down: true }))?;
            }
            std::thread::sleep(Duration::from_millis(30));
            live.tap(c.key)?;
            std::thread::sleep(Duration::from_millis(30));
            for m in c.mods.iter().rev() {
                live.send(ViewerMsg::Input(InputEvent::Key { keysym: *m, down: false }))?;
            }
            live.sync(Duration::from_secs(5))?;
            Ok(Output { json: json!({"pressed": combo}), png: None })
        }
        Action::ClipboardGet { host, wait } => {
            let live = Live::connect(t, host, true)?;
            if live.caps & caps::CLIPBOARD_TO_VIEWER == 0 {
                bail!("host did not negotiate clipboard sync to the viewer (start the host with --clipboard)");
            }
            match live.wait_clipboard(*wait) {
                Some(text) => Ok(Output { json: json!({"text": text, "bytes": text.len()}), png: None }),
                None => bail!(
                    "no clipboard change within {}s: the host only pushes changes made after we connect, \
                     it cannot be asked for its current clipboard (protocol limitation)",
                    wait.as_secs()
                ),
            }
        }
        Action::ClipboardSet { host, text } => {
            let Some(clean) = crate::clipboard::sanitize(text) else {
                bail!("clipboard text rejected (empty, over {} bytes, or only control characters)", fd_proto::CLIPBOARD_MAX_BYTES);
            };
            let live = Live::connect(t, host, true)?;
            if live.caps & caps::CLIPBOARD_TO_HOST == 0 {
                bail!("host did not negotiate clipboard sync to the host (needs --clipboard on the host, and not --view-only)");
            }
            let n = clean.len();
            live.send(ViewerMsg::Clipboard { text: clean })?;
            live.sync(Duration::from_secs(5))?;
            Ok(Output { json: json!({"bytes": n}), png: None })
        }
    }
}

/// Map a pixel coordinate inside `dim` pixels onto the wire's 0..=NORM_MAX range.
pub fn norm(v: u32, dim: u32) -> u16 {
    if dim <= 1 {
        return 0;
    }
    let v = v.min(dim - 1) as u64;
    ((v * NORM_MAX as u64 + (dim as u64 - 1) / 2) / (dim as u64 - 1)) as u16
}

// ------------------------------------------------------------------ audit + kill switch

pub fn kill_switch(dir: &Path) -> Option<String> {
    if let Some(v) = std::env::var_os(KILL_NAME) {
        let v = v.to_string_lossy().trim().to_ascii_lowercase();
        if !v.is_empty() && v != "0" && v != "false" {
            return Some(format!("{KILL_NAME} is set: input tools are disabled"));
        }
    }
    let f = dir.join(KILL_NAME);
    if f.exists() {
        return Some(format!("kill switch file {} exists: input tools are disabled", f.display()));
    }
    None
}

pub fn audit(dir: &Path, source: &str, a: &Action, tail: &str) {
    let host = a.host().unwrap_or("-").replace(['"', '\n', ' '], "_");
    let line = format!(
        "{} agent=\"{source}\" action={} host=\"{host}\" {} {tail}\n",
        crate::host::unix_time(),
        a.name(),
        a.audit_detail()
    );
    crate::host::write_audit(&dir.join("audit.log"), &line);
}

// ------------------------------------------------------------------ machines

/// One pinned host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    pub label: String,
    pub fingerprint: String,
}

/// Parse `<config>/known_hosts` (no network). A missing file is an empty list.
pub fn known_machines(dir: &Path) -> Result<Vec<Machine>> {
    let path = dir.join("known_hosts");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow!("reading {}: {e}", path.display())),
    };
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut it = line.split_whitespace();
        let (Some(label), Some(key)) = (it.next(), it.next()) else { continue };
        let Ok(bytes) = data_encoding::HEXLOWER_PERMISSIVE.decode(key.as_bytes()) else { continue };
        if bytes.len() != 32 {
            continue;
        }
        out.push(Machine { label: label.to_string(), fingerprint: fd_crypto::fingerprint(&bytes) });
    }
    Ok(out)
}

fn machines(dir: &Path, allow: Option<&[String]>) -> Result<Value> {
    let list: Vec<Value> = known_machines(dir)?
        .into_iter()
        .map(|m| {
            let name = m.label.rsplit_once(':').map(|(n, _)| n.to_string()).unwrap_or_else(|| m.label.clone());
            let mut v = json!({"name": name, "addr": m.label, "fingerprint": m.fingerprint});
            if let Some(allow) = allow {
                v["allowed"] = json!(allow.contains(&normalize_fingerprint(&m.fingerprint)));
            }
            v
        })
        .collect();
    Ok(json!({"machines": list, "known_hosts": dir.join("known_hosts").display().to_string()}))
}

/// Pre-network pin policy: the host must be pinned (or its fingerprint given), and in the allowlist.
fn precheck(t: &Target, host: &str) -> Result<()> {
    let (h, port) = viewer::split_host(host.trim());
    let label = format!("{h}:{port}").to_ascii_lowercase();
    let pinned = known_machines(t.dir)?.into_iter().find(|m| m.label == label);
    match (&pinned, &t.expect_fp) {
        (None, None) => bail!(
            "host {host} is not pinned and no fingerprint was given: refusing to trust it implicitly. \
             Pass --expect-fingerprint (read it off the host with `freedomdesk id`), or pin it once with `freedomdesk view`"
        ),
        (Some(m), Some(exp)) if normalize_fingerprint(exp) != normalize_fingerprint(&m.fingerprint) => {
            bail!("expected fingerprint {exp} does not match the pinned one for {host}")
        }
        _ => {}
    }
    if let (Some(m), Some(allow)) = (&pinned, &t.allow) {
        if !allow.contains(&normalize_fingerprint(&m.fingerprint)) {
            bail!("host {host} ({}) is not in the agent allowlist (agent.toml allow_hosts)", m.fingerprint);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ live session

struct AgentUi {
    allow: Option<Vec<String>>,
}

impl ConnectUi for AgentUi {
    fn status(&mut self, msg: &str) {
        log::debug!("{msg}");
    }
    fn trust(&mut self, _p: &TrustPrompt) -> bool {
        false // never trust-on-first-use from an agent
    }
    fn check_peer(&mut self, fp: &str) -> std::result::Result<(), String> {
        match &self.allow {
            Some(a) if !a.contains(&normalize_fingerprint(fp)) => {
                Err(format!("host {fp} is not in the agent allowlist (agent.toml allow_hosts); nothing was sent to it"))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Default)]
struct State {
    frame: Option<fd_codec::DecodedFrame>,
    clip: Option<String>,
    sync_seen: bool,
    ended: Option<String>,
}

type Shared = Arc<(Mutex<State>, Condvar)>;

pub struct Live {
    tx: Option<Sender<ViewerMsg>>,
    writer: Option<JoinHandle<()>>,
    reader: Option<JoinHandle<()>>,
    shared: Shared,
    shutdown: ShutdownHandle,
    host_name: String,
    fingerprint: String,
    addr: String,
    screen: (u32, u32),
    video: (u32, u32),
    pub caps: u32,
}

impl Live {
    fn connect(t: &Target, host: &str, clipboard: bool) -> Result<Live> {
        precheck(t, host)?;
        let opts = ConnectOpts {
            host: host.to_string(),
            expect_fingerprint: t.expect_fp.clone(),
            name: Some(format!("agent@{}", crate::host::hostname())),
            clipboard,
        };
        let conn = viewer::connect(t.dir, &opts, &mut AgentUi { allow: t.allow.clone() })?;
        let (host_name, fingerprint) = (conn.host_name.clone(), conn.host_fingerprint.clone());
        let (screen, video, caps) = (conn.screen_size(), conn.video_size(), conn.clipboard_caps());
        let (mut reader, writer) = conn.into_parts();
        let shutdown = writer.shutdown_handle()?;
        let (tx, rx) = mpsc::channel::<ViewerMsg>();
        let writer = viewer::spawn_writer(writer, rx, Instant::now());
        let shared: Shared = Arc::new((Mutex::new(State::default()), Condvar::new()));
        let (sh, rtx) = (shared.clone(), tx.clone());
        let reader = std::thread::Builder::new().name("agent-reader".into()).spawn(move || {
            let mut dec = viewer::GatedDecoder::new().ok();
            let end = |why: String| {
                let (m, cv) = &*sh;
                if let Ok(mut s) = m.lock() {
                    s.ended.get_or_insert(why);
                }
                cv.notify_all();
            };
            loop {
                let msg = match reader.recv().and_then(|b| fd_proto::decode::<HostMsg>(&b)) {
                    Ok(m) => m,
                    Err(e) => return end(format!("{e:#}")),
                };
                let (m, cv) = &*sh;
                match msg {
                    HostMsg::Video { data, keyframe, .. } => {
                        if let Some(f) = dec.as_mut().and_then(|d| d.decode(&data, keyframe, &rtx)) {
                            if let Ok(mut s) = m.lock() {
                                s.frame = Some(f);
                            }
                            cv.notify_all();
                        }
                    }
                    HostMsg::Clipboard { text } => {
                        if let Ok(mut s) = m.lock() {
                            s.clip = crate::clipboard::sanitize(&text);
                        }
                        cv.notify_all();
                    }
                    HostMsg::Pong { ts_us } if ts_us == SYNC_TS => {
                        if let Ok(mut s) = m.lock() {
                            s.sync_seen = true;
                        }
                        cv.notify_all();
                    }
                    HostMsg::Bye { reason } => return end(format!("host ended session: {}", viewer::clean(&reason))),
                    _ => {}
                }
            }
        })?;
        let (h, p) = viewer::split_host(host.trim());
        Ok(Live {
            tx: Some(tx),
            writer: Some(writer),
            reader: Some(reader),
            shared,
            shutdown,
            host_name,
            fingerprint,
            addr: format!("{h}:{p}"),
            screen,
            video,
            caps,
        })
    }

    fn info(&self) -> Value {
        json!({
            "host_name": self.host_name,
            "addr": self.addr,
            "fingerprint": self.fingerprint,
            "screen": {"width": self.screen.0, "height": self.screen.1},
            "video": {"width": self.video.0, "height": self.video.1},
            "clipboard": {
                "to_host": self.caps & caps::CLIPBOARD_TO_HOST != 0,
                "to_viewer": self.caps & caps::CLIPBOARD_TO_VIEWER != 0,
            },
        })
    }

    fn send(&self, m: ViewerMsg) -> Result<()> {
        if let Some(why) = self.shared.0.lock().ok().and_then(|s| s.ended.clone()) {
            bail!("session ended: {why}");
        }
        self.tx.as_ref().ok_or_else(|| anyhow!("closed"))?.send(m).map_err(|_| anyhow!("connection to host lost"))
    }

    fn tap(&self, keysym: u32) -> Result<()> {
        self.send(ViewerMsg::Input(InputEvent::Key { keysym, down: true }))?;
        std::thread::sleep(Duration::from_millis(10));
        self.send(ViewerMsg::Input(InputEvent::Key { keysym, down: false }))
    }

    /// Ping and wait for the pong: everything sent before has been read by the host.
    fn sync(&self, timeout: Duration) -> Result<()> {
        self.send(ViewerMsg::Ping { ts_us: SYNC_TS })?;
        let (m, cv) = &*self.shared;
        let g = m.lock().map_err(|_| anyhow!("poisoned"))?;
        let (g, res) = cv.wait_timeout_while(g, timeout, |s| !s.sync_seen && s.ended.is_none()).map_err(|_| anyhow!("poisoned"))?;
        if let Some(why) = &g.ended {
            bail!("session ended: {why}");
        }
        if res.timed_out() {
            bail!("host did not acknowledge within {}s", timeout.as_secs());
        }
        Ok(())
    }

    fn wait_frame(&self, timeout: Duration) -> Result<(u32, u32)> {
        let (m, cv) = &*self.shared;
        let g = m.lock().map_err(|_| anyhow!("poisoned"))?;
        let (g, _) = cv.wait_timeout_while(g, timeout, |s| s.frame.is_none() && s.ended.is_none()).map_err(|_| anyhow!("poisoned"))?;
        match (&g.frame, &g.ended) {
            (Some(f), _) => Ok((f.width, f.height)),
            (None, Some(why)) => bail!("session ended before a frame arrived: {why}"),
            (None, None) => bail!("no frame within {}s (is the host's screen available?)", timeout.as_secs()),
        }
    }

    /// Size of the picture coordinates refer to: the first decoded frame, else the
    /// size announced in `Welcome`.
    fn frame_dims(&self, timeout: Duration) -> (u32, u32) {
        self.wait_frame(timeout.min(Duration::from_secs(5))).unwrap_or(self.video)
    }

    fn screenshot(&self, timeout: Duration) -> Result<(u32, u32, Vec<u8>)> {
        self.wait_frame(timeout)?;
        let g = self.shared.0.lock().map_err(|_| anyhow!("poisoned"))?;
        let f = g.frame.as_ref().ok_or_else(|| anyhow!("no frame"))?;
        Ok((f.width, f.height, f.rgba.clone()))
    }

    fn wait_clipboard(&self, timeout: Duration) -> Option<String> {
        let (m, cv) = &*self.shared;
        let g = m.lock().ok()?;
        let (g, _) = cv.wait_timeout_while(g, timeout, |s| s.clip.is_none() && s.ended.is_none()).ok()?;
        g.clip.clone()
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(ViewerMsg::Bye);
        }
        if let Some(h) = self.writer.take() {
            let _ = h.join();
        }
        self.shutdown.shutdown();
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
    }
}

// ------------------------------------------------------------------ PNG

/// Encode tightly packed RGBA8 as an RGB PNG (alpha dropped: screens are opaque).
pub fn encode_png(w: u32, h: u32, rgba: &[u8]) -> Result<Vec<u8>> {
    if w == 0 || h == 0 || rgba.len() != w as usize * h as usize * 4 {
        bail!("bad picture: {w}x{h} with {} bytes", rgba.len());
    }
    let mut rgb = Vec::with_capacity(w as usize * h as usize * 3);
    for px in rgba.chunks(4) {
        rgb.extend_from_slice(&px[..3]);
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_compression(png::Compression::Fast);
        let mut wr = enc.write_header()?;
        wr.write_image_data(&rgb)?;
        wr.finish()?;
    }
    Ok(out)
}

// ------------------------------------------------------------------ key combos

#[derive(Debug, PartialEq, Eq)]
pub struct Combo {
    /// Modifier keysyms, pressed in this order and released in reverse.
    pub mods: Vec<u32>,
    pub key: u32,
    /// The key is a single printable character.
    pub printable: bool,
}

const SHIFT: u32 = 0xffe1;
const CTRL: u32 = 0xffe3;
const ALT: u32 = 0xffe9;
const SUPER: u32 = 0xffeb;

/// Parse `ctrl+alt+Delete`, `shift+Tab`, `ctrl+c`, `F5`, `super+l`, `ctrl++` …
pub fn parse_combo(s: &str) -> Result<Combo> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty key combo");
    }
    let (head, last) = if s == "+" {
        ("", "+")
    } else if let Some(h) = s.strip_suffix("++") {
        (h, "+")
    } else {
        match s.rsplit_once('+') {
            Some((h, l)) => (h, l),
            None => ("", s),
        }
    };
    let mut mods = Vec::new();
    for m in head.split('+').map(str::trim).filter(|m| !m.is_empty()) {
        let k = match m.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => CTRL,
            "alt" | "option" => ALT,
            "shift" => SHIFT,
            "super" | "meta" | "win" | "windows" | "cmd" | "command" => SUPER,
            other => bail!("unknown modifier {other:?} (ctrl, alt, shift, super)"),
        };
        if mods.contains(&k) {
            bail!("modifier {m:?} given twice");
        }
        mods.push(k);
    }
    let last = last.trim();
    let mut chars = last.chars();
    let (key, printable) = match (chars.next(), chars.next()) {
        (Some(c), None) => {
            if c.is_control() {
                bail!("control character in key combo");
            }
            let lower = c.to_lowercase().next().unwrap_or(c);
            if lower != c && !mods.contains(&SHIFT) {
                mods.push(SHIFT); // "A" means shift+a
            }
            (if (lower as u32) < 0x100 { lower as u32 } else { 0x0100_0000 + lower as u32 }, true)
        }
        _ => (named_key(last)?, false),
    };
    Ok(Combo { mods, key, printable })
}

fn named_key(name: &str) -> Result<u32> {
    let l = name.to_ascii_lowercase();
    Ok(match l.as_str() {
        "enter" | "return" => 0xff0d,
        "esc" | "escape" => 0xff1b,
        "tab" => 0xff09,
        "backspace" => 0xff08,
        "delete" | "del" => 0xffff,
        "insert" | "ins" => 0xff63,
        "home" => 0xff50,
        "end" => 0xff57,
        "pageup" | "pgup" | "page_up" => 0xff55,
        "pagedown" | "pgdn" | "page_down" => 0xff56,
        "up" => 0xff52,
        "down" => 0xff54,
        "left" => 0xff51,
        "right" => 0xff53,
        "space" => 0x20,
        "print" | "printscreen" => 0xff61,
        _ => {
            if let Some(n) = l.strip_prefix('f').and_then(|n| n.parse::<u32>().ok()).filter(|n| (1..=12).contains(n)) {
                0xffbe + n - 1
            } else {
                bail!("unknown key {name:?} (single character, F1-F12, Enter, Escape, Tab, Backspace, Delete, Home, End, PageUp, PageDown, Up, Down, Left, Right, Space)")
            }
        }
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fd-agent-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn combos() {
        let c = parse_combo("ctrl+alt+Delete").unwrap();
        assert_eq!(c, Combo { mods: vec![CTRL, ALT], key: 0xffff, printable: false });
        assert_eq!(parse_combo("Return").unwrap().key, 0xff0d);
        assert_eq!(parse_combo("f5").unwrap().key, 0xffc2);
        assert_eq!(parse_combo("F12").unwrap().key, 0xffc9);
        let c = parse_combo("Ctrl+C").unwrap();
        assert_eq!((c.mods.clone(), c.key), (vec![CTRL, SHIFT], 'c' as u32));
        let c = parse_combo("super+l").unwrap();
        assert_eq!((c.mods, c.key, c.printable), (vec![SUPER], 'l' as u32, true));
        assert_eq!(parse_combo("ctrl++").unwrap(), Combo { mods: vec![CTRL], key: '+' as u32, printable: true });
        assert_eq!(parse_combo("+").unwrap().key, '+' as u32);
        assert_eq!(parse_combo("ж").unwrap().key, 0x0100_0000 + 'ж' as u32);
        assert_eq!(parse_combo("é").unwrap().key, 0xe9);
    }

    #[test]
    fn bad_combos() {
        for bad in ["", "ctrl+", "ctrl+ctrl+a", "hyper+a", "ctrl+Foo", "f13", "ctrl+\n"] {
            assert!(parse_combo(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn normalisation_covers_the_edges() {
        assert_eq!(norm(0, 1920), 0);
        assert_eq!(norm(1919, 1920), NORM_MAX);
        assert_eq!(norm(5000, 1920), NORM_MAX);
        let mid = norm(960, 1920) as i64;
        assert!((mid - 32785).abs() < 40);
        assert_eq!(norm(3, 1), 0);
    }

    #[test]
    fn png_roundtrip() {
        let (w, h) = (5u32, 3u32);
        let rgba: Vec<u8> = (0..w * h).flat_map(|i| [i as u8, 2 * i as u8, 255 - i as u8, 255]).collect();
        let png = encode_png(w, h, &rgba).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let dec = png::Decoder::new(std::io::Cursor::new(&png));
        let mut r = dec.read_info().unwrap();
        let mut buf = vec![0; r.output_buffer_size().unwrap()];
        let info = r.next_frame(&mut buf).unwrap();
        assert_eq!((info.width, info.height, info.color_type), (w, h, png::ColorType::Rgb));
        for (i, px) in buf[..info.buffer_size()].chunks(3).enumerate() {
            assert_eq!(px, &rgba[i * 4..i * 4 + 3]);
        }
        assert!(encode_png(2, 2, &[0; 3]).is_err());
        assert!(encode_png(0, 2, &[]).is_err());
    }

    #[test]
    fn audit_never_contains_typed_text_or_clipboard() {
        let t = Action::Type { host: "h".into(), text: "hunter2-secret".into() };
        let c = Action::ClipboardSet { host: "h".into(), text: "clip-secret".into() };
        let k = Action::Key { host: "h".into(), combo: "p".into() };
        for a in [&t, &c, &k] {
            let d = a.audit_detail();
            assert!(!d.contains("secret") && !d.contains("hunter") && !d.contains("=p"), "{d}");
        }
        assert_eq!(t.audit_detail(), "chars=14");
        assert_eq!(c.audit_detail(), "bytes=11");
    }

    #[test]
    fn machines_listing_and_precheck() {
        let dir = tempdir("machines");
        let key = [7u8; 32];
        std::fs::write(dir.join("known_hosts"), format!("# c\nbox:47801 {}\nbad line\n", data_encoding::HEXLOWER.encode(&key))).unwrap();
        let m = known_machines(&dir).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].label, "box:47801");
        let fp = m[0].fingerprint.clone();
        let j = machines(&dir, Some(&[normalize_fingerprint(&fp)])).unwrap();
        assert_eq!(j["machines"][0]["name"], "box");
        assert_eq!(j["machines"][0]["allowed"], true);
        let t = |expect: Option<&str>, allow: Option<Vec<String>>| Target {
            dir: &dir,
            expect_fp: expect.map(String::from),
            allow,
            timeout: Duration::from_secs(1),
            source: "test",
        };
        assert!(precheck(&t(None, None), "box").is_ok());
        assert!(precheck(&t(None, None), "other").unwrap_err().to_string().contains("not pinned"));
        assert!(precheck(&t(Some("AAAA-AAAA"), None), "box").is_err());
        assert!(precheck(&t(None, Some(vec![])), "box").unwrap_err().to_string().contains("allowlist"));
        assert!(precheck(&t(None, Some(vec![normalize_fingerprint(&fp)])), "box").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kill_switch_file() {
        let dir = tempdir("kill");
        assert!(kill_switch(&dir).is_none());
        std::fs::write(dir.join(KILL_NAME), "").unwrap();
        assert!(kill_switch(&dir).unwrap().contains("kill switch"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
