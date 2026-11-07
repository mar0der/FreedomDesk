//! `freedomdesk service`: root supervisor for a systemd system unit (H1).
//!
//! It follows the active console session on seat0, whether that is the GDM
//! greeter (user `gdm`) or a logged-in desktop. For each one it runs
//! `freedomdesk host` as that session's own uid with its DISPLAY/XAUTHORITY.
//! When the console session changes it stops the old host and starts a new one.
//!
//! Only the supervisor runs as root, and it never parses network input. The
//! identity key stays root-only (`<config>/identity.key`, 0600) and reaches the
//! host on a pipe. The host reads `<config>/authorized_viewers` (must be
//! world-readable: it holds public fingerprints only) and audits to stderr
//! (journald).

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(clap::Args)]
pub struct ServiceArgs {
    /// Extra arguments for `freedomdesk host`, after `--` (e.g. `-- --bind 100.x.y.z`).
    #[arg(last = true)]
    host_args: Vec<String>,
}

/// The console session we serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Console {
    pub session: String,
    pub class: String,
    pub uid: u32,
    pub gid: u32,
    pub user: String,
    pub home: PathBuf,
    pub display: String,
    pub xauthority: Option<PathBuf>,
}

const POLL: Duration = Duration::from_secs(1);
const RESTART_BACKOFF: Duration = Duration::from_secs(3);
const STOP_GRACE: Duration = Duration::from_secs(5);

pub fn run(dir: &Path, args: ServiceArgs) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("`freedomdesk service` must run as root (systemd system unit); use `freedomdesk host` for a per-user host");
    }
    let identity = fd_crypto::Identity::load(&dir.join("identity.key"))
        .with_context(|| format!("loading {}/identity.key (create it with `freedomdesk --config-dir {} id`)", dir.display(), dir.display()))?;
    log::info!("FreedomDesk service: host fingerprint {}", identity.fingerprint());
    let key = identity.to_text();
    let exe = std::env::current_exe().context("locating own executable")?;

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst)).context("signal handler")?;
    }

    let mut current: Option<(Console, Child)> = None;
    let mut last_start = Instant::now() - RESTART_BACKOFF;
    let mut last_none_log: Option<String> = None;
    while !stop.load(Ordering::SeqCst) {
        let want = match active_console() {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("{e:#}");
                if last_none_log.as_deref() != Some(&msg) {
                    log::info!("no console to serve: {msg}");
                    last_none_log = Some(msg);
                }
                None
            }
        };
        if want.is_some() {
            last_none_log = None;
        }

        // Child ended by itself (crash, X server gone, bind failed …)?
        if let Some((c, child)) = &mut current {
            if let Ok(Some(st)) = child.try_wait() {
                log::warn!("host for session {} ({}) exited: {st}", c.session, c.user);
                current = None;
            }
        }
        // Console changed: stop the old host.
        if current.as_ref().map(|(c, _)| c) != want.as_ref() {
            if let Some((c, child)) = current.take() {
                log::info!("console changed; stopping host for session {} ({})", c.session, c.user);
                stop_child(child);
            }
        }
        if current.is_none() && last_start.elapsed() >= RESTART_BACKOFF {
            if let Some(c) = want {
                last_start = Instant::now();
                match start_host(&exe, dir, &c, &args.host_args, &key) {
                    Ok(child) => {
                        log::info!(
                            "serving session {} ({}, {}) on {} as uid {}",
                            c.session, c.class, c.user, c.display, c.uid
                        );
                        current = Some((c, child));
                    }
                    Err(e) => log::warn!("could not start host for session {}: {e:#}", c.session),
                }
            }
        }
        std::thread::sleep(POLL);
    }
    if let Some((_, child)) = current {
        stop_child(child);
    }
    log::info!("FreedomDesk service stopped");
    Ok(())
}

fn start_host(exe: &Path, dir: &Path, c: &Console, extra: &[String], key: &str) -> Result<Child> {
    let mut cmd = Command::new(exe);
    cmd.arg("--config-dir")
        .arg(dir)
        .arg("host")
        .arg("--identity-stdin")
        .arg("--audit-log")
        .arg("-")
        .args(extra)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", &c.home)
        .env("USER", &c.user)
        .env("LOGNAME", &c.user)
        .env("DISPLAY", &c.display)
        .env("XDG_RUNTIME_DIR", format!("/run/user/{}", c.uid))
        .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .current_dir("/")
        .stdin(Stdio::piped())
        // Drops supplementary groups too (std calls setgroups when uid is set as root).
        .uid(c.uid)
        .gid(c.gid);
    if let Some(x) = &c.xauthority {
        cmd.env("XAUTHORITY", x);
    }
    let mut child = cmd.spawn().context("spawning host")?;
    let mut stdin = child.stdin.take().context("host stdin")?;
    if let Err(e) = stdin.write_all(key.as_bytes()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e).context("handing identity to host");
    }
    drop(stdin);
    Ok(child)
}

/// SIGTERM (the host releases held keys and says Bye), then SIGKILL.
fn stop_child(mut child: Child) {
    let pid = child.id() as libc::pid_t;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let t = Instant::now();
    while t.elapsed() < STOP_GRACE {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    log::warn!("host {pid} did not stop in {STOP_GRACE:?}; killing");
    let _ = child.kill();
    let _ = child.wait();
}

// ------------------------------------------------------------ console discovery

fn loginctl(args: &[&str]) -> Result<String> {
    let out = Command::new("loginctl").args(args).output().context("running loginctl")?;
    if !out.status.success() {
        bail!("loginctl {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn props(text: &str) -> std::collections::HashMap<String, String> {
    text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// The active seat0 session, if it is an X11 session we can serve.
pub fn active_console() -> Result<Option<Console>> {
    let seat = props(&loginctl(&["show-seat", "seat0", "-p", "ActiveSession"])?);
    let Some(session) = seat.get("ActiveSession").filter(|s| !s.is_empty()).cloned() else {
        return Ok(None);
    };
    if !session.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("odd session id {session:?}");
    }
    let p = props(&loginctl(&["show-session", &session, "-p", "Type", "-p", "Class", "-p", "User", "-p", "Name", "-p", "State"])?);
    let ty = p.get("Type").map(String::as_str).unwrap_or("");
    if ty != "x11" {
        bail!("session {session} is {ty:?}; only X11 sessions are supported (H5 = Wayland)");
    }
    let uid: u32 = p.get("User").and_then(|u| u.parse().ok()).context("session has no uid")?;
    let class = p.get("Class").cloned().unwrap_or_default();
    let (user, home, gid) = passwd(uid)?;
    let (display, xauthority) = session_display(&session, uid)?.with_context(|| format!("no X display found in session {session}"))?;
    Ok(Some(Console { session, class, uid, gid, user, home, display, xauthority }))
}

fn passwd(uid: u32) -> Result<(String, PathBuf, u32)> {
    let mut buf = vec![0u8; 16384];
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut res) };
    if rc != 0 || res.is_null() {
        bail!("no passwd entry for uid {uid}");
    }
    let s = |p: *const libc::c_char| unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned();
    Ok((s(pw.pw_name), PathBuf::from(s(pw.pw_dir)), pw.pw_gid))
}

/// DISPLAY / XAUTHORITY from a process of `uid` inside the session's scope.
/// gnome-shell is preferred; any process with DISPLAY will do.
fn session_display(session: &str, uid: u32) -> Result<Option<(String, Option<PathBuf>)>> {
    let scope = format!("/session-{session}.scope");
    let mut best: Option<(bool, String, Option<PathBuf>)> = None;
    for e in std::fs::read_dir("/proc")?.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().filter(|s| s.bytes().all(|b| b.is_ascii_digit())) else { continue };
        let base = Path::new("/proc").join(pid);
        let Ok(cg) = std::fs::read_to_string(base.join("cgroup")) else { continue };
        if !cg.lines().any(|l| l.ends_with(&scope)) {
            continue;
        }
        if proc_uid(&base) != Some(uid) {
            continue;
        }
        let Ok(env) = std::fs::read(base.join("environ")) else { continue };
        let (mut display, mut xauth) = (None, None);
        for kv in env.split(|b| *b == 0) {
            let kv = String::from_utf8_lossy(kv);
            if let Some(v) = kv.strip_prefix("DISPLAY=") {
                display = Some(v.to_string());
            } else if let Some(v) = kv.strip_prefix("XAUTHORITY=") {
                xauth = Some(PathBuf::from(v));
            }
        }
        let Some(display) = display.filter(|d| valid_local_display(d)) else { continue };
        let xauth = xauth.filter(|p| p.is_absolute());
        let comm = std::fs::read_to_string(base.join("comm")).unwrap_or_default();
        let preferred = comm.trim() == "gnome-shell";
        if best.as_ref().is_none_or(|b| !b.0 && (preferred || (b.2.is_none() && xauth.is_some()))) {
            best = Some((preferred, display, xauth));
        }
    }
    Ok(best.map(|(_, d, x)| (d, x)))
}

fn proc_uid(base: &Path) -> Option<u32> {
    let st = std::fs::read_to_string(base.join("status")).ok()?;
    let line = st.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Only local displays like `:0` or `:1024.0`: never a TCP display.
pub fn valid_local_display(d: &str) -> bool {
    let Some(rest) = d.strip_prefix(':') else { return false };
    let (num, screen) = rest.split_once('.').unwrap_or((rest, "0"));
    !num.is_empty() && num.len() <= 5 && num.bytes().all(|b| b.is_ascii_digit()) && !screen.is_empty() && screen.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays() {
        assert!(valid_local_display(":0"));
        assert!(valid_local_display(":1024.0"));
        assert!(!valid_local_display("evil.example:0"));
        assert!(!valid_local_display(":"));
        assert!(!valid_local_display(":0.x"));
        assert!(!valid_local_display("unix:0"));
    }

    #[test]
    fn props_parse() {
        let p = props("Type=x11\nUser=1000\nName=petar\n");
        assert_eq!(p["Type"], "x11");
        assert_eq!(p["User"], "1000");
    }
}
