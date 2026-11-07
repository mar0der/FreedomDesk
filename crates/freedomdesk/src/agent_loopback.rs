//! Loopback integration test for the agent operations.
//!
//! The "host" here is a small in-test stand-in that speaks the real wire protocol
//! (Noise handshake, Hello/Welcome with capability negotiation, H.264 video from the
//! real encoder, input/clipboard/ping handling). It is NOT `host.rs`: the repo's host
//! always captures a real X display and has no fake-capture seam, so this test
//! proves the agent side end to end but not the real host's input injection.

use crate::agent::{self, Action, Target};
use fd_crypto::Identity;
use fd_proto::{caps, HostMsg, InputEvent, MouseButton, Rect, ViewerMsg, PROTOCOL_VERSION};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const W: u32 = 640;
const H: u32 = 360;

#[derive(Clone, Default)]
struct Seen {
    inputs: Arc<Mutex<Vec<InputEvent>>>,
    clipboard: Arc<Mutex<Vec<String>>>,
    hellos: Arc<Mutex<Vec<(String, u32)>>>,
}

struct FakeHost {
    addr: String,
    fp: String,
    seen: Seen,
}

fn spawn_host(clipboard: bool) -> FakeHost {
    let id = Identity::generate().unwrap();
    let fp = id.fingerprint();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = Seen::default();
    let s = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let _ = serve(stream, &id, clipboard, &s); // aborted sessions (e.g. allowlist) are fine
        }
    });
    FakeHost { addr, fp, seen }
}

fn serve(stream: std::net::TcpStream, id: &Identity, clipboard: bool, seen: &Seen) -> anyhow::Result<()> {
    let mut sess = fd_crypto::accept(stream, id)?;
    let ViewerMsg::Hello { viewer_name, caps: want, .. } = fd_proto::decode_viewer(&sess.reader.recv()?)? else { anyhow::bail!("no hello") };
    seen.hellos.lock().unwrap().push((viewer_name, want));
    let negotiated = caps::negotiate(want, if clipboard { caps::KNOWN } else { 0 });
    let send = |w: &mut fd_crypto::SecureWriter, m: &HostMsg| w.send(&fd_proto::encode(m).unwrap());
    send(&mut sess.writer, &HostMsg::Welcome { protocol: PROTOCOL_VERSION, host_name: "fakehost".into(), screen_width: W, screen_height: H, video_width: W, video_height: H, caps: negotiated })?;
    // A solid red picture through the real H.264 encoder.
    let mut data = vec![0u8; (W * H * 4) as usize];
    for px in data.chunks_mut(4) {
        px.copy_from_slice(&[30, 30, 200, 0]); // BGRX
    }
    let frame = fd_capture::Frame { width: W, height: H, stride: (W * 4) as usize, data };
    let mut enc = fd_codec::VideoEncoder::new(W, H, fd_codec::EncoderConfig::default())?;
    let mut unit = None;
    for _ in 0..20 {
        if let Some(u) = enc.encode(&frame, true)? {
            unit = Some(u);
            break;
        }
    }
    let unit = unit.ok_or_else(|| anyhow::anyhow!("encoder produced nothing"))?;
    send(&mut sess.writer, &HostMsg::Video { seq: 0, keyframe: unit.keyframe, ts_us: 0, region: Rect { x: 0, y: 0, w: W, h: H }, screen_width: W, screen_height: H, data: unit.data })?;
    if negotiated & caps::CLIPBOARD_TO_VIEWER != 0 {
        send(&mut sess.writer, &HostMsg::Clipboard { text: "from the host".into() })?;
    }
    loop {
        match fd_proto::decode_viewer(&sess.reader.recv()?)? {
            ViewerMsg::Input(ev) => seen.inputs.lock().unwrap().push(ev),
            ViewerMsg::Clipboard { text } => seen.clipboard.lock().unwrap().push(text),
            ViewerMsg::Ping { ts_us } => send(&mut sess.writer, &HostMsg::Pong { ts_us })?,
            ViewerMsg::Bye => return Ok(()),
            _ => {}
        }
    }
}

fn target<'a>(dir: &'a std::path::Path, fp: Option<&str>, allow: Option<Vec<String>>) -> Target<'a> {
    Target { dir, expect_fp: fp.map(String::from), allow, timeout: Duration::from_secs(20), source: "test" }
}

fn identity_of(dir: &std::path::Path) -> String {
    // The agent creates its identity on first connect; make it up front so we can name it.
    crate::load_identity(dir).unwrap().fingerprint()
}

#[test]
fn agent_against_a_loopback_host() {
    let dir = agent::tests::tempdir("loopback");
    let _ = identity_of(&dir);
    let host = spawn_host(false);

    // 1. Not pinned and no fingerprint: refused before any network traffic.
    let e = agent::execute(&target(&dir, None, None), &Action::Status { host: host.addr.clone() }).unwrap_err();
    assert!(e.to_string().contains("not pinned"), "{e:#}");
    assert!(host.seen.hellos.lock().unwrap().is_empty());

    // 2. A wrong fingerprint is refused and nothing is pinned.
    let e = agent::execute(&target(&dir, Some("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"), None), &Action::Status { host: host.addr.clone() }).unwrap_err();
    assert!(e.to_string().contains("MISMATCH"), "{e:#}");
    assert!(agent::known_machines(&dir).unwrap().is_empty());

    // 3. Screenshot with the right fingerprint: pins it, returns a decodable PNG of the picture.
    let out = agent::execute(&target(&dir, Some(&host.fp), None), &Action::Screenshot { host: host.addr.clone(), out: None, base64: false }).unwrap();
    assert_eq!((out.json["width"].as_u64(), out.json["height"].as_u64()), (Some(W as u64), Some(H as u64)));
    assert_eq!(out.json["host_name"], "fakehost");
    assert_eq!(out.json["fingerprint"], host.fp);
    let png = out.png.unwrap();
    let mut r = png::Decoder::new(std::io::Cursor::new(&png)).read_info().unwrap();
    let mut buf = vec![0; r.output_buffer_size().unwrap()];
    let info = r.next_frame(&mut buf).unwrap();
    assert_eq!((info.width, info.height), (W, H));
    let mid = ((H / 2 * W + W / 2) * 3) as usize;
    assert!(buf[mid] > 150 && buf[mid + 1] < 90 && buf[mid + 2] < 90, "centre pixel {:?} is not red", &buf[mid..mid + 3]);
    // The screenshot call offered no clipboard.
    assert_eq!(host.seen.hellos.lock().unwrap()[0].1, 0);

    // 4. machines lists the pin, no network needed.
    let m = agent::execute(&target(&dir, None, None), &Action::Machines).unwrap();
    assert_eq!(m.json["machines"][0]["fingerprint"], host.fp);

    // 5. Now pinned: input works without a fingerprint. Click the centre.
    agent::execute(&target(&dir, None, None), &Action::Click { host: host.addr.clone(), x: W / 2, y: H / 2, button: MouseButton::Right, double: true }).unwrap();
    {
        let ev = host.seen.inputs.lock().unwrap();
        let InputEvent::MouseMove { x, y } = ev[0] else { panic!("{ev:?}") };
        assert!((x as i32 - 32800).abs() < 80 && (y as i32 - 32800).abs() < 80, "{x},{y}");
        let btns: Vec<_> = ev[1..].iter().map(|e| matches!(e, InputEvent::MouseButton { button: MouseButton::Right, .. })).collect();
        assert_eq!(btns, vec![true; 4], "double click = 2 x (down, up): {ev:?}");
    }
    let e = agent::execute(&target(&dir, None, None), &Action::Click { host: host.addr.clone(), x: W, y: 0, button: MouseButton::Left, double: false }).unwrap_err();
    assert!(e.to_string().contains("outside"), "{e:#}");

    host.seen.inputs.lock().unwrap().clear();
    agent::execute(&target(&dir, None, None), &Action::Type { host: host.addr.clone(), text: "aж\n".into() }).unwrap();
    assert_eq!(
        *host.seen.inputs.lock().unwrap(),
        vec![InputEvent::Text { ch: 'a' }, InputEvent::Text { ch: 'ж' }, InputEvent::Key { keysym: 0xff0d, down: true }, InputEvent::Key { keysym: 0xff0d, down: false }]
    );
    host.seen.inputs.lock().unwrap().clear();
    agent::execute(&target(&dir, None, None), &Action::Key { host: host.addr.clone(), combo: "ctrl+alt+Delete".into() }).unwrap();
    let k: Vec<_> = host.seen.inputs.lock().unwrap().iter().map(|e| match e { InputEvent::Key { keysym, down } => (*keysym, *down), o => panic!("{o:?}") }).collect();
    assert_eq!(k, vec![(0xffe3, true), (0xffe9, true), (0xffff, true), (0xffff, false), (0xffe9, false), (0xffe3, false)]);

    // 6. Status is honest about what the protocol cannot tell.
    let st = agent::execute(&target(&dir, None, None), &Action::Status { host: host.addr.clone() }).unwrap();
    assert_eq!(st.json["login_or_lock_screen"], "unknown");
    assert_eq!(st.json["clipboard"]["to_host"], false);
    assert!(st.json["rtt_ms"].is_number());

    // 7. Host without --clipboard: clear errors, nothing written.
    for a in [
        Action::ClipboardGet { host: host.addr.clone(), wait: Duration::from_secs(1) },
        Action::ClipboardSet { host: host.addr.clone(), text: "x".into() },
    ] {
        let e = agent::execute(&target(&dir, None, None), &a).unwrap_err();
        assert!(e.to_string().contains("did not negotiate"), "{e:#}");
    }
    assert!(host.seen.clipboard.lock().unwrap().is_empty());

    // 8. Allowlist: a pinned host that is not allowed is refused without connecting.
    let before = host.seen.hellos.lock().unwrap().len();
    let other = vec![fd_crypto::normalize_fingerprint("ABCD-EFGH-IJKL-MNOP-QRST-UVWX")];
    let e = agent::execute(&target(&dir, None, Some(other.clone())), &Action::Status { host: host.addr.clone() }).unwrap_err();
    assert!(e.to_string().contains("allowlist"), "{e:#}");
    assert_eq!(host.seen.hellos.lock().unwrap().len(), before);
    let ok = vec![fd_crypto::normalize_fingerprint(&host.fp)];
    agent::execute(&target(&dir, None, Some(ok)), &Action::Status { host: host.addr.clone() }).unwrap();

    // 9. Every call left an audit line; none holds the typed text.
    let audit = std::fs::read_to_string(dir.join("audit.log")).unwrap();
    assert!(audit.contains("action=screenshot") && audit.contains("action=type") && audit.contains("chars=3") && audit.contains("outcome=error"), "{audit}");
    assert!(!audit.contains("aж"), "{audit}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowlist_is_enforced_before_hello_on_first_contact() {
    // First contact with a fingerprint given, but the host is not on the allowlist:
    // the handshake happens (to learn the key) but no Hello is ever sent.
    let dir = agent::tests::tempdir("loopback-allow");
    let host = spawn_host(false);
    let other = vec![fd_crypto::normalize_fingerprint("ABCD-EFGH-IJKL-MNOP-QRST-UVWX")];
    let e = agent::execute(&target(&dir, Some(&host.fp), Some(other)), &Action::Status { host: host.addr.clone() }).unwrap_err();
    assert!(e.to_string().contains("allowlist"), "{e:#}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(host.seen.hellos.lock().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clipboard_when_negotiated() {
    let dir = agent::tests::tempdir("loopback-clip");
    let host = spawn_host(true);
    let t = target(&dir, Some(&host.fp), None);
    let got = agent::execute(&t, &Action::ClipboardGet { host: host.addr.clone(), wait: Duration::from_secs(10) }).unwrap();
    assert_eq!(got.json["text"], "from the host");
    agent::execute(&target(&dir, None, None), &Action::ClipboardSet { host: host.addr.clone(), text: "to the host\r\n".into() }).unwrap();
    assert_eq!(*host.seen.clipboard.lock().unwrap(), vec!["to the host\n".to_string()]);
    let audit = std::fs::read_to_string(dir.join("audit.log")).unwrap();
    assert!(audit.contains("action=clipboard_set") && audit.contains("bytes=13") && !audit.contains("to the host"), "{audit}");
    let _ = std::fs::remove_dir_all(&dir);
}
