//! FreedomDesk cryptography: device identity, the Noise_XX secure channel and
//! TOFU key pinning.
//!
//! * Every device has a long-term X25519 static key ([`Identity`]), stored with
//!   0600 permissions. Its [`fingerprint`] is what humans compare.
//! * Sessions run `Noise_XX_25519_ChaChaPoly_BLAKE2s` over TCP: mutual
//!   authentication of static keys, forward secrecy via ephemerals, and
//!   AEAD on every byte after the handshake. Nothing is ever sent in cleartext
//!   apart from the Noise handshake messages themselves.
//! * Viewers pin host keys in a `known_hosts` file (trust on first use;
//!   a later mismatch is a hard failure).

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Bound into the handshake hash: peers speaking another protocol (or version) fail the handshake.
const PROLOGUE: &[u8] = b"FreedomDesk/noise/1";
const MAX_NOISE_MSG: usize = 65535;
const TAG_LEN: usize = 16;
/// Plaintext bytes per Noise transport message (1 byte is our continuation flag).
const CHUNK_PAYLOAD: usize = MAX_NOISE_MSG - TAG_LEN - 1;
/// Largest application message we will reassemble (anti memory-DoS).
pub const MAX_APP_MSG: usize = 32 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------- identity

/// A device's long-term static key pair.
pub struct Identity {
    private: Zeroizing<Vec<u8>>,
    public: [u8; 32],
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let kp = Builder::new(params())
            .generate_keypair()
            .map_err(|e| anyhow!("keygen: {e}"))?;
        let public: [u8; 32] = kp.public.as_slice().try_into()?;
        Ok(Self { private: Zeroizing::new(kp.private), public })
    }

    /// Load the identity at `path`, creating it (0600, parent dir 0700) if missing.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            return Self::load(path);
        }
        let id = Self::generate()?;
        if let Err(e) = id.save_new(path) {
            // Lost a creation race with another process: use its key.
            if path.exists() {
                return Self::load(path);
            }
            return Err(e);
        }
        log::info!("created new device identity at {}", path.display());
        Ok(id)
    }

    pub fn load(path: &Path) -> Result<Self> {
        check_private_perms(path)?;
        let text = Zeroizing::new(
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
        );
        let mut private = None;
        let mut public = None;
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("private=") {
                private = Some(Zeroizing::new(hex_decode(v.trim())?));
            } else if let Some(v) = line.strip_prefix("public=") {
                public = Some(hex_decode(v.trim())?);
            }
        }
        let private = private.ok_or_else(|| anyhow!("identity file missing private key"))?;
        let public = public.ok_or_else(|| anyhow!("identity file missing public key"))?;
        if private.len() != 32 || public.len() != 32 {
            bail!("identity file has malformed keys");
        }
        Ok(Self { private, public: public.as_slice().try_into()? })
    }

    /// Write to `path`, failing if it already exists (never clobbers a key).
    pub fn save_new(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        let body = self.serialize();
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path).with_context(|| format!("creating {}", path.display()))?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        write_private_file(path, self.serialize().as_bytes())
    }

    fn serialize(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "# FreedomDesk device identity. KEEP PRIVATE. Never commit or share this file.\n\
             private={}\npublic={}\n",
            hex_encode(&self.private),
            hex_encode(&self.public)
        ))
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }
}

/// Human-comparable fingerprint of a static public key:
/// first 120 bits of SHA-256, base32, in groups of 4 (e.g. `ABCD-EFGH-…`, 24 chars).
pub fn fingerprint(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    let b32 = data_encoding::BASE32_NOPAD.encode(&digest[..15]);
    b32.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

/// Normalise a user-typed fingerprint for comparison (case, spaces, dashes ignored).
pub fn normalize_fingerprint(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

fn params() -> snow::params::NoiseParams {
    NOISE_PARAMS.parse().expect("valid noise params")
}

// ---------------------------------------------------------------- handshake

/// Result of a completed handshake.
pub struct Session {
    pub reader: SecureReader,
    pub writer: SecureWriter,
    /// Authenticated static key of the peer. Callers MUST check it (pin / allow-list / consent).
    pub remote_public: [u8; 32],
}

impl Session {
    pub fn remote_fingerprint(&self) -> String {
        fingerprint(&self.remote_public)
    }
}

/// Run the initiator (viewer) side of Noise_XX on `stream`.
pub fn connect(stream: TcpStream, id: &Identity) -> Result<Session> {
    let hs = Builder::new(params())
        .local_private_key(&id.private)
        .and_then(|b| b.prologue(PROLOGUE))
        .and_then(|b| b.build_initiator())
        .map_err(|e| anyhow!("noise init: {e}"))?;
    run_handshake(stream, hs, true)
}

/// Run the responder (host) side of Noise_XX on `stream`.
pub fn accept(stream: TcpStream, id: &Identity) -> Result<Session> {
    let hs = Builder::new(params())
        .local_private_key(&id.private)
        .and_then(|b| b.prologue(PROLOGUE))
        .and_then(|b| b.build_responder())
        .map_err(|e| anyhow!("noise init: {e}"))?;
    run_handshake(stream, hs, false)
}

fn run_handshake(mut stream: TcpStream, mut hs: HandshakeState, initiator: bool) -> Result<Session> {
    stream.set_nodelay(true)?;
    // One deadline for the whole handshake: a peer trickling bytes can't hold us longer.
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut buf = vec![0u8; MAX_NOISE_MSG];
    let mut payload = vec![0u8; MAX_NOISE_MSG];
    // XX: -> e ; <- e, ee, s, es ; -> s, se
    let mut my_turn = initiator;
    while !hs.is_handshake_finished() {
        if my_turn {
            let n = hs.write_message(&[], &mut buf).map_err(|e| anyhow!("handshake write: {e}"))?;
            write_frame(&mut stream, &buf[..n])?;
        } else {
            let msg = read_frame(&mut stream, Some(deadline))?;
            hs.read_message(&msg, &mut payload).map_err(|e| anyhow!("handshake failed: {e}"))?;
        }
        my_turn = !my_turn;
    }
    let remote_public: [u8; 32] = hs
        .get_remote_static()
        .ok_or_else(|| anyhow!("peer sent no static key"))?
        .try_into()
        .map_err(|_| anyhow!("peer static key has wrong length"))?;
    let transport = Arc::new(
        hs.into_stateless_transport_mode().map_err(|e| anyhow!("noise transport: {e}"))?,
    );
    stream.set_read_timeout(None)?;
    // A peer that stops reading (laptop asleep, path gone) must not block a sender
    // forever while it holds locks: fail the write and end the session instead.
    stream.set_write_timeout(Some(SEND_TIMEOUT))?;
    let read_stream = stream.try_clone()?;
    Ok(Session {
        reader: SecureReader { stream: read_stream, transport: transport.clone(), nonce: 0 },
        writer: SecureWriter { stream, transport, nonce: 0 },
        remote_public,
    })
}

// ---------------------------------------------------------------- transport

/// Sending half. Messages are split into Noise frames of at most 64 KiB.
/// Wire: `[u16 BE length][ciphertext]`, plaintext = `[flag: 1=more, 0=last][chunk]`.
pub struct SecureWriter {
    stream: TcpStream,
    transport: Arc<StatelessTransportState>,
    nonce: u64,
}

/// Receiving half. Nonces must arrive strictly in sequence, so replayed,
/// reordered or dropped frames fail authentication and end the session.
pub struct SecureReader {
    stream: TcpStream,
    transport: Arc<StatelessTransportState>,
    nonce: u64,
}

impl SecureWriter {
    pub fn send(&mut self, msg: &[u8]) -> Result<()> {
        if msg.len() > MAX_APP_MSG {
            bail!("message too large ({} bytes)", msg.len());
        }
        let mut plain = Vec::with_capacity(CHUNK_PAYLOAD + 1);
        let mut cipher = vec![0u8; MAX_NOISE_MSG];
        let mut chunks = msg.chunks(CHUNK_PAYLOAD).peekable();
        if chunks.peek().is_none() {
            // Empty message still produces one (final) frame.
            return self.send_chunk(&mut plain, &mut cipher, &[], false);
        }
        while let Some(chunk) = chunks.next() {
            let more = chunks.peek().is_some();
            self.send_chunk(&mut plain, &mut cipher, chunk, more)?;
        }
        self.stream.flush()?;
        Ok(())
    }

    fn send_chunk(&mut self, plain: &mut Vec<u8>, cipher: &mut [u8], chunk: &[u8], more: bool) -> Result<()> {
        plain.clear();
        plain.push(more as u8);
        plain.extend_from_slice(chunk);
        let n = self
            .transport
            .write_message(self.nonce, plain, cipher)
            .map_err(|e| anyhow!("encrypt: {e}"))?;
        self.nonce = self.nonce.checked_add(1).ok_or_else(|| anyhow!("nonce exhausted"))?;
        write_frame(&mut self.stream, &cipher[..n])
    }

    /// Close the underlying socket in both directions (unblocks the reader too).
    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    /// A handle that can later shut the connection down from another thread.
    pub fn shutdown_handle(&self) -> Result<ShutdownHandle> {
        Ok(ShutdownHandle(self.stream.try_clone()?))
    }
}

/// Closes a session's socket (both directions) from any thread.
pub struct ShutdownHandle(TcpStream);

impl ShutdownHandle {
    pub fn shutdown(&self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

impl SecureReader {
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        self.recv_limited(MAX_APP_MSG, None)
    }

    /// Receive one message of at most `max_len` bytes, failing if it isn't
    /// complete by `deadline`. Use for anything read before the peer is authorised.
    pub fn recv_limited(&mut self, max_len: usize, deadline: Option<Instant>) -> Result<Vec<u8>> {
        let max_len = max_len.min(MAX_APP_MSG);
        let mut out = Vec::new();
        let mut plain = vec![0u8; MAX_NOISE_MSG];
        loop {
            let frame = read_frame(&mut self.stream, deadline)?;
            let n = self
                .transport
                .read_message(self.nonce, &frame, &mut plain)
                .map_err(|_| anyhow!("decryption failed (tampered or out-of-sequence data)"))?;
            self.nonce = self.nonce.checked_add(1).ok_or_else(|| anyhow!("nonce exhausted"))?;
            if n == 0 {
                bail!("malformed frame");
            }
            let more = match plain[0] {
                0 => false,
                1 => true,
                _ => bail!("malformed frame flag"),
            };
            if out.len() + n - 1 > max_len {
                bail!("peer message exceeds {max_len} bytes");
            }
            out.extend_from_slice(&plain[1..n]);
            if !more {
                return Ok(out);
            }
        }
    }

    /// Bound how long `recv` may block (None = forever).
    pub fn set_timeout(&self, t: Option<Duration>) -> Result<()> {
        self.stream.set_read_timeout(t)?;
        Ok(())
    }
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len: u16 = data.len().try_into().map_err(|_| anyhow!("frame too large"))?;
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    stream.write_all(&buf)?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream, deadline: Option<Instant>) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    read_exact_by(stream, &mut len, deadline)?;
    let len = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; len];
    read_exact_by(stream, &mut buf, deadline)?;
    Ok(buf)
}

/// `read_exact`, but with an absolute deadline across all the underlying reads.
fn read_exact_by(stream: &mut TcpStream, buf: &mut [u8], deadline: Option<Instant>) -> Result<()> {
    let Some(deadline) = deadline else {
        return stream.read_exact(buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                anyhow::Error::new(e).context("connection closed by the other side")
            } else {
                e.into()
            }
        });
    };
    let saved = stream.read_timeout()?;
    let r = read_exact_deadline(stream, buf, deadline);
    stream.set_read_timeout(saved)?;
    r
}

fn read_exact_deadline(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<()> {
    let mut done = 0;
    while done < buf.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            bail!("peer too slow (deadline exceeded)");
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut buf[done..]) {
            Ok(0) => bail!(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- pinning

/// Outcome of checking a host key against the pin store.
#[derive(Debug, PartialEq, Eq)]
pub enum PinCheck {
    /// Key matches the pinned key for this host.
    Match,
    /// Host never seen before (caller decides whether to trust & pin).
    Unknown,
    /// DIFFERENT key than pinned: possible MITM. Must refuse.
    Mismatch { pinned_fingerprint: String },
}

/// `known_hosts`-style pin store: one `<host-label> <public-key-hex>` per line.
pub struct KnownHosts {
    path: PathBuf,
    entries: Vec<(String, [u8; 32])>,
}

impl KnownHosts {
    pub fn load(path: &Path) -> Result<Self> {
        let mut entries = Vec::new();
        if path.exists() {
            for (i, line) in std::fs::read_to_string(path)?.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut it = line.split_whitespace();
                let (Some(label), Some(key)) = (it.next(), it.next()) else {
                    bail!("{}:{}: malformed line", path.display(), i + 1);
                };
                let key = hex_decode(key)?;
                let key: [u8; 32] =
                    key.as_slice().try_into().map_err(|_| anyhow!("{}:{}: bad key", path.display(), i + 1))?;
                entries.push((label.to_string(), key));
            }
        }
        Ok(Self { path: path.to_path_buf(), entries })
    }

    pub fn check(&self, label: &str, key: &[u8; 32]) -> PinCheck {
        let label = label.to_ascii_lowercase();
        match self.entries.iter().find(|(l, _)| *l == label) {
            None => PinCheck::Unknown,
            Some((_, k)) if k == key => PinCheck::Match,
            Some((_, k)) => PinCheck::Mismatch { pinned_fingerprint: fingerprint(k) },
        }
    }

    /// Other labels under which this exact key is already pinned.
    pub fn labels_for(&self, key: &[u8; 32]) -> Vec<String> {
        self.entries.iter().filter(|(_, k)| k == key).map(|(l, _)| l.clone()).collect()
    }

    pub fn pin(&mut self, label: &str, key: &[u8; 32]) -> Result<()> {
        if label.chars().any(char::is_whitespace) || label.is_empty() {
            bail!("invalid host label");
        }
        let label = label.to_ascii_lowercase();
        // Re-read so concurrent viewers don't drop each other's pins.
        if let Ok(fresh) = Self::load(&self.path) {
            self.entries = fresh.entries;
        }
        let label = label.as_str();
        self.entries.retain(|(l, _)| l != label);
        self.entries.push((label.to_string(), *key));
        let mut body = String::from("# FreedomDesk pinned host keys: <host> <x25519-public-key-hex>\n");
        for (l, k) in &self.entries {
            body.push_str(&format!("{l} {}\n", hex_encode(k)));
        }
        if let Some(dir) = self.path.parent() {
            create_private_dir(dir)?;
        }
        write_private_file(&self.path, body.as_bytes())
    }
}

// ---------------------------------------------------------------- helpers

fn hex_encode(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    data_encoding::HEXLOWER_PERMISSIVE.decode(s.as_bytes()).map_err(|_| anyhow!("invalid hex"))
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !dir.exists() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    } else {
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o022 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode & !0o077))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// Atomically write a file readable only by the owner.
fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn check_private_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} is accessible by other users (mode {:o}); run: chmod 600 {}",
            path.display(),
            mode & 0o777,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_perms(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn pair() -> (Session, Session, [u8; 32], [u8; 32]) {
        let host = Identity::generate().unwrap();
        let viewer = Identity::generate().unwrap();
        let (hp, vp) = (*host.public_key(), *viewer.public_key());
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            accept(s, &host).unwrap()
        });
        let v = connect(TcpStream::connect(addr).unwrap(), &viewer).unwrap();
        let h = t.join().unwrap();
        (h, v, hp, vp)
    }

    #[test]
    fn handshake_authenticates_both_sides() {
        let (h, v, hp, vp) = pair();
        assert_eq!(h.remote_public, vp);
        assert_eq!(v.remote_public, hp);
    }

    #[test]
    fn messages_roundtrip_including_large_and_empty() {
        let (mut h, mut v, _, _) = pair();
        let big: Vec<u8> = (0..300_000u32).map(|i| (i * 7) as u8).collect();
        let big2 = big.clone();
        let t = std::thread::spawn(move || {
            h.writer.send(b"hello").unwrap();
            h.writer.send(&big2).unwrap();
            h.writer.send(&[]).unwrap();
            h.reader.recv().unwrap()
        });
        assert_eq!(v.reader.recv().unwrap(), b"hello");
        assert_eq!(v.reader.recv().unwrap(), big);
        assert_eq!(v.reader.recv().unwrap(), b"");
        v.writer.send(b"bye").unwrap();
        assert_eq!(t.join().unwrap(), b"bye");
    }

    #[test]
    fn recv_limited_caps_size() {
        let (mut h, mut v, _, _) = pair();
        v.writer.send(&[7u8; 5000]).unwrap();
        let err = h.reader.recv_limited(1024, None).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn handshake_deadline_beats_trickling_peer() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            // Announce a 32-byte frame, then dribble a byte every 100 ms.
            s.write_all(&[0, 32]).unwrap();
            for _ in 0..32 {
                if s.write_all(&[0]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let (s, _) = l.accept().unwrap();
        let host = Identity::generate().unwrap();
        let start = Instant::now();
        let deadline = Some(start + Duration::from_millis(500));
        let mut s2 = s.try_clone().unwrap();
        assert!(read_frame(&mut s2, deadline).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        drop((s, host));
        t.join().unwrap();
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (h, mut v, _, _) = pair();
        // Write a bogus frame directly on the host's socket.
        let mut raw = h.writer.stream.try_clone().unwrap();
        write_frame(&mut raw, &[0u8; 40]).unwrap();
        assert!(v.reader.recv().is_err());
    }

    #[test]
    fn wrong_protocol_peer_fails_handshake() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.write_all(b"\x00\x05hello").unwrap();
        });
        let viewer = Identity::generate().unwrap();
        let s = TcpStream::connect(addr).unwrap();
        // Our `-> e` goes out fine; the junk reply must fail.
        assert!(connect(s, &viewer).is_err());
        t.join().unwrap();
    }

    #[test]
    fn identity_persists_with_private_perms() {
        let dir = std::env::temp_dir().join(format!("fd-crypto-test-{}", std::process::id()));
        let path = dir.join("identity.key");
        let a = Identity::load_or_create(&path).unwrap();
        let b = Identity::load_or_create(&path).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pinning() {
        let dir = std::env::temp_dir().join(format!("fd-crypto-pin-{}", std::process::id()));
        let path = dir.join("known_hosts");
        let mut kh = KnownHosts::load(&path).unwrap();
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        assert_eq!(kh.check("the21th", &k1), PinCheck::Unknown);
        kh.pin("the21th", &k1).unwrap();
        let kh = KnownHosts::load(&path).unwrap();
        assert_eq!(kh.check("the21th", &k1), PinCheck::Match);
        assert!(matches!(kh.check("the21th", &k2), PinCheck::Mismatch { .. }));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint(&[0u8; 32]);
        assert_eq!(fp.len(), 24 + 5);
        assert_eq!(normalize_fingerprint(&fp.to_lowercase().replace('-', " ")), normalize_fingerprint(&fp));
    }
}
