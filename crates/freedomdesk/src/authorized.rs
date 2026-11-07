//! Unattended access allow-list: `<config>/authorized_viewers`.
//!
//! One viewer fingerprint per line, optional label after it, `#` comments.
//! The host re-reads it on every connection, so `freedomdesk authorize`
//! takes effect without restarting the host. Listed viewers skip the consent
//! prompt — only add devices you own.

use anyhow::{bail, Context, Result};
use fd_crypto::normalize_fingerprint;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn path(dir: &Path) -> PathBuf {
    dir.join("authorized_viewers")
}

/// (normalised fingerprint, label) pairs. Missing file = empty list.
pub fn load(dir: &Path) -> Vec<(String, String)> {
    let text = match std::fs::read_to_string(path(dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            // Under `freedomdesk service` the host runs as the session user:
            // the file must be world-readable (it holds public fingerprints only).
            log::warn!("cannot read {}: {e} — nobody is authorised for unattended access", path(dir).display());
            return Vec::new();
        }
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut it = l.splitn(2, char::is_whitespace);
            let fp = normalize_fingerprint(it.next()?);
            (fp.len() == 24).then(|| (fp, it.next().unwrap_or("").trim().to_string()))
        })
        .collect()
}

/// Label of `fp` if it is authorised.
pub fn lookup(dir: &Path, fp: &str) -> Option<String> {
    let fp = normalize_fingerprint(fp);
    load(dir).into_iter().find(|(f, _)| *f == fp).map(|(_, l)| l)
}

#[derive(clap::Args)]
pub struct AuthorizeArgs {
    /// Viewer fingerprint as shown by `freedomdesk id` on the viewer.
    fingerprint: String,
    /// Label to remember the device by (e.g. "petar-macbook").
    #[arg(long, default_value = "")]
    label: String,
}

pub fn run(dir: &Path, a: AuthorizeArgs) -> Result<()> {
    let fp = normalize_fingerprint(&a.fingerprint);
    if fp.len() != 24 || data_encoding_check(&fp).is_err() {
        bail!("not a FreedomDesk fingerprint (expected 24 base32 chars like ABCD-EFGH-IJKL-MNOP-QRST-UVWX)");
    }
    let label = crate::consent::sanitize(&a.label, 64).replace(['\n', '\r'], " ");
    if load(dir).iter().any(|(f, _)| *f == fp) {
        println!("Already authorised.");
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let p = path(dir);
    let mut f = opts.open(&p).with_context(|| format!("opening {}", p.display()))?;
    let pretty: Vec<String> = fp.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    writeln!(f, "{} {}", pretty.join("-"), label)?;
    println!("Authorised {} for unattended access (no consent prompt). File: {}", pretty.join("-"), p.display());
    Ok(())
}

fn data_encoding_check(fp: &str) -> Result<()> {
    if fp.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)) {
        Ok(())
    } else {
        bail!("invalid base32")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("fd-auth-{}", std::process::id()));
        run(&dir, AuthorizeArgs { fingerprint: "kesu-yexl-qnsk-vv6g-uhnq-rahy".into(), label: "the20th".into() }).unwrap();
        assert_eq!(lookup(&dir, "KESU YEXL QNSK VV6G UHNQ RAHY").as_deref(), Some("the20th"));
        assert!(lookup(&dir, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA").is_none());
        assert!(run(&dir, AuthorizeArgs { fingerprint: "nope".into(), label: String::new() }).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
