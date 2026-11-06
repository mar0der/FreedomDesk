//! Where the host agent is allowed to listen.
//!
//! Policy (SPEC §5): never listen on the public internet by default. Only
//! loopback, LAN (RFC 1918 / ULA / link-local) and Tailscale (100.64/10,
//! fd7a:115c:a1e0::/48) addresses are accepted unless the user explicitly opts in.

use anyhow::{bail, Context, Result};
use std::net::{IpAddr, SocketAddr};

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT (Tailscale)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA (includes Tailscale)
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// This machine's Tailscale IPv4, if Tailscale is installed and up.
pub fn tailscale_ipv4() -> Option<IpAddr> {
    let out = std::process::Command::new("tailscale").args(["ip", "-4"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).lines().next()?.trim().parse().ok()
}

pub fn resolve_bind(bind: Option<&str>, port: u16, allow_public: bool) -> Result<SocketAddr> {
    let addr: SocketAddr = match bind {
        Some(s) => match s.parse::<SocketAddr>() {
            Ok(a) => a,
            Err(_) => SocketAddr::new(s.parse::<IpAddr>().context("--bind must be an IP or IP:port")?, port),
        },
        None => match tailscale_ipv4() {
            Some(ip) => SocketAddr::new(ip, port),
            None => bail!(
                "Tailscale not detected. Pass --bind <LAN-or-Tailscale-IP> (e.g. --bind 192.168.1.20)"
            ),
        },
    };
    if addr.ip().is_unspecified() && !allow_public {
        bail!(
            "refusing to listen on all interfaces ({addr}): that may expose this computer to the internet. \
             Bind a LAN/Tailscale IP, or pass --allow-public-bind if you really mean it."
        );
    }
    if !addr.ip().is_unspecified() && !is_private(addr.ip()) && !allow_public {
        bail!("refusing to listen on public address {addr}; pass --allow-public-bind to override");
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        for ok in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.20.1.1", "100.116.143.66", "fd7a:115c:a1e0::1", "::1"] {
            assert!(is_private(ok.parse().unwrap()), "{ok}");
        }
        for bad in ["8.8.8.8", "100.128.0.1", "2001:4860::1", "172.32.0.1"] {
            assert!(!is_private(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn bind_policy() {
        assert!(resolve_bind(Some("0.0.0.0"), 1, false).is_err());
        assert!(resolve_bind(Some("8.8.8.8:5"), 1, false).is_err());
        assert!(resolve_bind(Some("0.0.0.0"), 1, true).is_ok());
        assert_eq!(resolve_bind(Some("127.0.0.1"), 9, false).unwrap().port(), 9);
        assert_eq!(resolve_bind(Some("127.0.0.1:7"), 9, false).unwrap().port(), 7);
    }
}
