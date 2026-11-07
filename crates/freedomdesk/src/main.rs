//! FreedomDesk — one binary that is both host agent and viewer.

mod authorized;
mod consent;
mod host;
mod keymap;
mod launcher;
mod netpolicy;
#[cfg(target_os = "linux")]
mod service;
mod viewer;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "freedomdesk", version, about = "Open-source remote desktop (host + viewer)")]
struct Cli {
    /// Config directory (identity key, pinned hosts, audit log).
    /// Default: $FREEDOMDESK_CONFIG_DIR or ~/.config/freedomdesk
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,

    /// No command: open the GUI (saved machines + connect).
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show this device's identity fingerprint (creates the identity on first run).
    Id,
    /// Share this screen: listen for a viewer on the LAN/Tailscale.
    Host(host::HostArgs),
    /// Connect to a host and view/control it.
    View(viewer::ViewArgs),
    /// Allow a viewer to connect to this host without a consent prompt (unattended).
    Authorize(authorized::AuthorizeArgs),
    /// Run as a root system service: follow the console (login screen or
    /// desktop) and host it as that session's user. Linux, X11.
    #[cfg(target_os = "linux")]
    Service(service::ServiceArgs),
    /// (internal) Show the host-side consent dialog. Exit code 0 = allowed.
    #[command(hide = true)]
    Consent(consent::ConsentArgs),
}

pub fn config_dir(cli: &Option<PathBuf>) -> PathBuf {
    if let Some(d) = cli {
        return d.clone();
    }
    if let Some(d) = std::env::var_os("FREEDOMDESK_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    directories::ProjectDirs::from("org", "FreedomDesk", "freedomdesk")
        .map(|p| p.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".freedomdesk"))
}

pub fn load_identity(dir: &std::path::Path) -> Result<fd_crypto::Identity> {
    fd_crypto::Identity::load_or_create(&dir.join("identity.key"))
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let dir = config_dir(&cli.config_dir);
    let Some(cmd) = cli.cmd else {
        return launcher::run_gui(&dir, None);
    };
    match cmd {
        Cmd::Id => {
            let id = load_identity(&dir)?;
            println!("Device fingerprint: {}", id.fingerprint());
            println!("Config dir:         {}", dir.display());
            Ok(())
        }
        Cmd::Host(a) => host::run(&dir, a),
        Cmd::View(a) => viewer::run(&dir, a),
        Cmd::Authorize(a) => authorized::run(&dir, a),
        Cmd::Consent(a) => consent::run(a),
        #[cfg(target_os = "linux")]
        Cmd::Service(a) => service::run(&dir, a),
    }
}
