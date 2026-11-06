//! Host-side consent prompt (attended mode, SPEC P0-6).
//!
//! Runs as a short-lived child process (`freedomdesk consent …`) so the host
//! agent itself never needs a GUI event loop. Exit code 0 = allowed; anything
//! else (Deny, timeout, window closed, no display) = denied.

use anyhow::{Context, Result};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(clap::Args)]
pub struct ConsentArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    fingerprint: String,
    #[arg(long)]
    peer: String,
    #[arg(long, default_value_t = 30)]
    timeout: u64,
}

/// Strip control characters and bound length of peer-supplied text before display.
pub fn sanitize(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Ask the local user. Blocks until answered or `timeout` elapses.
pub fn ask(name: &str, fingerprint: &str, peer: &str, timeout: Duration) -> bool {
    match ask_inner(name, fingerprint, peer, timeout) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("consent prompt failed ({e:#}); denying");
            false
        }
    }
}

fn ask_inner(name: &str, fingerprint: &str, peer: &str, timeout: Duration) -> Result<bool> {
    let exe = std::env::current_exe().context("locating own executable")?;
    let mut child = Command::new(exe)
        // `--flag=value` form: peer-chosen text starting with '-' can't be read as a flag.
        .arg("consent")
        .arg(format!("--name={name}"))
        .arg(format!("--fingerprint={fingerprint}"))
        .arg(format!("--peer={peer}"))
        .arg(format!("--timeout={}", timeout.as_secs()))
        .stdin(Stdio::null())
        .spawn()
        .context("spawning consent dialog")?;
    let deadline = Instant::now() + timeout + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct Dialog {
    args: ConsentArgs,
    started: Instant,
}

impl eframe::App for Dialog {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        use eframe::egui;
        let left = self.args.timeout.saturating_sub(self.started.elapsed().as_secs());
        if left == 0 {
            std::process::exit(2);
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            ui.heading("Remote access request");
            ui.add_space(8.0);
            ui.label(format!("“{}” wants to SEE and CONTROL this computer.", self.args.name));
            ui.label(format!("From: {}", self.args.peer));
            ui.label("Their device fingerprint:");
            ui.monospace(&self.args.fingerprint);
            ui.add_space(8.0);
            ui.label("Only allow this if you are expecting help from this person.");
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button(egui::RichText::new("  Deny  ").size(18.0)).clicked() {
                    std::process::exit(1);
                }
                ui.add_space(24.0);
                if ui.button(egui::RichText::new("  Allow  ").size(18.0)).clicked() {
                    std::process::exit(0);
                }
            });
            ui.add_space(8.0);
            ui.weak(format!("Denying automatically in {left} s"));
        });
        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

pub fn run(args: ConsentArgs) -> Result<()> {
    let args = ConsentArgs {
        name: sanitize(&args.name, 64),
        fingerprint: sanitize(&args.fingerprint, 64),
        peer: sanitize(&args.peer, 80),
        timeout: args.timeout.clamp(5, 300),
    };
    let opts = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("FreedomDesk — allow remote access?")
            .with_inner_size([460.0, 280.0])
            .with_always_on_top()
            .with_resizable(false),
        ..Default::default()
    };
    let started = Instant::now();
    eframe::run_native("freedomdesk-consent", opts, Box::new(move |_| Ok(Box::new(Dialog { args, started }))))
        .map_err(|e| anyhow::anyhow!("consent window: {e}"))?;
    // Window closed without a choice = deny.
    std::process::exit(1);
}
