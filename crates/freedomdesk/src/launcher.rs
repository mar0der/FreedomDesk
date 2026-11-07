//! GUI launcher: saved machines, connect, first-connection fingerprint check,
//! then the remote session in the same window. Used by the macOS .app and by
//! `freedomdesk` with no arguments on any platform.

use crate::viewer::{self, ConnectOpts, ConnectUi, Connected, TrustPrompt, ViewerApp};
use anyhow::{bail, Context, Result};
use eframe::egui;
use fd_crypto::{normalize_fingerprint, ShutdownHandle};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ------------------------------------------------------------ saved machines

/// One saved machine. Stored as `name<TAB>address<TAB>fingerprint` lines in
/// `<config>/machines` (0600). The fingerprint, once set, is enforced on every
/// connect, exactly like `--expect-fingerprint`.
#[derive(Clone, Debug, PartialEq)]
pub struct Machine {
    pub name: String,
    pub address: String,
    pub fingerprint: Option<String>,
}

const FP_LEN: usize = 24; // base32 chars of a fingerprint (120 bits)

/// Canonical `XXXX-XXXX-…` form, or an error if it is not a fingerprint.
pub fn parse_fingerprint(s: &str) -> Result<Option<String>> {
    let n = normalize_fingerprint(s);
    if n.is_empty() {
        return Ok(None);
    }
    if n.len() != FP_LEN || !n.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)) {
        bail!("a fingerprint is 24 letters/digits, like ABCD-EFGH-IJKL-MNOP-QRST-UVWX");
    }
    let groups: Vec<String> = n.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    Ok(Some(groups.join("-")))
}

impl Machine {
    /// Validate and normalise user input.
    pub fn new(name: &str, address: &str, fingerprint: &str) -> Result<Machine> {
        let name = crate::consent::sanitize(name.trim(), 64);
        let address = address.trim().to_string();
        if address.is_empty() {
            bail!("address is empty");
        }
        if address.len() > 255 || address.chars().any(|c| c.is_whitespace() || c.is_control()) {
            bail!("address must be a host name or IP, optionally with :port");
        }
        let name = if name.is_empty() { address.clone() } else { name };
        Ok(Machine { name, address, fingerprint: parse_fingerprint(fingerprint)? })
    }
}

fn machines_path(dir: &Path) -> PathBuf {
    dir.join("machines")
}

pub fn load_machines(dir: &Path) -> Result<Vec<Machine>> {
    let text = match std::fs::read_to_string(machines_path(dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("reading machines"),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        // Comments are whole lines without a tab (a name may start with '#').
        if line.trim().is_empty() || (line.starts_with('#') && !line.contains('\t')) {
            continue;
        }
        let mut f = line.split('\t');
        let (name, addr, fp) = (f.next().unwrap_or(""), f.next().unwrap_or(""), f.next().unwrap_or(""));
        match Machine::new(name, addr, fp) {
            Ok(m) => out.push(m),
            Err(e) => log::warn!("skipping bad line in machines file: {e:#}"),
        }
    }
    Ok(out)
}

pub fn save_machines(dir: &Path, machines: &[Machine]) -> Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let path = machines_path(dir);
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp); // a stale tmp could carry looser permissions
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    writeln!(f, "# FreedomDesk saved machines: name<TAB>address<TAB>fingerprint")?;
    for m in machines {
        // Fields were validated: no tabs/newlines can be in them.
        writeln!(f, "{}\t{}\t{}", m.name, m.address, m.fingerprint.as_deref().unwrap_or(""))?;
    }
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

// ------------------------------------------------------------ connect worker

enum WorkerMsg {
    Status(String),
    Trust(TrustPrompt, Sender<bool>),
    Done(Result<Connected>),
}

/// Cancel flag and the socket to shut down, under one lock so neither side
/// can miss the other.
#[derive(Default)]
struct CancelState {
    cancelled: bool,
    socket: Option<ShutdownHandle>,
}

type Cancel = Arc<Mutex<CancelState>>;

struct GuiUi {
    tx: Sender<WorkerMsg>,
    ctx: egui::Context,
    cancel: Cancel,
}

impl ConnectUi for GuiUi {
    fn status(&mut self, msg: &str) {
        log::info!("{msg}");
        let _ = self.tx.send(WorkerMsg::Status(msg.to_string()));
        self.ctx.request_repaint();
    }
    fn trust(&mut self, p: &TrustPrompt) -> bool {
        let (rtx, rrx) = mpsc::channel();
        if self.tx.send(WorkerMsg::Trust(TrustPrompt { label: p.label.clone(), fingerprint: p.fingerprint.clone() }, rtx)).is_err() {
            return false;
        }
        self.ctx.request_repaint();
        rrx.recv().unwrap_or(false) // launcher dropped the sender (cancel) = no
    }
    fn cancel_handle(&mut self, h: ShutdownHandle) {
        let mut c = self.cancel.lock().unwrap();
        if c.cancelled {
            h.shutdown();
        }
        c.socket = Some(h);
    }
    fn cancelled(&self) -> bool {
        self.cancel.lock().unwrap().cancelled
    }
}

struct Connecting {
    machine: Machine,
    /// Index in the saved list, or None for a quick connect.
    index: Option<usize>,
    rx: Receiver<WorkerMsg>,
    status: String,
    trust: Option<(TrustPrompt, Sender<bool>)>,
    cancel: Cancel,
}

impl Connecting {
    fn abort(&self) {
        let mut c = self.cancel.lock().unwrap();
        c.cancelled = true;
        if let Some(h) = &c.socket {
            h.shutdown();
        }
    }
}

// ------------------------------------------------------------ app

struct Editor {
    /// None = adding a new machine.
    index: Option<usize>,
    name: String,
    address: String,
    fingerprint: String,
    error: Option<String>,
}

enum Screen {
    Launcher,
    Connecting(Box<Connecting>),
    Session(Box<ViewerApp>),
}

pub struct FdApp {
    dir: PathBuf,
    my_fingerprint: String,
    machines: Vec<Machine>,
    screen: Screen,
    editor: Option<Editor>,
    confirm_remove: Option<usize>,
    quick: String,
    error: Option<String>,
    notice: Option<String>,
    /// The machines file exists but could not be read: never overwrite it.
    load_failed: bool,
}

const TITLE: &str = "FreedomDesk";

impl FdApp {
    fn new(dir: &Path, conn: Option<Connected>, ctx: &egui::Context) -> FdApp {
        let my_fingerprint = crate::load_identity(dir).map(|i| i.fingerprint()).unwrap_or_else(|e| format!("(error: {e:#})"));
        let (machines, error) = match load_machines(dir) {
            Ok(m) => (m, None),
            Err(e) => (Vec::new(), Some(format!("{e:#} — saved machines are read-only until this is fixed"))),
        };
        let load_failed = error.is_some();
        let mut app = FdApp {
            dir: dir.to_path_buf(),
            my_fingerprint,
            machines,
            screen: Screen::Launcher,
            editor: None,
            confirm_remove: None,
            quick: String::new(),
            error,
            notice: None,
            load_failed,
        };
        if let Some(c) = conn {
            app.enter_session(c, ctx);
        }
        app
    }

    fn enter_session(&mut self, conn: Connected, ctx: &egui::Context) {
        // The launcher window is small; grow it for the remote screen.
        let (vw, vh) = conn.video_size();
        let cur = ctx.input(|i| i.viewport().inner_rect).map(|r| r.size()).unwrap_or_default();
        let mon = ctx.input(|i| i.viewport().monitor_size).unwrap_or(egui::vec2(1600.0, 1000.0));
        let want = egui::vec2((vw as f32).min(mon.x * 0.85), (vh as f32).min(mon.y * 0.85));
        if cur.x < want.x && cur.y < want.y {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(want));
        }
        match ViewerApp::start(conn, ctx) {
            Ok(v) => self.screen = Screen::Session(Box::new(v)),
            Err(e) => self.error = Some(format!("{e:#}")),
        }
    }

    fn save(&mut self) {
        if self.load_failed {
            return;
        }
        if let Err(e) = save_machines(&self.dir, &self.machines) {
            self.error = Some(format!("could not save machines: {e:#}"));
        }
    }

    fn start_connect(&mut self, machine: Machine, index: Option<usize>, ctx: &egui::Context) {
        self.error = None;
        self.notice = None;
        let (tx, rx) = mpsc::channel();
        let cancel: Cancel = Arc::default();
        let mut ui = GuiUi { tx: tx.clone(), ctx: ctx.clone(), cancel: cancel.clone() };
        let opts = ConnectOpts { host: machine.address.clone(), expect_fingerprint: machine.fingerprint.clone(), name: None };
        let dir = self.dir.clone();
        let ctx2 = ctx.clone();
        std::thread::spawn(move || {
            let r = viewer::connect(&dir, &opts, &mut ui);
            let _ = tx.send(WorkerMsg::Done(r));
            ctx2.request_repaint();
        });
        self.screen = Screen::Connecting(Box::new(Connecting {
            status: format!("Connecting to {} …", machine.address),
            machine,
            index,
            rx,
            trust: None,
            cancel,
        }));
    }

    /// Drain worker messages. Returns a finished connection, if any.
    fn poll_connect(&mut self) -> Option<Result<(Connected, Machine, Option<usize>)>> {
        let Screen::Connecting(c) = &mut self.screen else { return None };
        while let Ok(m) = c.rx.try_recv() {
            match m {
                WorkerMsg::Status(s) => c.status = s,
                WorkerMsg::Trust(p, reply) => c.trust = Some((p, reply)),
                WorkerMsg::Done(r) => return Some(r.map(|conn| (conn, c.machine.clone(), c.index))),
            }
        }
        None
    }

    fn connected(&mut self, conn: Connected, mut machine: Machine, index: Option<usize>, ctx: &egui::Context) {
        // Remember what we learned: the pinned fingerprint, and quick connects.
        let fp = parse_fingerprint(&conn.host_fingerprint).ok().flatten();
        match index {
            Some(i) if i < self.machines.len() && self.machines[i] == machine => {
                if self.machines[i].fingerprint.is_none() {
                    self.machines[i].fingerprint = fp;
                    self.save();
                }
            }
            _ => {
                if !self.machines.iter().any(|m| m.address == machine.address) {
                    if machine.name == machine.address && !conn.host_name.is_empty() {
                        machine.name = crate::consent::sanitize(&conn.host_name, 64);
                    }
                    machine.fingerprint = machine.fingerprint.or(fp);
                    self.machines.push(machine);
                    self.save();
                }
            }
        }
        self.enter_session(conn, ctx);
    }

    // -------------------------------------------------------- drawing

    fn launcher_ui(&mut self, ctx: &egui::Context) {
        let mut connect: Option<(Machine, Option<usize>)> = None;
        egui::TopBottomPanel::bottom("fd-me").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.weak("This device:");
                ui.monospace(&self.my_fingerprint);
                if ui.small_button("Copy").clicked() {
                    ctx.copy_text(self.my_fingerprint.clone());
                }
                ui.weak("— give this to a host owner so they can authorize you.");
            });
            ui.add_space(4.0);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            ui.heading("FreedomDesk");
            ui.add_space(8.0);
            if let Some(e) = &self.error {
                ui.colored_label(ui.visuals().error_fg_color, e);
                ui.add_space(6.0);
            }
            if let Some(n) = &self.notice {
                ui.label(n);
                ui.add_space(6.0);
            }

            ui.horizontal(|ui| {
                ui.strong("Machines");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(self.editor.is_none() && self.confirm_remove.is_none(), egui::Button::new("➕ Add machine")).clicked() {
                        self.editor = Some(Editor { index: None, name: String::new(), address: String::new(), fingerprint: String::new(), error: None });
                    }
                });
            });
            ui.separator();
            if self.machines.is_empty() {
                ui.add_space(12.0);
                ui.weak("No saved machines yet. Add one, or type an address below.");
                ui.add_space(12.0);
            }
            let dialog_open = self.editor.is_some() || self.confirm_remove.is_some();
            ui.add_enabled_ui(!dialog_open, |ui| {
            egui::ScrollArea::vertical().max_height(ui.available_height() - 70.0).show(ui, |ui| {
                egui::Grid::new("fd-machines").num_columns(4).spacing([16.0, 10.0]).striped(true).show(ui, |ui| {
                    for (i, m) in self.machines.iter().enumerate() {
                        ui.vertical(|ui| {
                            ui.set_min_width(170.0);
                            ui.add(egui::Label::new(egui::RichText::new(&m.name).strong()).truncate());
                            ui.add(egui::Label::new(egui::RichText::new(&m.address).weak()).truncate());
                        });
                        match &m.fingerprint {
                            Some(fp) => ui.monospace(fp).on_hover_text("Pinned host fingerprint: the connection is refused if the host presents another key."),
                            None => ui.weak("fingerprint checked on first connect"),
                        };
                        if ui.button("Connect").clicked() {
                            connect = Some((m.clone(), Some(i)));
                        }
                        ui.horizontal(|ui| {
                            if ui.button("Edit").clicked() {
                                self.editor = Some(Editor {
                                    index: Some(i),
                                    name: m.name.clone(),
                                    address: m.address.clone(),
                                    fingerprint: m.fingerprint.clone().unwrap_or_default(),
                                    error: None,
                                });
                            }
                            if ui.button("Remove").clicked() {
                                self.confirm_remove = Some(i);
                            }
                        });
                        ui.end_row();
                    }
                });
            });

            ui.add_space(12.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Quick connect:");
                let r = ui.add(egui::TextEdit::singleline(&mut self.quick).hint_text("name or IP[:port]").desired_width(240.0));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if (ui.button("Connect").clicked() || enter) && !self.quick.trim().is_empty() {
                    match Machine::new("", &self.quick, "") {
                        Ok(m) => {
                            // Same address as a saved machine: use it, so its pinned fingerprint applies.
                            connect = Some(match self.machines.iter().position(|s| s.address == m.address) {
                                Some(i) => (self.machines[i].clone(), Some(i)),
                                None => (m, None),
                            });
                            self.quick.clear();
                        }
                        Err(e) => self.error = Some(format!("{e:#}")),
                    }
                }
            });
            }); // add_enabled_ui
        });

        self.editor_window(ctx);
        self.remove_window(ctx);
        if let Some((m, i)) = connect {
            self.start_connect(m, i, ctx);
        }
    }

    fn editor_window(&mut self, ctx: &egui::Context) {
        let Some(ed) = &mut self.editor else { return };
        let mut close = false;
        let mut save: Option<Machine> = None;
        let title = if ed.index.is_some() { "Edit machine" } else { "Add machine" };
        egui::Window::new(title).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO).show(ctx, |ui| {
            egui::Grid::new("fd-edit").num_columns(2).spacing([8.0, 8.0]).show(ui, |ui| {
                ui.label("Name");
                ui.add(egui::TextEdit::singleline(&mut ed.name).hint_text("Mum's laptop").desired_width(300.0));
                ui.end_row();
                ui.label("Address");
                ui.add(egui::TextEdit::singleline(&mut ed.address).hint_text("100.x.y.z or name[:port]").desired_width(300.0));
                ui.end_row();
                ui.label("Fingerprint");
                ui.add(egui::TextEdit::singleline(&mut ed.fingerprint).hint_text("optional: XXXX-XXXX-…").font(egui::TextStyle::Monospace).desired_width(300.0));
                ui.end_row();
            });
            ui.weak("Fingerprint: run `freedomdesk id` on that machine. Leave it empty to\ncheck it on the first connection; it is saved after that.");
            if let Some(e) = &ed.error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    match Machine::new(&ed.name, &ed.address, &ed.fingerprint) {
                        Ok(m) => save = Some(m),
                        Err(e) => ed.error = Some(format!("{e:#}")),
                    }
                }
                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        });
        if let Some(m) = save {
            let index = ed.index;
            match index {
                Some(i) if i < self.machines.len() => self.machines[i] = m,
                _ => self.machines.push(m),
            }
            self.save();
            close = true;
        }
        if close {
            self.editor = None;
        }
    }

    fn remove_window(&mut self, ctx: &egui::Context) {
        let Some(i) = self.confirm_remove else { return };
        let Some(m) = self.machines.get(i) else {
            self.confirm_remove = None;
            return;
        };
        let name = m.name.clone();
        let (mut yes, mut no) = (false, false);
        egui::Window::new("Remove machine").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO).show(ctx, |ui| {
            ui.label(format!("Remove “{name}” from the list?"));
            ui.weak("Its pinned key stays in known_hosts.");
            ui.horizontal(|ui| {
                yes = ui.button("Remove").clicked();
                no = ui.button("Cancel").clicked();
            });
        });
        if yes {
            self.machines.remove(i);
            self.save();
        }
        if yes || no {
            self.confirm_remove = None;
        }
    }

    fn connecting_ui(&mut self, ctx: &egui::Context) {
        let Screen::Connecting(c) = &mut self.screen else { return };
        let mut cancel = false;
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(ui.available_height() / 3.0);
            ui.vertical_centered(|ui| {
                ui.heading(&c.machine.name);
                ui.add_space(8.0);
                ui.spinner();
                ui.add_space(8.0);
                ui.label(&c.status);
                ui.add_space(12.0);
                cancel = ui.button("Cancel").clicked();
            });
        });
        if let Some((p, reply)) = &c.trust {
            let mut answer = None;
            egui::Window::new("New machine — check its fingerprint")
                .min_width(460.0)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label(format!("First connection to {}. It identifies itself as:", p.label));
                    ui.add_space(6.0);
                    ui.vertical_centered(|ui| ui.label(egui::RichText::new(&p.fingerprint).monospace().size(20.0).strong()));
                    ui.add_space(6.0);
                    ui.label("Compare it with the fingerprint shown on that machine\n(`freedomdesk id`, or read out over the phone).\nOnly continue if they are identical.");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("They match — trust and connect").clicked() {
                            answer = Some(true);
                        }
                        if ui.button("Cancel").clicked() {
                            answer = Some(false);
                        }
                    });
                });
            if let Some(a) = answer {
                let _ = reply.send(a);
                c.trust = None;
                if !a {
                    cancel = true;
                }
            }
        }
        if cancel {
            c.abort();
            self.screen = Screen::Launcher;
        }
        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

impl eframe::App for FdApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(r) = self.poll_connect() {
            self.screen = Screen::Launcher;
            match r {
                Ok((conn, m, i)) => self.connected(conn, m, i, ctx),
                Err(e) => self.error = Some(format!("Could not connect: {e:#}")),
            }
        }
        match &mut self.screen {
            Screen::Launcher => self.launcher_ui(ctx),
            Screen::Connecting(_) => self.connecting_ui(ctx),
            Screen::Session(v) => {
                if v.show(ctx) {
                    self.screen = Screen::Launcher; // drops the session → Bye
                    ctx.send_viewport_cmd(egui::ViewportCommand::Title(TITLE.into()));
                }
            }
        }
    }
}

/// Run the GUI. With `conn`, start straight in that session (`freedomdesk view`).
pub fn run_gui(dir: &Path, conn: Option<Connected>) -> Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(TITLE)
            .with_app_id("freedomdesk")
            .with_inner_size(if conn.is_some() { [1600.0, 900.0] } else { [760.0, 520.0] })
            .with_min_inner_size([480.0, 320.0]),
        ..Default::default()
    };
    let dir = dir.to_path_buf();
    let r = eframe::run_native(
        "freedomdesk-viewer",
        opts,
        Box::new(move |cc| {
            cc.egui_ctx.options_mut(|o| o.zoom_with_keyboard = false);
            Ok(Box::new(FdApp::new(&dir, conn, &cc.egui_ctx)))
        }),
    );
    viewer::join_closers();
    r.map_err(|e| anyhow::anyhow!("viewer window: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_parsing() {
        assert_eq!(parse_fingerprint("").unwrap(), None);
        assert_eq!(parse_fingerprint("l4o7lflsptvehw7urr6pvzwo").unwrap().unwrap(), "L4O7-LFLS-PTVE-HW7U-RR6P-VZWO");
        assert!(parse_fingerprint("L4O7-LFLS").is_err());
        assert!(parse_fingerprint("L4O7-LFLS-PTVE-HW7U-RR6P-VZW1").is_err()); // 1 is not base32
    }

    #[test]
    fn machine_validation() {
        assert!(Machine::new("x", "", "").is_err());
        assert!(Machine::new("x", "a b", "").is_err());
        let m = Machine::new("  ", "100.1.2.3:47801", "").unwrap();
        assert_eq!(m.name, "100.1.2.3:47801");
        let m = Machine::new("Mum\t\n", "mum-laptop", "").unwrap();
        assert_eq!(m.name, "Mum");
    }

    #[test]
    fn machines_roundtrip() {
        let dir = std::env::temp_dir().join(format!("fd-machines-{}", std::process::id()));
        let ms = vec![
            Machine::new("the21th", "100.116.143.66", "L4O7-LFLS-PTVE-HW7U-RR6P-VZWO").unwrap(),
            Machine::new("Mum", "mum:47801", "").unwrap(),
        ];
        save_machines(&dir, &ms).unwrap();
        assert_eq!(load_machines(&dir).unwrap(), ms);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(machines_path(&dir)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
