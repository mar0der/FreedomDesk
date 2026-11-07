//! Diagnostics: how often does the screen really change, and is a display lit?
//! `cargo run --release -p fd-capture --example changes -- 5`
use std::time::{Duration, Instant};
fn main() -> anyhow::Result<()> {
    let secs: f64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(5.0);
    let mut c = fd_capture::open_default()?;
    c.set_draw_cursor(false);
    println!("active outputs: {:?}", c.active_outputs());
    let t0 = Instant::now();
    let (mut calls, mut changed, mut slow) = (0u32, 0u32, Duration::ZERO);
    while t0.elapsed().as_secs_f64() < secs {
        let t = Instant::now();
        if c.capture_if_changed()?.is_some() {
            changed += 1;
        }
        calls += 1;
        slow = slow.max(t.elapsed());
        if let Some(r) = Duration::from_millis(33).checked_sub(t.elapsed()) {
            std::thread::sleep(r);
        }
    }
    println!("calls={calls} changed={changed} ({:.1}/s) slowest call {slow:?}", changed as f64 / secs);
    Ok(())
}
