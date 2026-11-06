//! Moves the pointer in a small square around its current position and puts it
//! back. Injects motion only (no clicks, no keys). Linux/X11 only.
//!
//!     DISPLAY=:0 cargo run -p fd-input --example jiggle

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use fd_proto::InputEvent;
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::ConnectionExt;
    use x11rb::wrapper::ConnectionExt as _;

    let (conn, screen) = x11rb::connect(None)?;
    let root = conn.setup().roots[screen].clone();
    let (w, h) = (root.width_in_pixels as u32, root.height_in_pixels as u32);
    let p = conn.query_pointer(root.root)?.reply()?;
    let (ox, oy) = (p.root_x as i32, p.root_y as i32);
    println!("screen {w}x{h}, pointer at {ox},{oy}");

    let to_norm = |px: i32, size: u32| -> u16 {
        let px = px.clamp(0, size as i32 - 1) as u64;
        ((px * 65535).div_ceil(size as u64 - 1)).min(65535) as u16
    };
    let mut inj = fd_input::open_default(w, h)?;
    let d = 100;
    for (dx, dy) in [(d, 0), (d, d), (0, d), (0, 0)] {
        let (x, y) = (ox + dx, oy + dy);
        inj.inject(&InputEvent::MouseMove { x: to_norm(x, w), y: to_norm(y, h) })?;
        std::thread::sleep(std::time::Duration::from_millis(300));
        let p = conn.query_pointer(root.root)?.reply()?;
        println!("asked {x},{y} -> pointer at {},{}", p.root_x, p.root_y);
    }
    inj.release_all()?;
    // Restore the exact original position (normalisation may round by a pixel).
    conn.warp_pointer(x11rb::NONE, root.root, 0, 0, 0, 0, ox as i16, oy as i16)?;
    conn.sync()?;
    let p = conn.query_pointer(root.root)?.reply()?;
    println!("restored pointer to {},{}", p.root_x, p.root_y);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("jiggle: Linux/X11 only");
}
