//! Debug helper: capture one frame and write it as a binary PPM.
//!
//! cargo run -p fd-capture --example snap -- out.ppm [x y w h] [cursor=1]

use std::io::Write;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args.first().map_or("snap.ppm", String::as_str);
    let num = |i: usize| args.get(i).and_then(|s| s.parse::<u32>().ok());
    let mut cap = fd_capture::open_default()?;
    cap.set_draw_cursor(num(5).unwrap_or(1) != 0);
    let f = cap.capture()?;
    let (x0, y0) = (
        num(1).unwrap_or(0).min(f.width - 1),
        num(2).unwrap_or(0).min(f.height - 1),
    );
    let w = num(3).unwrap_or(f.width).min(f.width - x0);
    let h = num(4).unwrap_or(f.height).min(f.height - y0);
    let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
    write!(out, "P6\n{w} {h}\n255\n")?;
    for y in y0..y0 + h {
        let row = &f.data[y as usize * f.stride + x0 as usize * 4..][..w as usize * 4];
        for p in row.chunks_exact(4) {
            out.write_all(&[p[2], p[1], p[0]])?;
        }
    }
    println!("wrote {path}: {w}x{h} at ({x0},{y0})");
    Ok(())
}
