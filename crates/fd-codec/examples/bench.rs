//! Capture -> convert -> encode -> decode benchmark against the live display.
//!
//! cargo run --release -p fd-codec --example bench -- [frames=120] [max_w=1920] [max_h=1080] [kbps=6000]
//!
//! Frames are captured back-to-back (not paced), so the screen content is whatever is on it;
//! move a window around during the run for a "busy" measurement.

use std::time::{Duration, Instant};

use fd_codec::{EncoderConfig, VideoDecoder, VideoEncoder};

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn main() -> anyhow::Result<()> {
    let args: Vec<u32> = std::env::args().skip(1).map(|a| a.parse()).collect::<Result<_, _>>()?;
    let arg = |i: usize, d: u32| args.get(i).copied().unwrap_or(d);
    let n = arg(0, 120);
    let cfg =
        EncoderConfig { max_width: arg(1, 1920), max_height: arg(2, 1080), fps: 30.0, bitrate_bps: arg(3, 6000) * 1000 };

    let mut cap = fd_capture::open_default()?;
    let (sw, sh) = cap.size();
    let mut enc = VideoEncoder::new(sw, sh, cfg.clone())?;
    let mut dec = VideoDecoder::new()?;
    let (ow, oh) = enc.output_size();
    println!("source {sw}x{sh} -> {ow}x{oh}, {} kbps, {n} frames", cfg.bitrate_bps / 1000);

    let (mut t_cap, mut t_conv, mut t_enc, mut t_dec) = (Duration::ZERO, Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let (mut bytes, mut encoded, mut skipped, mut decoded) = (0usize, 0u32, 0u32, 0u32);
    let mut first_kb = 0.0;
    let total = Instant::now();
    for i in 0..n {
        let t = Instant::now();
        let frame = cap.capture()?;
        t_cap += t.elapsed();

        let t = Instant::now();
        enc.convert(frame)?;
        t_conv += t.elapsed();

        let t = Instant::now();
        let out = enc.encode_converted(false)?;
        t_enc += t.elapsed();

        let Some(out) = out else {
            skipped += 1;
            continue;
        };
        if i == 0 {
            first_kb = out.data.len() as f64 / 1024.0;
        } else {
            bytes += out.data.len();
            encoded += 1;
        }

        let t = Instant::now();
        if let Some(pic) = dec.decode(&out.data)? {
            assert_eq!((pic.width, pic.height), (ow, oh));
            decoded += 1;
        }
        t_dec += t.elapsed();
    }
    let wall = total.elapsed();

    // Forced keyframe size on the current content.
    let frame = cap.capture()?;
    let idr = loop {
        if let Some(f) = enc.encode(frame, true)? {
            break f;
        }
    };

    let nf = n as f64;
    println!("capture  {:7.2} ms/frame", ms(t_cap) / nf);
    println!("convert  {:7.2} ms/frame (BGRX->I420 + scale)", ms(t_conv) / nf);
    println!("encode   {:7.2} ms/frame (OpenH264)", ms(t_enc) / nf);
    println!("decode   {:7.2} ms/frame (OpenH264 + I420->RGBA)", ms(t_dec) / decoded.max(1) as f64);
    println!(
        "pipeline {:7.2} ms/frame => {:.1} fps (sequential, single stream)",
        ms(wall) / nf,
        nf / wall.as_secs_f64()
    );
    println!(
        "size: first IDR {:.1} KB, forced IDR {:.1} KB (keyframe={}), P avg {:.2} KB over {encoded} frames; skipped {skipped}, decoded {decoded}",
        first_kb,
        idr.data.len() as f64 / 1024.0,
        idr.keyframe,
        bytes as f64 / 1024.0 / encoded.max(1) as f64
    );
    Ok(())
}
