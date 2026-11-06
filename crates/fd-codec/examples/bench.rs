//! Capture -> convert -> encode -> decode benchmark against the live display.
//!
//! cargo run --release -p fd-codec --example bench -- [frames=120] [max_w=1920] [max_h=1080] [kbps=6000] [threads=1] [busy=0] [screen=1]
//!
//! `busy=1` paints a moving 800x600 pattern into each captured frame (outside the timed
//! capture) so the encoder sees motion like a dragged window; otherwise the content is whatever
//! is on screen. After the sequential run, a 2-thread pipelined run is measured
//! (thread A: capture+convert, thread B: encode), as the host does it. Captures use the
//! zero-copy `capture_ref()` (unconditional, so a static screen still exercises every stage).

use std::sync::mpsc;
use std::time::{Duration, Instant};

use fd_capture::{Frame, FrameRef};
use fd_codec::{Converter, DecodedFrame, EncoderConfig, I420Frame, VideoDecoder, VideoEncoder};

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn paint_busy(f: &mut Frame, i: u32) {
    let (bw, bh) = (
        800usize.min(f.width as usize),
        600usize.min(f.height as usize),
    );
    let x0 = (i as usize * 37) % (f.width as usize - bw + 1);
    let y0 = (i as usize * 23) % (f.height as usize - bh + 1);
    for y in 0..bh {
        let row = &mut f.data[(y0 + y) * f.stride + x0 * 4..][..bw * 4];
        for (x, p) in row.chunks_exact_mut(4).enumerate() {
            let v = ((x ^ y) as u32).wrapping_add(i * 3) as u8;
            p[0] = v;
            p[1] = (x as u8).wrapping_add(i as u8);
            p[2] = (y as u8) ^ v;
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<u32> = std::env::args()
        .skip(1)
        .map(|a| a.parse())
        .collect::<Result<_, _>>()?;
    let arg = |i: usize, d: u32| args.get(i).copied().unwrap_or(d);
    let n = arg(0, 120);
    let cfg = EncoderConfig {
        max_width: arg(1, 1920),
        max_height: arg(2, 1080),
        fps: 30.0,
        bitrate_bps: arg(3, 6000) * 1000,
    };
    let threads = arg(4, 1) as u16;
    let busy = arg(5, 0) != 0;
    let tuning = fd_codec::EncoderTuning {
        threads,
        screen_content: arg(6, 1) != 0,
    };

    let mut cap = fd_capture::open_default()?;
    let (sw, sh) = cap.size();
    let conv = Converter::new(sw, sh, &cfg)?;
    let mut enc = VideoEncoder::with_tuning(sw, sh, cfg.clone(), tuning)?;
    let mut dec = VideoDecoder::new()?;
    let (ow, oh) = enc.output_size();
    println!(
        "source {sw}x{sh} -> {ow}x{oh}, {} kbps, {tuning:?}, busy={busy}, {n} frames",
        cfg.bitrate_bps / 1000
    );

    let (mut t_cap, mut t_conv, mut t_enc, mut t_dec) = (
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
    );
    let (mut bytes, mut encoded, mut skipped, mut decoded) = (0usize, 0u32, 0u32, 0u32);
    let mut first_kb = 0.0;
    let mut pic = conv.new_frame();
    let mut out_pic = DecodedFrame::empty();
    let mut scratch: Option<Frame> = None;
    let mut busy_time = Duration::ZERO;
    let total = Instant::now();
    for i in 0..n {
        let t = Instant::now();
        let frame = cap.capture_ref()?;
        t_cap += t.elapsed();

        let frame: FrameRef = if busy {
            let tb = Instant::now();
            let s = scratch.get_or_insert_with(|| Frame {
                width: 0,
                height: 0,
                stride: 0,
                data: vec![],
            });
            s.width = frame.width;
            s.height = frame.height;
            s.stride = frame.stride;
            s.data.clear();
            s.data.extend_from_slice(frame.data);
            paint_busy(s, i);
            busy_time += tb.elapsed();
            s.view()
        } else {
            frame
        };

        let t = Instant::now();
        conv.convert(frame, &mut pic)?;
        t_conv += t.elapsed();

        let t = Instant::now();
        let out = enc.encode_i420(&pic, false)?;
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
        if dec.decode_into(&out.data, &mut out_pic)? {
            assert_eq!((out_pic.width, out_pic.height), (ow, oh));
            decoded += 1;
        }
        t_dec += t.elapsed();
    }
    let wall = total.elapsed() - busy_time;

    // Forced keyframe size on the current content.
    let idr = loop {
        let frame = cap.capture()?;
        if let Some(f) = enc.encode(frame, true)? {
            break f;
        }
    };

    let nf = n as f64;
    println!("capture  {:7.2} ms/frame", ms(t_cap) / nf);
    println!(
        "convert  {:7.2} ms/frame (BGRX->I420 + scale)",
        ms(t_conv) / nf
    );
    println!("encode   {:7.2} ms/frame (OpenH264)", ms(t_enc) / nf);
    println!(
        "decode   {:7.2} ms/frame (OpenH264 + I420->RGBA)",
        ms(t_dec) / decoded.max(1) as f64
    );
    println!(
        "sequential {:7.2} ms/frame => {:.1} fps (all four stages)",
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

    // Pipelined: A = capture (+busy paint) + convert, B = encode. Two recycled I420 buffers.
    let (to_b, from_a) = mpsc::sync_channel::<I420Frame>(1);
    let (to_a, from_b) = mpsc::channel::<I420Frame>();
    to_a.send(conv.new_frame())?;
    to_a.send(conv.new_frame())?;
    let total = Instant::now();
    let produced = std::thread::scope(|s| -> anyhow::Result<u32> {
        let b = s.spawn(move || -> anyhow::Result<u32> {
            let mut got = 0;
            while let Ok(pic) = from_a.recv() {
                if enc.encode_i420(&pic, false)?.is_some() {
                    got += 1;
                }
                let _ = to_a.send(pic);
            }
            Ok(got)
        });
        for i in 0..n {
            let mut pic = from_b.recv()?;
            let frame = cap.capture_ref()?;
            if busy {
                let s = scratch.as_mut().expect("busy scratch");
                s.data.copy_from_slice(frame.data);
                paint_busy(s, i);
                conv.convert(&*s, &mut pic)?;
            } else {
                conv.convert(frame, &mut pic)?;
            }
            to_b.send(pic)?;
        }
        drop(to_b);
        b.join().expect("encoder thread")
    })?;
    let wall = total.elapsed();
    let pipelined = (ms(wall) / nf, nf / wall.as_secs_f64());

    // Change detection: poll capture_if_changed() at ~100 Hz for 1 s on the live screen.
    cap.capture()?;
    let (mut polls, mut unchanged, mut t_none, mut t_some) =
        (0u32, 0u32, Duration::ZERO, Duration::ZERO);
    let end = Instant::now() + Duration::from_secs(1);
    while Instant::now() < end {
        let t = Instant::now();
        let changed = cap.capture_if_changed()?.is_some();
        if changed {
            t_some += t.elapsed()
        } else {
            t_none += t.elapsed();
            unchanged += 1
        }
        polls += 1;
        std::thread::sleep(Duration::from_millis(10));
    }
    println!(
        "capture_if_changed: {unchanged}/{polls} polls unchanged ({:.3} ms each), changed grabs {:.2} ms each",
        ms(t_none) / unchanged.max(1) as f64,
        ms(t_some) / (polls - unchanged).max(1) as f64
    );
    let wall = Duration::from_secs_f64(pipelined.0 * nf / 1e3);
    println!(
        "pipelined (A: capture+convert, B: encode) {:7.2} ms/frame => {:.1} fps ({produced} encoded)",
        ms(wall) / nf,
        nf / wall.as_secs_f64()
    );
    Ok(())
}
