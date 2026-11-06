//! Colour conversion and scaling.
//!
//! BGRX -> I420 (BT.601 limited range) with downscaling, and I420 -> RGBA8 with the
//! matching inverse. Written as tight row loops over `chunks_exact` so LLVM can drop bounds
//! checks and vectorise; the encoder side is split into horizontal bands across threads.

// `as_chunks` (what clippy suggests) needs Rust 1.88; the workspace MSRV is 1.85.
#![allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]

use std::thread;

/// Fixed-point BT.601 limited range, 8-bit coefficients (the classic "studio swing" set).
#[inline(always)]
fn rgb_to_y(r: i32, g: i32, b: i32) -> u8 {
    (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16) as u8
}

/// Chroma from the *sum* of four RGB samples (2x2 block); the extra >>2 is folded into the shift.
#[inline(always)]
fn rgb4_to_uv(r: i32, g: i32, b: i32) -> (u8, u8) {
    let u = ((-38 * r - 74 * g + 112 * b + 512) >> 10) + 128;
    let v = ((112 * r - 94 * g - 18 * b + 512) >> 10) + 128;
    (u as u8, v as u8)
}

/// Convert two rows of BGRX (each exactly `w*4` bytes, `w` even) to two Y rows + one U and V row.
#[inline]
fn bgrx_rows_to_i420(
    r0: &[u8],
    r1: &[u8],
    y0: &mut [u8],
    y1: &mut [u8],
    u: &mut [u8],
    v: &mut [u8],
) {
    let it = r0
        .chunks_exact(8)
        .zip(r1.chunks_exact(8))
        .zip(y0.chunks_exact_mut(2))
        .zip(y1.chunks_exact_mut(2))
        .zip(u.iter_mut().zip(v.iter_mut()));
    for ((((a, b), ya), yb), (uo, vo)) in it {
        let (b00, g00, r00) = (a[0] as i32, a[1] as i32, a[2] as i32);
        let (b01, g01, r01) = (a[4] as i32, a[5] as i32, a[6] as i32);
        let (b10, g10, r10) = (b[0] as i32, b[1] as i32, b[2] as i32);
        let (b11, g11, r11) = (b[4] as i32, b[5] as i32, b[6] as i32);
        ya[0] = rgb_to_y(r00, g00, b00);
        ya[1] = rgb_to_y(r01, g01, b01);
        yb[0] = rgb_to_y(r10, g10, b10);
        yb[1] = rgb_to_y(r11, g11, b11);
        let (uu, vv) = rgb4_to_uv(
            r00 + r01 + r10 + r11,
            g00 + g01 + g10 + g11,
            b00 + b01 + b10 + b11,
        );
        *uo = uu;
        *vo = vv;
    }
}

/// 2x2 box filter of two source rows into one BGRX row of `out.len()/4` pixels.
#[inline]
fn box2_row(a: &[u8], b: &[u8], out: &mut [u8]) {
    for ((o, pa), pb) in out
        .chunks_exact_mut(4)
        .zip(a.chunks_exact(8))
        .zip(b.chunks_exact(8))
    {
        o[0] = ((pa[0] as u16 + pa[4] as u16 + pb[0] as u16 + pb[4] as u16 + 2) >> 2) as u8;
        o[1] = ((pa[1] as u16 + pa[5] as u16 + pb[1] as u16 + pb[5] as u16 + 2) >> 2) as u8;
        o[2] = ((pa[2] as u16 + pa[6] as u16 + pb[2] as u16 + pb[6] as u16 + 2) >> 2) as u8;
    }
}

/// k x k box filter (generic integer factor) of `k` source rows into one BGRX row.
fn boxk_row(src: &[u8], stride: usize, row0: usize, k: usize, out: &mut [u8]) {
    let n = (k * k) as u32;
    for (x, o) in out.chunks_exact_mut(4).enumerate() {
        let mut s = [0u32; 3];
        for dy in 0..k {
            let base = (row0 + dy) * stride + x * k * 4;
            for p in src[base..base + k * 4].chunks_exact(4) {
                s[0] += p[0] as u32;
                s[1] += p[1] as u32;
                s[2] += p[2] as u32;
            }
        }
        o[0] = ((s[0] + n / 2) / n) as u8;
        o[1] = ((s[1] + n / 2) / n) as u8;
        o[2] = ((s[2] + n / 2) / n) as u8;
    }
}

#[derive(Clone, Copy)]
struct Tap {
    /// Byte offset of the left/top sample (and +1 sample) in the source.
    i0: usize,
    i1: usize,
    /// Weight of sample 1, 0..=256.
    f: u32,
}

fn bilinear_taps(src: u32, dst: u32, unit: usize) -> Vec<Tap> {
    let scale = src as f64 / dst as f64;
    (0..dst)
        .map(|d| {
            let s = ((d as f64 + 0.5) * scale - 0.5).clamp(0.0, (src - 1) as f64);
            let s0 = s.floor() as u32;
            let s1 = (s0 + 1).min(src - 1);
            let f = ((s - s0 as f64) * 256.0).round() as u32;
            Tap {
                i0: s0 as usize * unit,
                i1: s1 as usize * unit,
                f,
            }
        })
        .collect()
}

#[inline]
fn bilinear_row(r0: &[u8], r1: &[u8], fy: u32, xt: &[Tap], out: &mut [u8]) {
    let gy = 256 - fy;
    for (o, t) in out.chunks_exact_mut(4).zip(xt) {
        let gx = 256 - t.f;
        for c in 0..3 {
            let top = r0[t.i0 + c] as u32 * gx + r0[t.i1 + c] as u32 * t.f;
            let bot = r1[t.i0 + c] as u32 * gx + r1[t.i1 + c] as u32 * t.f;
            o[c] = ((top * gy + bot * fy + (1 << 15)) >> 16) as u8;
        }
    }
}

enum Kind {
    /// Same size (possibly cropping one odd column/row).
    Copy,
    Box2,
    BoxK(usize),
    Bilinear {
        xt: Vec<Tap>,
        yt: Vec<Tap>,
    },
}

/// BGRX -> I420 converter for fixed source and destination sizes.
pub(crate) struct ToI420 {
    src_w: u32,
    src_h: u32,
    dst_w: u32,
    dst_h: u32,
    kind: Kind,
    threads: usize,
}

impl ToI420 {
    /// `dst_w`, `dst_h` must be even, non-zero and <= the source size.
    pub(crate) fn new(src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Self {
        assert!(dst_w >= 2 && dst_h >= 2 && dst_w % 2 == 0 && dst_h % 2 == 0);
        assert!(dst_w <= src_w && dst_h <= src_h);
        let kind = if dst_w == src_w & !1 && dst_h == src_h & !1 {
            Kind::Copy
        } else if dst_w * 2 == src_w && dst_h * 2 == src_h {
            Kind::Box2
        } else if src_w % dst_w == 0 && src_h % dst_h == 0 && src_w / dst_w == src_h / dst_h {
            Kind::BoxK((src_w / dst_w) as usize)
        } else {
            Kind::Bilinear {
                xt: bilinear_taps(src_w, dst_w, 4),
                yt: bilinear_taps(src_h, dst_h, 1),
            }
        };
        // Bands of row pairs across a few threads; small frames aren't worth the spawn cost.
        let threads = if dst_w * dst_h >= 640 * 360 {
            thread::available_parallelism()
                .map_or(1, |n| n.get())
                .clamp(1, 4)
        } else {
            1
        };
        Self {
            src_w,
            src_h,
            dst_w,
            dst_h,
            kind,
            threads,
        }
    }

    pub(crate) fn kind_name(&self) -> &'static str {
        match self.kind {
            Kind::Copy => "copy",
            Kind::Box2 => "box2",
            Kind::BoxK(_) => "boxN",
            Kind::Bilinear { .. } => "bilinear",
        }
    }

    /// Convert; `y` is `dst_w*dst_h`, `u`/`v` are `dst_w/2 * dst_h/2`.
    pub(crate) fn convert(
        &self,
        src: &[u8],
        stride: usize,
        y: &mut [u8],
        u: &mut [u8],
        v: &mut [u8],
    ) {
        let (w, h) = (self.dst_w as usize, self.dst_h as usize);
        assert!(stride >= self.src_w as usize * 4);
        assert!(src.len() >= stride * (self.src_h as usize - 1) + self.src_w as usize * 4);
        assert_eq!(y.len(), w * h);
        assert_eq!(u.len(), w / 2 * (h / 2));
        assert_eq!(v.len(), u.len());

        let pairs = h / 2;
        let per = pairs.div_ceil(self.threads);
        if self.threads == 1 {
            self.band(src, stride, 0, y, u, v);
            return;
        }
        thread::scope(|s| {
            let ys = y.chunks_mut(per * 2 * w);
            let us = u.chunks_mut(per * (w / 2));
            let vs = v.chunks_mut(per * (w / 2));
            for (i, ((yb, ub), vb)) in ys.zip(us).zip(vs).enumerate() {
                s.spawn(move || self.band(src, stride, i * per, yb, ub, vb));
            }
        });
    }

    /// Convert the destination row pairs starting at `pair0` covering `y.len() / (2w)` pairs.
    fn band(
        &self,
        src: &[u8],
        stride: usize,
        pair0: usize,
        y: &mut [u8],
        u: &mut [u8],
        v: &mut [u8],
    ) {
        let w = self.dst_w as usize;
        let row_bytes = w * 4;
        let mut t0 = vec![0u8; row_bytes];
        let mut t1 = vec![0u8; row_bytes];
        let src_row_bytes = self.src_w as usize * 4;
        let row = |r: usize| &src[r * stride..r * stride + src_row_bytes];

        for (p, ((yy, uu), vv)) in y
            .chunks_exact_mut(2 * w)
            .zip(u.chunks_exact_mut(w / 2))
            .zip(v.chunks_exact_mut(w / 2))
            .enumerate()
        {
            let dy = (pair0 + p) * 2;
            let (y0, y1) = yy.split_at_mut(w);
            match &self.kind {
                Kind::Copy => {
                    bgrx_rows_to_i420(
                        &row(dy)[..row_bytes],
                        &row(dy + 1)[..row_bytes],
                        y0,
                        y1,
                        uu,
                        vv,
                    );
                    continue;
                }
                Kind::Box2 => {
                    box2_row(row(2 * dy), row(2 * dy + 1), &mut t0);
                    box2_row(row(2 * dy + 2), row(2 * dy + 3), &mut t1);
                }
                Kind::BoxK(k) => {
                    boxk_row(src, stride, dy * k, *k, &mut t0);
                    boxk_row(src, stride, (dy + 1) * k, *k, &mut t1);
                }
                Kind::Bilinear { xt, yt } => {
                    let (a, b) = (yt[dy], yt[dy + 1]);
                    bilinear_row(row(a.i0), row(a.i1), a.f, xt, &mut t0);
                    bilinear_row(row(b.i0), row(b.i1), b.f, xt, &mut t1);
                }
            }
            bgrx_rows_to_i420(&t0, &t1, y0, y1, uu, vv);
        }
    }
}

#[inline(always)]
fn clamp8(x: i32) -> u8 {
    x.clamp(0, 255) as u8
}

/// Convert one output row. `orow` is `w*4` bytes; `yrow` has >= w, `urow`/`vrow` >= ceil(w/2).
#[inline]
fn i420_row_to_rgba(w: usize, yrow: &[u8], urow: &[u8], vrow: &[u8], orow: &mut [u8]) {
    let cw = w.div_ceil(2);
    let (yrow, urow, vrow) = (&yrow[..w], &urow[..cw], &vrow[..cw]);
    for (((o, yp), &uu), &vv) in orow
        .chunks_exact_mut(8)
        .zip(yrow.chunks_exact(2))
        .zip(urow)
        .zip(vrow)
    {
        let d = uu as i32 - 128;
        let e = vv as i32 - 128;
        let (ruv, guv, buv) = (409 * e + 128, -100 * d - 208 * e + 128, 516 * d + 128);
        let c0 = 298 * (yp[0] as i32 - 16);
        let c1 = 298 * (yp[1] as i32 - 16);
        o[0] = clamp8((c0 + ruv) >> 8);
        o[1] = clamp8((c0 + guv) >> 8);
        o[2] = clamp8((c0 + buv) >> 8);
        o[3] = 255;
        o[4] = clamp8((c1 + ruv) >> 8);
        o[5] = clamp8((c1 + guv) >> 8);
        o[6] = clamp8((c1 + buv) >> 8);
        o[7] = 255;
    }
    if w % 2 == 1 {
        let d = urow[cw - 1] as i32 - 128;
        let e = vrow[cw - 1] as i32 - 128;
        let c = 298 * (yrow[w - 1] as i32 - 16) + 128;
        let o = &mut orow[(w - 1) * 4..];
        o[0] = clamp8((c + 409 * e) >> 8);
        o[1] = clamp8((c - 100 * d - 208 * e) >> 8);
        o[2] = clamp8((c + 516 * d) >> 8);
        o[3] = 255;
    }
}

/// I420 (BT.601 limited) -> tightly packed RGBA8. Handles odd sizes; bands across threads.
#[allow(clippy::too_many_arguments)]
pub(crate) fn i420_to_rgba(
    w: usize,
    h: usize,
    y: &[u8],
    ys: usize,
    u: &[u8],
    us: usize,
    v: &[u8],
    vs: usize,
    out: &mut [u8],
) {
    assert_eq!(out.len(), w * h * 4);
    if w == 0 || h == 0 {
        return;
    }
    let band = |row0: usize, ob: &mut [u8]| {
        for (i, orow) in ob.chunks_exact_mut(w * 4).enumerate() {
            let r = row0 + i;
            let c = r / 2;
            i420_row_to_rgba(w, &y[r * ys..], &u[c * us..], &v[c * vs..], orow);
        }
    };
    let threads = if w * h >= 640 * 360 {
        thread::available_parallelism()
            .map_or(1, |n| n.get())
            .clamp(1, 4)
    } else {
        1
    };
    if threads == 1 {
        band(0, out);
        return;
    }
    let rows_per = h.div_ceil(threads);
    thread::scope(|s| {
        for (i, ob) in out.chunks_mut(rows_per * w * 4).enumerate() {
            let band = &band;
            s.spawn(move || band(i * rows_per, ob));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: u32, h: u32, bgrx: [u8; 4]) -> Vec<u8> {
        bgrx.iter()
            .copied()
            .cycle()
            .take((w * h * 4) as usize)
            .collect()
    }

    fn roundtrip(src_w: u32, src_h: u32, dst_w: u32, dst_h: u32, bgr: [u8; 3]) {
        let src = solid(src_w, src_h, [bgr[0], bgr[1], bgr[2], 0]);
        let c = ToI420::new(src_w, src_h, dst_w, dst_h);
        let (w, h) = (dst_w as usize, dst_h as usize);
        let (mut y, mut u, mut v) = (vec![0; w * h], vec![0; w * h / 4], vec![0; w * h / 4]);
        c.convert(&src, src_w as usize * 4, &mut y, &mut u, &mut v);
        let mut rgba = vec![0; w * h * 4];
        i420_to_rgba(w, h, &y, w, &u, w / 2, &v, w / 2, &mut rgba);
        for px in rgba.chunks_exact(4) {
            for (c, want) in [(0, bgr[2]), (1, bgr[1]), (2, bgr[0])] {
                assert!(
                    (px[c] as i32 - want as i32).abs() <= 3,
                    "{} kind: got {:?} want bgr {:?}",
                    c,
                    px,
                    bgr
                );
            }
            assert_eq!(px[3], 255);
        }
    }

    #[test]
    fn colour_roundtrip_all_kinds() {
        for bgr in [
            [0, 0, 0],
            [255, 255, 255],
            [0, 0, 255],
            [0, 255, 0],
            [255, 0, 0],
            [40, 120, 200],
        ] {
            roundtrip(64, 48, 64, 48, bgr); // copy
            roundtrip(65, 49, 64, 48, bgr); // copy w/ crop
            roundtrip(128, 96, 64, 48, bgr); // box2
            roundtrip(192, 144, 64, 48, bgr); // box3
            roundtrip(100, 75, 64, 48, bgr); // bilinear
            roundtrip(1280, 720, 960, 540, bgr); // bilinear, threaded
        }
    }

    #[test]
    fn kinds_selected() {
        assert_eq!(ToI420::new(3840, 2160, 1920, 1080).kind_name(), "box2");
        assert_eq!(ToI420::new(3840, 2160, 1280, 720).kind_name(), "boxN");
        assert_eq!(ToI420::new(1920, 1080, 1920, 1080).kind_name(), "copy");
        assert_eq!(ToI420::new(2560, 1440, 1920, 1080).kind_name(), "bilinear");
    }

    #[test]
    fn box2_averages() {
        // Left half black, right half white at 2x2 granularity: average to mid-grey per pixel.
        let (sw, sh) = (8u32, 4u32);
        let mut src = vec![0u8; (sw * sh * 4) as usize];
        for r in 0..sh as usize {
            for x in 0..sw as usize {
                let val = if x % 2 == 0 { 0 } else { 255 };
                src[(r * sw as usize + x) * 4..][..3].fill(val);
            }
        }
        let c = ToI420::new(sw, sh, 4, 2);
        let (mut y, mut u, mut v) = (vec![0; 8], vec![0; 2], vec![0; 2]);
        c.convert(&src, sw as usize * 4, &mut y, &mut u, &mut v);
        for &yy in &y {
            assert!((yy as i32 - 126).abs() <= 2, "{y:?}");
        }
    }
}
