//! Video codec: BGRX capture frames -> H.264 (OpenH264, software) -> RGBA8.
//!
//! Colour: BT.601 limited range in both directions (signalled in the SPS VUI).
//! Bitstream: Annex-B, Constrained Baseline (OpenH264 never emits B-frames), one access unit
//! per encode call, `threads` slices per picture; every IDR carries SPS+PPS so a fresh
//! decoder can join at any keyframe.
//!
//! Pipelining: [`Converter`] (BGRX -> I420 + downscale) is independent of [`VideoEncoder`], so
//! capture+convert can run on one thread and encode on another, passing recycled
//! [`I420Frame`]s between them. [`VideoEncoder::encode`] still does both in one call.

mod convert;
mod h264;

use std::time::Instant;

use anyhow::{bail, Context};
use fd_capture::FrameRef;
use openh264::formats::YUVSource;

/// OpenH264 encoder limit (level 5.2), landscape orientation.
const MAX_ENC_LONG: u32 = 3840;
const MAX_ENC_SHORT: u32 = 2160;

/// Decoder output limits (defence in depth against a hostile host).
pub const MAX_DECODE_DIM: u32 = 8192;
pub const MAX_DECODE_PIXELS: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct EncoderConfig {
    /// Downscale (keeping aspect) so the output fits within these bounds. Output dims are even.
    pub max_width: u32,
    pub max_height: u32,
    pub fps: f32,
    pub bitrate_bps: u32,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            max_width: 1920,
            max_height: 1080,
            fps: 30.0,
            bitrate_bps: 6_000_000,
        }
    }
}

pub struct EncodedFrame {
    /// H.264 Annex-B access unit.
    pub data: Vec<u8>,
    pub keyframe: bool,
}

/// Output size: fit `src` inside `max` (and the OpenH264 limit) keeping aspect, never upscaling,
/// rounded down to even, at least 2x2.
pub fn fit_size(src_w: u32, src_h: u32, max_w: u32, max_h: u32) -> (u32, u32) {
    let (lim_w, lim_h) = if src_w >= src_h {
        (MAX_ENC_LONG, MAX_ENC_SHORT)
    } else {
        (MAX_ENC_SHORT, MAX_ENC_LONG)
    };
    let max_w = max_w.clamp(2, lim_w).min(src_w) as u64;
    let max_h = max_h.clamp(2, lim_h).min(src_h) as u64;
    let (sw, sh) = (src_w as u64, src_h as u64);
    let (w, h) = if max_w * sh <= max_h * sw {
        (max_w, (sh * max_w / sw).min(max_h))
    } else {
        ((sw * max_h / sh).min(max_w), max_h)
    };
    (((w as u32) & !1).max(2), ((h as u32) & !1).max(2))
}

/// An owned, reusable I420 picture (tightly packed planes: Y stride = width, U/V stride = width/2).
/// Width and height are even.
#[derive(Clone)]
pub struct I420Frame {
    width: u32,
    height: u32,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
}

impl I420Frame {
    /// A black picture. `width`/`height` are rounded down to even (min 2).
    pub fn new(width: u32, height: u32) -> Self {
        let (width, height) = ((width & !1).max(2), (height & !1).max(2));
        let (w, h) = (width as usize, height as usize);
        Self {
            width,
            height,
            y: vec![16; w * h],
            u: vec![128; w * h / 4],
            v: vec![128; w * h / 4],
        }
    }
    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
    /// (Y, U, V) planes.
    pub fn planes(&self) -> (&[u8], &[u8], &[u8]) {
        (&self.y, &self.u, &self.v)
    }
    fn resize(&mut self, width: u32, height: u32) {
        if (self.width, self.height) != (width, height) {
            *self = Self::new(width, height);
        }
    }
}

/// BGRX -> I420 colour conversion + downscale for a fixed source size. `Send + Sync`; uses up
/// to 4 short-lived worker threads per call for large frames.
pub struct Converter {
    src: (u32, u32),
    out: (u32, u32),
    conv: convert::ToI420,
}

impl Converter {
    /// Output size is `fit_size(src, cfg.max_width, cfg.max_height)`, identical to the
    /// `VideoEncoder::output_size()` of an encoder created with the same arguments.
    pub fn new(src_width: u32, src_height: u32, cfg: &EncoderConfig) -> anyhow::Result<Self> {
        if src_width < 2 || src_height < 2 {
            bail!("fd-codec: source size {src_width}x{src_height} too small");
        }
        let out = fit_size(src_width, src_height, cfg.max_width, cfg.max_height);
        let conv = convert::ToI420::new(src_width, src_height, out.0, out.1);
        log::debug!(
            "fd-codec: converter {src_width}x{src_height} -> {}x{} ({})",
            out.0,
            out.1,
            conv.kind_name()
        );
        Ok(Self {
            src: (src_width, src_height),
            out,
            conv,
        })
    }

    pub fn source_size(&self) -> (u32, u32) {
        self.src
    }

    pub fn output_size(&self) -> (u32, u32) {
        self.out
    }

    /// A correctly sized output buffer (allocate a few and recycle them between threads).
    pub fn new_frame(&self) -> I420Frame {
        I420Frame::new(self.out.0, self.out.1)
    }

    /// Convert `frame` (`&Frame` or a borrowed `FrameRef`) into `out` (reallocated only if it
    /// has the wrong size). Errors if the frame's size differs from the converter's source size
    /// (screen resized).
    pub fn convert<'a>(
        &self,
        frame: impl Into<FrameRef<'a>>,
        out: &mut I420Frame,
    ) -> anyhow::Result<()> {
        let frame = frame.into();
        if (frame.width, frame.height) != self.src {
            bail!(
                "fd-codec: frame is {}x{} but converter was created for {}x{} (screen resized? recreate it)",
                frame.width,
                frame.height,
                self.src.0,
                self.src.1
            );
        }
        let need = frame.stride * (frame.height as usize - 1) + frame.width as usize * 4;
        if frame.stride < frame.width as usize * 4 || frame.data.len() < need {
            bail!(
                "fd-codec: frame buffer too small (stride {}, {} bytes)",
                frame.stride,
                frame.data.len()
            );
        }
        out.resize(self.out.0, self.out.1);
        self.conv
            .convert(frame.data, frame.stride, &mut out.y, &mut out.u, &mut out.v);
        Ok(())
    }
}

/// Default encoder thread / slice count for [`EncoderTuning::fast`]: available cores, capped at 4.
pub fn default_encoder_threads() -> u16 {
    std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, 4) as u16
}

/// OpenH264 speed/size trade-off.
///
/// Measured on the21th (Xeon W-2125, 1920x1080, nasm): `screen()` (default) encodes in
/// ~18-23 ms/frame single-threaded with tiny P-frames on static/text content (~0.2 KB);
/// `fast()` encodes in ~10-12 ms but P-frames are ~1.7x larger on motion and ~9 KB even on a
/// static screen. Screen-content mode's analysis is single-threaded: slices make it *slower*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderTuning {
    /// Encoder threads == slices per picture (1 = single slice).
    pub threads: u16,
    /// Use OpenH264's screen-content mode (better compression of desktop content).
    pub screen_content: bool,
}

impl EncoderTuning {
    /// Screen-content mode, single slice. The default.
    pub fn screen() -> Self {
        Self {
            threads: 1,
            screen_content: true,
        }
    }
    /// Camera mode with multi-slice threading: ~2x faster encode, more bits.
    pub fn fast() -> Self {
        Self {
            threads: default_encoder_threads(),
            screen_content: false,
        }
    }
}

impl Default for EncoderTuning {
    fn default() -> Self {
        Self::screen()
    }
}

pub struct VideoEncoder {
    conv: Converter,
    pic: I420Frame,
    enc: h264::H264Encoder,
    frames: u64,
    /// A forced keyframe was requested but not yet delivered (e.g. the frame was skipped).
    idr_pending: bool,
    start: Instant,
}

impl VideoEncoder {
    /// Encoder with the default [`EncoderTuning`] (screen content, single slice).
    pub fn new(src_width: u32, src_height: u32, cfg: EncoderConfig) -> anyhow::Result<Self> {
        Self::with_tuning(src_width, src_height, cfg, EncoderTuning::default())
    }

    pub fn with_tuning(
        src_width: u32,
        src_height: u32,
        cfg: EncoderConfig,
        tuning: EncoderTuning,
    ) -> anyhow::Result<Self> {
        if !(cfg.fps > 0.0 && cfg.fps <= 240.0) {
            bail!("fd-codec: fps {} out of range", cfg.fps);
        }
        if cfg.bitrate_bps < 10_000 || cfg.bitrate_bps > i32::MAX as u32 {
            bail!("fd-codec: bitrate {} out of range", cfg.bitrate_bps);
        }
        let conv = Converter::new(src_width, src_height, &cfg)?;
        let out = conv.output_size();
        let threads = tuning.threads.clamp(1, 16);
        let enc = h264::H264Encoder::new(&h264::Params {
            width: out.0,
            height: out.1,
            fps: cfg.fps,
            bitrate_bps: cfg.bitrate_bps,
            threads,
            screen_content: tuning.screen_content,
        })
        .context("fd-codec: OpenH264 encoder")?;
        log::info!(
            "fd-codec: encoder {src_width}x{src_height} -> {}x{}, {} fps, {} kbps, {threads} slice thread(s), {}",
            out.0,
            out.1,
            cfg.fps,
            cfg.bitrate_bps / 1000,
            if tuning.screen_content { "screen-content" } else { "camera" }
        );
        Ok(Self {
            pic: conv.new_frame(),
            conv,
            enc,
            frames: 0,
            idr_pending: false,
            start: Instant::now(),
        })
    }

    /// Encoded (possibly downscaled) output size.
    pub fn output_size(&self) -> (u32, u32) {
        self.conv.output_size()
    }

    /// Convert + encode a BGRX frame. Returns None if the encoder skipped the frame (rate control).
    /// A requested keyframe that gets skipped is retried automatically on the next call.
    pub fn encode<'a>(
        &mut self,
        frame: impl Into<FrameRef<'a>>,
        force_keyframe: bool,
    ) -> anyhow::Result<Option<EncodedFrame>> {
        let mut pic = std::mem::replace(
            &mut self.pic,
            I420Frame {
                width: 0,
                height: 0,
                y: vec![],
                u: vec![],
                v: vec![],
            },
        );
        let r = self
            .conv
            .convert(frame, &mut pic)
            .and_then(|()| self.encode_i420(&pic, force_keyframe));
        self.pic = pic;
        r
    }

    /// Encode an already converted picture (from a [`Converter`] with the same source size and
    /// config). Must be exactly `output_size()`. Same skip / keyframe semantics as `encode`.
    pub fn encode_i420(
        &mut self,
        pic: &I420Frame,
        force_keyframe: bool,
    ) -> anyhow::Result<Option<EncodedFrame>> {
        if (pic.width, pic.height) != self.output_size() {
            bail!(
                "fd-codec: I420 picture is {}x{}, encoder expects {}x{}",
                pic.width,
                pic.height,
                self.output_size().0,
                self.output_size().1
            );
        }
        self.idr_pending |= force_keyframe;
        if self.idr_pending {
            self.enc.force_idr();
        }
        let ts = self.start.elapsed().as_millis() as i64;
        let mut data = Vec::new();
        let ty = self
            .enc
            .encode(&pic.y, &pic.u, &pic.v, ts, &mut data)
            .context("fd-codec: H.264 encode failed")?;
        self.frames += 1;
        if ty == h264::PicType::Skip || data.is_empty() {
            return Ok(None);
        }
        let keyframe = ty == h264::PicType::Idr;
        if keyframe {
            self.idr_pending = false;
        }
        Ok(Some(EncodedFrame { data, keyframe }))
    }
}

pub struct DecodedFrame {
    pub width: u32,
    pub height: u32,
    /// Tightly packed RGBA8, width*height*4 bytes.
    pub rgba: Vec<u8>,
}

impl DecodedFrame {
    /// An empty frame to pass to [`VideoDecoder::decode_into`].
    pub fn empty() -> Self {
        Self {
            width: 0,
            height: 0,
            rgba: Vec::new(),
        }
    }
}

fn check_decode_dims(w: usize, h: usize) -> anyhow::Result<()> {
    if w == 0
        || h == 0
        || w > MAX_DECODE_DIM as usize
        || h > MAX_DECODE_DIM as usize
        || (w as u64 * h as u64) > MAX_DECODE_PIXELS
    {
        bail!("fd-codec: refusing decoded picture of {w}x{h} (limit {MAX_DECODE_DIM}x{MAX_DECODE_DIM}, 64 MP)");
    }
    Ok(())
}

pub struct VideoDecoder {
    dec: openh264::decoder::Decoder,
}

impl VideoDecoder {
    pub fn new() -> anyhow::Result<Self> {
        let dec = openh264::decoder::Decoder::new().context("fd-codec: OpenH264 decoder")?;
        Ok(Self { dec })
    }

    /// Decode one Annex-B access unit. Returns None if no picture is ready yet.
    pub fn decode(&mut self, data: &[u8]) -> anyhow::Result<Option<DecodedFrame>> {
        let mut out = DecodedFrame::empty();
        Ok(self.decode_into(data, &mut out)?.then_some(out))
    }

    /// Like [`decode`](Self::decode) but writes into `out`, reusing its RGBA allocation.
    /// Returns `true` if `out` now holds a new picture (`false`: no picture yet, `out` untouched).
    pub fn decode_into(&mut self, data: &[u8], out: &mut DecodedFrame) -> anyhow::Result<bool> {
        let Some(yuv) = self
            .dec
            .decode(data)
            .context("fd-codec: H.264 decode failed")?
        else {
            return Ok(false);
        };
        let (w, h) = yuv.dimensions();
        check_decode_dims(w, h)?;
        let (ys, us, vs) = yuv.strides();
        out.rgba.resize(w * h * 4, 0);
        convert::i420_to_rgba(w, h, yuv.y(), ys, yuv.u(), us, yuv.v(), vs, &mut out.rgba);
        out.width = w as u32;
        out.height = h as u32;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fd_capture::Frame;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn codec_types_are_send() {
        assert_send::<VideoEncoder>();
        assert_send::<VideoDecoder>();
        assert_send::<Converter>();
        assert_sync::<Converter>();
        assert_send::<I420Frame>();
    }

    #[test]
    fn fit_sizes() {
        assert_eq!(fit_size(3840, 2160, 1920, 1080), (1920, 1080));
        assert_eq!(fit_size(1920, 1080, 1920, 1080), (1920, 1080));
        assert_eq!(fit_size(1366, 768, 1920, 1080), (1366, 768));
        assert_eq!(fit_size(1365, 767, 1920, 1080), (1364, 766));
        assert_eq!(fit_size(2560, 1600, 1920, 1080), (1728, 1080));
        assert_eq!(fit_size(5120, 2880, 8000, 8000), (3840, 2160));
        assert_eq!(fit_size(1080, 1920, 1920, 1080), (606, 1080));
        assert_eq!(fit_size(2560, 1440, 1600, 900), (1600, 900));
        assert_eq!(fit_size(1280, 720, 1280, 720), (1280, 720));
        assert_eq!(fit_size(3, 3, 64, 64), (2, 2));
        assert_eq!(fit_size(3840, 2160, 64, 64), (64, 36));
    }

    #[test]
    fn decode_limits() {
        assert!(check_decode_dims(1920, 1080).is_ok());
        assert!(check_decode_dims(8192, 8192).is_ok());
        assert!(check_decode_dims(8193, 2).is_err());
        assert!(check_decode_dims(2, 8193).is_err());
        assert!(check_decode_dims(0, 10).is_err());
    }

    /// Synthetic BGRX frame: four solid quadrants (red, green, blue, white).
    fn quadrants(w: u32, h: u32) -> Frame {
        let stride = w as usize * 4 + 64; // padded stride on purpose
        let mut data = vec![0u8; stride * h as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let bgr = match (x < w as usize / 2, y < h as usize / 2) {
                    (true, true) => [0, 0, 255],
                    (false, true) => [0, 255, 0],
                    (true, false) => [255, 0, 0],
                    (false, false) => [255, 255, 255],
                };
                data[y * stride + x * 4..][..3].copy_from_slice(&bgr);
            }
        }
        Frame {
            width: w,
            height: h,
            stride,
            data,
        }
    }

    fn px(f: &DecodedFrame, x: u32, y: u32) -> [u8; 3] {
        let i = ((y * f.width + x) * 4) as usize;
        [f.rgba[i], f.rgba[i + 1], f.rgba[i + 2]]
    }

    fn nal_types(au: &[u8]) -> Vec<u8> {
        openh264::nal_units(au)
            .map(|n| {
                let body = n
                    .iter()
                    .skip_while(|&&b| b == 0)
                    .skip(1)
                    .copied()
                    .next()
                    .unwrap_or(0);
                body & 0x1f
            })
            .collect()
    }

    fn close(a: [u8; 3], b: [u8; 3]) -> bool {
        a.iter()
            .zip(b)
            .all(|(&x, y)| (x as i32 - y as i32).abs() <= 24)
    }

    fn check_quadrants(d: &DecodedFrame) {
        let (w, h) = (d.width, d.height);
        for (x, y, want) in [
            (w / 4, h / 4, [255, 0, 0]),
            (3 * w / 4, h / 4, [0, 255, 0]),
            (w / 4, 3 * h / 4, [0, 0, 255]),
            (3 * w / 4, 3 * h / 4, [255, 255, 255]),
        ] {
            let got = px(d, x, y);
            assert!(close(got, want), "at ({x},{y}) got {got:?} want {want:?}");
        }
    }

    fn roundtrip(tuning: EncoderTuning) {
        let threads = tuning.threads;
        let frame = quadrants(1280, 720);
        let cfg = EncoderConfig {
            max_width: 640,
            max_height: 640,
            fps: 30.0,
            bitrate_bps: 2_000_000,
        };
        let mut enc = VideoEncoder::with_tuning(1280, 720, cfg, tuning).unwrap();
        assert_eq!(enc.output_size(), (640, 360));
        let mut dec = VideoDecoder::new().unwrap();

        let first = enc.encode(&frame, false).unwrap().expect("first frame");
        assert!(first.keyframe, "first frame must be a keyframe");
        assert_eq!(&first.data[..4], &[0, 0, 0, 1], "Annex-B start code");
        let slices = nal_types(&first.data).iter().filter(|&&t| t == 5).count();
        assert_eq!(slices, threads.max(1) as usize, "one IDR slice per thread");
        let mut d = DecodedFrame::empty();
        assert!(
            dec.decode_into(&first.data, &mut d).unwrap(),
            "decoded picture"
        );
        assert_eq!((d.width, d.height), (640, 360));
        assert_eq!(d.rgba.len(), 640 * 360 * 4);
        check_quadrants(&d);

        // A few P-frames of the same content, then a forced keyframe.
        for _ in 0..3 {
            if let Some(p) = enc.encode(&frame, false).unwrap() {
                assert!(!p.keyframe);
                dec.decode_into(&p.data, &mut d).unwrap();
            }
        }
        let idr = enc.encode(&frame, true).unwrap().expect("forced keyframe");
        assert!(idr.keyframe, "force_keyframe must produce an IDR");
        let types = nal_types(&idr.data);
        assert!(
            types.contains(&5) && types.contains(&7) && types.contains(&8),
            "IDR+SPS+PPS, got {types:?}"
        );

        // A brand-new decoder must be able to start at the forced keyframe (SPS/PPS included).
        let mut fresh = VideoDecoder::new().unwrap();
        let d2 = fresh
            .decode(&idr.data)
            .unwrap()
            .expect("fresh decoder joins at IDR");
        assert_eq!((d2.width, d2.height), (640, 360));
        check_quadrants(&d2);
    }

    #[test]
    fn encode_decode_roundtrip_single_slice() {
        roundtrip(EncoderTuning::screen());
    }

    #[test]
    fn encode_decode_roundtrip_multi_slice() {
        roundtrip(EncoderTuning {
            threads: 4,
            screen_content: true,
        });
        roundtrip(EncoderTuning {
            threads: 4,
            screen_content: false,
        });
    }

    #[test]
    fn split_pipeline_matches() {
        let frame = quadrants(1920, 1080);
        let cfg = EncoderConfig {
            max_width: 960,
            max_height: 960,
            ..Default::default()
        };
        let conv = Converter::new(1920, 1080, &cfg).unwrap();
        let mut enc = VideoEncoder::new(1920, 1080, cfg).unwrap();
        assert_eq!(conv.output_size(), enc.output_size());
        let mut pic = conv.new_frame();
        // Convert on another thread, as the host pipeline does.
        std::thread::scope(|s| {
            s.spawn(|| conv.convert(&frame, &mut pic).unwrap());
        });
        let out = enc.encode_i420(&pic, false).unwrap().expect("frame");
        assert!(out.keyframe);
        let d = VideoDecoder::new()
            .unwrap()
            .decode(&out.data)
            .unwrap()
            .unwrap();
        assert_eq!((d.width, d.height), (960, 540));
        check_quadrants(&d);
        // Wrong-size picture is rejected.
        assert!(enc.encode_i420(&I420Frame::new(640, 360), false).is_err());
    }

    /// Viewer-zoom style crops: arbitrary odd sizes and ratios, small max sizes, 1:1.
    #[test]
    fn encode_cropped_regions() {
        let full = quadrants(1280, 720);
        // Centred crops keep all four quadrants visible.
        for (cw, ch, max_w, max_h, want) in [
            (1001u32, 667u32, 640u32, 640u32, (640u32, 426u32)),
            (641, 361, 1920, 1080, (640, 360)), // 1:1 (odd -> even crop)
            (333, 211, 64, 64, (64, 40)),       // small max
            (99, 99, 1920, 1080, (98, 98)),
        ] {
            let (x, y) = ((1280 - cw) / 2, (720 - ch) / 2);
            let view = fd_capture::crop(full.view(), x, y, cw, ch);
            assert_eq!((view.width, view.height), (cw, ch));
            let cfg = EncoderConfig {
                max_width: max_w,
                max_height: max_h,
                ..Default::default()
            };
            let mut enc = VideoEncoder::new(cw, ch, cfg).unwrap();
            assert_eq!(
                enc.output_size(),
                want,
                "crop {cw}x{ch} max {max_w}x{max_h}"
            );
            let out = enc.encode(view, false).unwrap().expect("frame");
            let d = VideoDecoder::new()
                .unwrap()
                .decode(&out.data)
                .unwrap()
                .unwrap();
            assert_eq!((d.width, d.height), want);
            check_quadrants(&d);
        }
    }

    #[test]
    fn rejects_wrong_frame_size() {
        let mut enc = VideoEncoder::new(640, 360, EncoderConfig::default()).unwrap();
        let frame = quadrants(320, 180);
        assert!(enc.encode(&frame, false).is_err());
    }
}
