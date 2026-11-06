//! Video codec: BGRX capture frames -> H.264 (OpenH264, software) -> RGBA8.
//!
//! Colour: BT.601 limited range in both directions (signalled in the SPS VUI).
//! Bitstream: Annex-B, Constrained-Baseline-style (OpenH264 never emits B-frames), one
//! access unit per [`VideoEncoder::encode`] call; every IDR carries SPS+PPS so a fresh
//! decoder can join at any keyframe.

mod convert;

use std::time::Instant;

use anyhow::{bail, Context};
use fd_capture::Frame;
use openh264::encoder::{
    BitRate, Complexity, Encoder, EncoderConfig as H264Config, FrameRate, FrameType, IntraFramePeriod, Profile,
    RateControlMode, UsageType, VuiConfig,
};
use openh264::formats::{YUVSlices, YUVSource};
use openh264::{OpenH264API, Timestamp};

/// OpenH264 encoder limit (level 5.2), landscape orientation.
const MAX_ENC_LONG: u32 = 3840;
const MAX_ENC_SHORT: u32 = 2160;

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
        Self { max_width: 1920, max_height: 1080, fps: 30.0, bitrate_bps: 6_000_000 }
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
    let (lim_w, lim_h) = if src_w >= src_h { (MAX_ENC_LONG, MAX_ENC_SHORT) } else { (MAX_ENC_SHORT, MAX_ENC_LONG) };
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

pub struct VideoEncoder {
    src: (u32, u32),
    out: (u32, u32),
    conv: convert::ToI420,
    enc: Encoder,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
    frames: u64,
    /// A forced keyframe was requested but not yet delivered (e.g. the frame was skipped).
    idr_pending: bool,
    start: Instant,
}

impl VideoEncoder {
    pub fn new(src_width: u32, src_height: u32, cfg: EncoderConfig) -> anyhow::Result<Self> {
        if src_width < 2 || src_height < 2 {
            bail!("fd-codec: source size {src_width}x{src_height} too small");
        }
        if !(cfg.fps > 0.0 && cfg.fps <= 240.0) {
            bail!("fd-codec: fps {} out of range", cfg.fps);
        }
        if cfg.bitrate_bps < 10_000 || cfg.bitrate_bps > i32::MAX as u32 {
            bail!("fd-codec: bitrate {} out of range", cfg.bitrate_bps);
        }
        let out = fit_size(src_width, src_height, cfg.max_width, cfg.max_height);
        let h264 = H264Config::new()
            .usage_type(UsageType::ScreenContentRealTime)
            .profile(Profile::Baseline)
            .rate_control_mode(RateControlMode::Bitrate)
            .bitrate(BitRate::from_bps(cfg.bitrate_bps))
            .max_frame_rate(FrameRate::from_hz(cfg.fps))
            // OpenH264 can only hold the bitrate if it may skip frames (encode() then returns None).
            .skip_frames(true)
            // Not supported for screen content; set explicitly to silence OpenH264 warnings.
            .adaptive_quantization(false)
            .background_detection(false)
            .complexity(Complexity::Low)
            // No periodic IDRs: the transport is reliable; keyframes come on demand (force_keyframe).
            .intra_frame_period(IntraFramePeriod::from_num_frames(0))
            .scene_change_detect(true)
            .vui(VuiConfig::bt601());
        let enc = Encoder::with_api_config(OpenH264API::from_source(), h264).context("fd-codec: OpenH264 encoder")?;
        let conv = convert::ToI420::new(src_width, src_height, out.0, out.1);
        log::info!(
            "fd-codec: encoder {src_width}x{src_height} -> {}x{} ({}), {} fps, {} kbps",
            out.0,
            out.1,
            conv.kind_name(),
            cfg.fps,
            cfg.bitrate_bps / 1000
        );
        let (w, h) = (out.0 as usize, out.1 as usize);
        Ok(Self {
            src: (src_width, src_height),
            out,
            conv,
            enc,
            y: vec![0; w * h],
            u: vec![0; w / 2 * (h / 2)],
            v: vec![0; w / 2 * (h / 2)],
            frames: 0,
            idr_pending: false,
            start: Instant::now(),
        })
    }

    /// Encoded (possibly downscaled) output size.
    pub fn output_size(&self) -> (u32, u32) {
        self.out
    }

    /// Encode a BGRX frame. Returns None if the encoder skipped the frame (rate control).
    /// A requested keyframe that gets skipped is retried automatically on the next call.
    pub fn encode(&mut self, frame: &Frame, force_keyframe: bool) -> anyhow::Result<Option<EncodedFrame>> {
        self.convert(frame)?;
        self.encode_converted(force_keyframe)
    }

    /// First half of [`encode`](Self::encode): colour-convert/scale into the internal I420 buffers.
    /// Exposed for benchmarking.
    pub fn convert(&mut self, frame: &Frame) -> anyhow::Result<()> {
        if (frame.width, frame.height) != self.src {
            bail!(
                "fd-codec: frame is {}x{} but encoder was created for {}x{} (screen resized? recreate the encoder)",
                frame.width,
                frame.height,
                self.src.0,
                self.src.1
            );
        }
        let need = frame.stride * (frame.height as usize - 1) + frame.width as usize * 4;
        if frame.stride < frame.width as usize * 4 || frame.data.len() < need {
            bail!("fd-codec: frame buffer too small (stride {}, {} bytes)", frame.stride, frame.data.len());
        }
        self.conv.convert(&frame.data, frame.stride, &mut self.y, &mut self.u, &mut self.v);
        Ok(())
    }

    /// Second half of [`encode`](Self::encode): H.264-encode the internal I420 buffers.
    pub fn encode_converted(&mut self, force_keyframe: bool) -> anyhow::Result<Option<EncodedFrame>> {
        let (w, h) = (self.out.0 as usize, self.out.1 as usize);
        let yuv = YUVSlices::new((&self.y, &self.u, &self.v), (w, h), (w, w / 2, w / 2));
        self.idr_pending |= force_keyframe;
        // The first frame is always an IDR; before that the encoder isn't initialised yet.
        if self.idr_pending && self.frames > 0 {
            self.enc.force_intra_frame();
        }
        let ts = Timestamp::from_millis(self.start.elapsed().as_millis() as u64);
        let bs = self.enc.encode_at(&yuv, ts).context("fd-codec: H.264 encode failed")?;
        self.frames += 1;
        let ft = bs.frame_type();
        if matches!(ft, FrameType::Skip | FrameType::Invalid) {
            return Ok(None);
        }
        let data = bs.to_vec();
        if data.is_empty() {
            return Ok(None);
        }
        let keyframe = ft == FrameType::IDR;
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
        let Some(yuv) = self.dec.decode(data).context("fd-codec: H.264 decode failed")? else {
            return Ok(None);
        };
        let (w, h) = yuv.dimensions();
        let (ys, us, vs) = yuv.strides();
        let mut rgba = vec![0u8; w * h * 4];
        convert::i420_to_rgba(w, h, yuv.y(), ys, yuv.u(), us, yuv.v(), vs, &mut rgba);
        Ok(Some(DecodedFrame { width: w as u32, height: h as u32, rgba }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}

    #[test]
    fn codec_types_are_send() {
        assert_send::<VideoEncoder>();
        assert_send::<VideoDecoder>();
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
        Frame { width: w, height: h, stride, data }
    }

    fn px(f: &DecodedFrame, x: u32, y: u32) -> [u8; 3] {
        let i = ((y * f.width + x) * 4) as usize;
        [f.rgba[i], f.rgba[i + 1], f.rgba[i + 2]]
    }

    fn nal_types(au: &[u8]) -> Vec<u8> {
        openh264::nal_units(au)
            .map(|n| {
                let body = n.iter().skip_while(|&&b| b == 0).skip(1).copied().next().unwrap_or(0);
                body & 0x1f
            })
            .collect()
    }

    fn close(a: [u8; 3], b: [u8; 3]) -> bool {
        a.iter().zip(b).all(|(&x, y)| (x as i32 - y as i32).abs() <= 24)
    }

    #[test]
    fn encode_decode_roundtrip_with_downscale() {
        let frame = quadrants(1280, 720);
        let cfg = EncoderConfig { max_width: 640, max_height: 640, fps: 30.0, bitrate_bps: 2_000_000 };
        let mut enc = VideoEncoder::new(1280, 720, cfg).unwrap();
        assert_eq!(enc.output_size(), (640, 360));
        let mut dec = VideoDecoder::new().unwrap();

        let first = enc.encode(&frame, false).unwrap().expect("first frame");
        assert!(first.keyframe, "first frame must be a keyframe");
        assert_eq!(&first.data[..4], &[0, 0, 0, 1], "Annex-B start code");
        let d = dec.decode(&first.data).unwrap().expect("decoded picture");
        assert_eq!((d.width, d.height), (640, 360));
        assert_eq!(d.rgba.len(), 640 * 360 * 4);
        for (x, y, want) in [
            (160, 90, [255, 0, 0]),
            (480, 90, [0, 255, 0]),
            (160, 270, [0, 0, 255]),
            (480, 270, [255, 255, 255]),
        ] {
            let got = px(&d, x, y);
            assert!(close(got, want), "at ({x},{y}) got {got:?} want {want:?}");
        }

        // A few P-frames of the same content, then a forced keyframe.
        for _ in 0..3 {
            if let Some(p) = enc.encode(&frame, false).unwrap() {
                assert!(!p.keyframe);
                dec.decode(&p.data).unwrap();
            }
        }
        let idr = enc.encode(&frame, true).unwrap().expect("forced keyframe");
        assert!(idr.keyframe, "force_keyframe must produce an IDR");
        let types = nal_types(&idr.data);
        assert!(types.contains(&5) && types.contains(&7) && types.contains(&8), "IDR+SPS+PPS, got {types:?}");

        // A brand-new decoder must be able to start at the forced keyframe (SPS/PPS included).
        let mut fresh = VideoDecoder::new().unwrap();
        let d2 = fresh.decode(&idr.data).unwrap().expect("fresh decoder joins at IDR");
        assert_eq!((d2.width, d2.height), (640, 360));
        assert!(close(px(&d2, 160, 90), [255, 0, 0]));
    }

    #[test]
    fn rejects_wrong_frame_size() {
        let mut enc = VideoEncoder::new(640, 360, EncoderConfig::default()).unwrap();
        let frame = quadrants(320, 180);
        assert!(enc.encode(&frame, false).is_err());
    }
}
