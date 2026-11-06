//! Thin safe wrapper over the raw OpenH264 encoder (via `openh264-sys2`).
//!
//! The `openh264` crate's `Encoder` hardcodes single-slice mode, which makes
//! `iMultipleThreadIdc` useless; we need a fixed slice count so OpenH264 can encode
//! slices in parallel. Everything else mirrors what that crate does.

use std::ffi::c_void;
use std::ptr::{addr_of_mut, null_mut};

use anyhow::{bail, Result};
use openh264_sys2::{
    DynamicAPI, ISVCEncoder, SEncParamExt, SFrameBSInfo, SSourcePicture, API,
    CAMERA_VIDEO_REAL_TIME, CONSTANT_ID, ENCODER_OPTION_DATAFORMAT, ENCODER_OPTION_TRACE_LEVEL,
    LOW_COMPLEXITY, PRO_BASELINE, RC_BITRATE_MODE, SCREEN_CONTENT_REAL_TIME, SM_FIXEDSLCNUM_SLICE,
    SM_SINGLE_SLICE,
};

/// H.264 VUI code for SMPTE 170M (BT.601 525) primaries/transfer/matrix.
const VUI_SMPTE170M: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PicType {
    Idr,
    Other,
    Skip,
}

pub(crate) struct Params {
    pub width: u32,
    pub height: u32,
    pub fps: f32,
    pub bitrate_bps: u32,
    /// Encoder worker threads == slice count. 1 = single slice.
    pub threads: u16,
    /// OpenH264 SCREEN_CONTENT_REAL_TIME (true) or CAMERA_VIDEO_REAL_TIME (false).
    pub screen_content: bool,
}

pub(crate) struct H264Encoder {
    api: DynamicAPI,
    enc: *mut ISVCEncoder,
    initialized: bool,
    info: Box<SFrameBSInfo>,
    width: i32,
    height: i32,
}

// SAFETY: the encoder instance is exclusively owned and only used through `&mut self`;
// OpenH264 encoder instances have no thread affinity (same reasoning as the openh264 crate,
// which marks its `Encoder` Send + Sync).
unsafe impl Send for H264Encoder {}

fn check(rc: i32, what: &str) -> Result<()> {
    if rc != 0 {
        bail!("OpenH264 {what} failed (code {rc})");
    }
    Ok(())
}

impl H264Encoder {
    pub(crate) fn new(p: &Params) -> Result<Self> {
        let api = DynamicAPI::from_source();
        let mut enc: *mut ISVCEncoder = null_mut();
        // SAFETY: FFI constructor; result checked.
        check(
            unsafe { api.WelsCreateSVCEncoder(&mut enc) },
            "WelsCreateSVCEncoder",
        )?;
        if enc.is_null() {
            bail!("OpenH264 returned a null encoder");
        }
        let mut this = Self {
            api,
            enc,
            initialized: false,
            info: Box::default(),
            width: p.width as i32,
            height: p.height as i32,
        };
        this.init(p)?;
        Ok(this)
    }

    /// SAFETY of all vtable calls: `self.enc` is a live encoder created in `new` and destroyed
    /// only in `Drop`; the vtable entries are filled in by OpenH264.
    fn vt(&self) -> &openh264_sys2::ISVCEncoderVtbl {
        unsafe { &**self.enc }
    }

    fn init(&mut self, p: &Params) -> Result<()> {
        let vt = *self.vt();
        let (get_default, init_ext, set_option) = (
            vt.GetDefaultParams.expect("vtable"),
            vt.InitializeExt.expect("vtable"),
            vt.SetOption.expect("vtable"),
        );
        let mut s = SEncParamExt::default();
        unsafe {
            let mut quiet: i32 = 0; // WELS_LOG_QUIET
            set_option(
                self.enc,
                ENCODER_OPTION_TRACE_LEVEL,
                addr_of_mut!(quiet).cast::<c_void>(),
            );
            check(get_default(self.enc, &mut s), "GetDefaultParams")?;
        }
        let bitrate = i32::try_from(p.bitrate_bps)?;
        s.iUsageType = if p.screen_content {
            SCREEN_CONTENT_REAL_TIME
        } else {
            CAMERA_VIDEO_REAL_TIME
        };
        s.iPicWidth = self.width;
        s.iPicHeight = self.height;
        s.iTargetBitrate = bitrate;
        s.iRCMode = RC_BITRATE_MODE;
        s.fMaxFrameRate = p.fps;
        s.iTemporalLayerNum = 1;
        s.iSpatialLayerNum = 1;
        s.iComplexityMode = LOW_COMPLEXITY;
        // No periodic IDRs: transport is reliable; keyframes on demand.
        s.uiIntraPeriod = 0;
        s.eSpsPpsIdStrategy = CONSTANT_ID;
        // OpenH264 can only hold the bitrate if it may skip frames.
        s.bEnableFrameSkip = true;
        s.bEnableSceneChangeDetect = true;
        // Not supported for screen content (OpenH264 would warn and turn them off); for camera
        // mode they only add work.
        s.bEnableAdaptiveQuant = false;
        s.bEnableBackgroundDetection = false;
        s.bEnableLongTermReference = false;
        s.bEnableDenoise = false;
        s.iLoopFilterDisableIdc = 0;
        s.iMultipleThreadIdc = p.threads.max(1);
        s.bUseLoadBalancing = false;
        let l = &mut s.sSpatialLayers[0];
        l.iVideoWidth = self.width;
        l.iVideoHeight = self.height;
        l.fFrameRate = p.fps;
        l.iSpatialBitrate = bitrate;
        l.iMaxSpatialBitrate = bitrate;
        l.uiProfileIdc = PRO_BASELINE;
        if p.threads > 1 {
            l.sSliceArgument.uiSliceMode = SM_FIXEDSLCNUM_SLICE;
            l.sSliceArgument.uiSliceNum = u32::from(p.threads);
        } else {
            l.sSliceArgument.uiSliceMode = SM_SINGLE_SLICE;
            l.sSliceArgument.uiSliceNum = 1;
        }
        // VUI: BT.601 limited range, matching our colour conversion.
        l.bVideoSignalTypePresent = true;
        l.uiVideoFormat = 5; // unspecified
        l.bFullRange = false;
        l.bColorDescriptionPresent = true;
        l.uiColorPrimaries = VUI_SMPTE170M;
        l.uiTransferCharacteristics = VUI_SMPTE170M;
        l.uiColorMatrix = VUI_SMPTE170M;
        unsafe {
            check(init_ext(self.enc, &s), "InitializeExt")?;
            self.initialized = true;
            let mut fmt = openh264_sys2::videoFormatI420;
            check(
                set_option(
                    self.enc,
                    ENCODER_OPTION_DATAFORMAT,
                    addr_of_mut!(fmt).cast(),
                ),
                "SetOption(DATAFORMAT)",
            )?;
        }
        Ok(())
    }

    pub(crate) fn force_idr(&mut self) {
        let f = self.vt().ForceIntraFrame.expect("vtable");
        unsafe {
            f(self.enc, true);
        }
    }

    /// Encode tightly packed I420 planes; appends the Annex-B access unit to `out`.
    pub(crate) fn encode(
        &mut self,
        y: &[u8],
        u: &[u8],
        v: &[u8],
        ts_ms: i64,
        out: &mut Vec<u8>,
    ) -> Result<PicType> {
        let (w, h) = (self.width as usize, self.height as usize);
        assert!(y.len() >= w * h && u.len() >= w / 2 * (h / 2) && v.len() >= w / 2 * (h / 2));
        let pic = SSourcePicture {
            iColorFormat: openh264_sys2::videoFormatI420,
            iStride: [self.width, self.width / 2, self.width / 2, 0],
            // The encoder only reads the planes.
            pData: [
                y.as_ptr().cast_mut(),
                u.as_ptr().cast_mut(),
                v.as_ptr().cast_mut(),
                null_mut(),
            ],
            iPicWidth: self.width,
            iPicHeight: self.height,
            uiTimeStamp: ts_ms,
            bPsnrY: false,
            bPsnrU: false,
            bPsnrV: false,
        };
        let f = self.vt().EncodeFrame.expect("vtable");
        check(unsafe { f(self.enc, &pic, &mut *self.info) }, "EncodeFrame")?;
        let info = &*self.info;
        let ty = match info.eFrameType {
            openh264_sys2::videoFrameTypeIDR => PicType::Idr,
            openh264_sys2::videoFrameTypeSkip | openh264_sys2::videoFrameTypeInvalid => {
                return Ok(PicType::Skip)
            }
            _ => PicType::Other,
        };
        let layers = usize::try_from(info.iLayerNum)
            .unwrap_or(0)
            .min(info.sLayerInfo.len());
        for layer in &info.sLayerInfo[..layers] {
            let n = usize::try_from(layer.iNalCount).unwrap_or(0);
            if n == 0 || layer.pBsBuf.is_null() || layer.pNalLengthInByte.is_null() {
                continue;
            }
            // SAFETY: OpenH264 guarantees pNalLengthInByte has iNalCount entries and that the
            // NALs are stored back-to-back in pBsBuf; valid until the next EncodeFrame.
            unsafe {
                let lens = std::slice::from_raw_parts(layer.pNalLengthInByte, n);
                let total: usize = lens.iter().map(|&l| usize::try_from(l).unwrap_or(0)).sum();
                out.extend_from_slice(std::slice::from_raw_parts(layer.pBsBuf, total));
            }
        }
        Ok(ty)
    }
}

impl Drop for H264Encoder {
    fn drop(&mut self) {
        unsafe {
            if self.initialized {
                if let Some(un) = self.vt().Uninitialize {
                    un(self.enc);
                }
            }
            self.api.WelsDestroySVCEncoder(self.enc);
        }
    }
}
