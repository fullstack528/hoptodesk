use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use hbb_common::{
    log,
    message_proto::{video_frame, VideoFrame},
};

const MAX_LATENCY: i64 = 500;
const MIN_LATENCY: i64 = 100;

// based on video frame time, fix audio latency relatively.
// only works on audio, can't fix video latency.
#[derive(Debug)]
pub struct LatencyController {
    last_video_remote_ts: i64, // generated on remote deivce
    update_time: Instant,
    allow_audio: bool,
}

impl Default for LatencyController {
    fn default() -> Self {
        Self {
            last_video_remote_ts: Default::default(),
            update_time: Instant::now(),
            allow_audio: Default::default(),
        }
    }
}

impl LatencyController {
    pub fn new() -> Arc<Mutex<LatencyController>> {
        Arc::new(Mutex::new(LatencyController::default()))
    }

    // first, receive new video frame and update time
    pub fn update_video(&mut self, timestamp: i64) {
        self.last_video_remote_ts = timestamp;
        self.update_time = Instant::now();
    }

    // second, compute audio latency
    // set MAX and MIN, avoid fixing too frequently.
    pub fn check_audio(&mut self, timestamp: i64) -> bool {
        let expected = self.update_time.elapsed().as_millis() as i64 + self.last_video_remote_ts;
        let latency = expected - timestamp;
        if self.allow_audio {
            if latency.abs() > MAX_LATENCY {
                log::debug!("LATENCY > {}ms cut off, latency:{}", MAX_LATENCY, latency);
                self.allow_audio = false;
            }
        } else {
            if latency.abs() < MIN_LATENCY {
                log::debug!("LATENCY < {}ms resume, latency:{}", MIN_LATENCY, latency);
                self.allow_audio = true;
            }
        }
        self.allow_audio
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum CodecFormat {
    VP9,
    H264,
    H265,
    Unknown,
}

impl From<&VideoFrame> for CodecFormat {
    fn from(it: &VideoFrame) -> Self {
        match it.union {
            Some(video_frame::Union::Vp9s(_)) => CodecFormat::VP9,
            Some(video_frame::Union::H264s(_)) => CodecFormat::H264,
            Some(video_frame::Union::H265s(_)) => CodecFormat::H265,
            _ => CodecFormat::Unknown,
        }
    }
}

impl ToString for CodecFormat {
    fn to_string(&self) -> String {
        match self {
            CodecFormat::VP9 => "VP9".into(),
            CodecFormat::H264 => "H264".into(),
            CodecFormat::H265 => "H265".into(),
            CodecFormat::Unknown => "Unknow".into(),
        }
    }
}

#[derive(Debug, Default)]
pub struct QualityStatus {
    pub speed: Option<String>,
    pub fps: Option<i32>,
    pub delay: Option<i32>,
    pub target_bitrate: Option<i32>,
    pub codec_format: Option<CodecFormat>,
}
