use std::{
    collections::HashMap,
    net::SocketAddr,
    ops::{Deref, Not},
    sync::{mpsc, Arc, Mutex, RwLock},
    time::UNIX_EPOCH,
};

pub use async_trait::async_trait;
#[cfg(not(any(target_os = "android", target_os = "linux")))]
use cpal::{
    traits::{DeviceTrait, HostTrait, StreamTrait},
    Device, Host, StreamConfig,
};
use magnum_opus::{Channels::*, Decoder as AudioDecoder};
use scrap::{
    codec::{Decoder, DecoderCfg},
    VpxDecoderConfig, VpxVideoCodecId,
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use hbb_common::{
    allow_err,
    anyhow::{anyhow, Context},
    bail,
    config::{Config, PeerConfig, PeerInfoSerde, CONNECT_TIMEOUT, RENDEZVOUS_TIMEOUT},
    log,
    message_proto::{option_message::BoolOption, *},
    protobuf::Message as _,
    rand,
    rendezvous_proto::*,
    socket_client,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::FramedStream,
    timeout,
    tokio::{net::TcpStream, time::Duration},
    tokio_util::compat::{Compat, TokioAsyncReadCompatExt},
    AddrMangle, ResultType, Stream,
};

pub use super::lang::*;
pub mod file_trait;
pub use file_trait::FileManager;
pub mod helper;
pub use helper::*;
pub const SEC30: Duration = Duration::from_secs(30);

pub struct Client;

use crate::{
    rendezvous_messages::{self, ToJson},
    turn_client,
};

#[cfg(not(any(target_os = "android", target_os = "linux")))]
lazy_static::lazy_static! {
static ref AUDIO_HOST: Host = cpal::default_host();
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "android")] {

use libc::{c_float, c_int, c_void};
use std::cell::RefCell;
type Oboe = *mut c_void;
extern "C" {
    fn create_oboe_player(channels: c_int, sample_rate: c_int) -> Oboe;
    fn push_oboe_data(oboe: Oboe, d: *const c_float, n: c_int);
    fn destroy_oboe_player(oboe: Oboe);
}

struct OboePlayer {
    raw: Oboe,
}

impl Default for OboePlayer {
    fn default() -> Self {
        Self {
            raw: std::ptr::null_mut(),
        }
    }
}

impl OboePlayer {
    fn new(channels: i32, sample_rate: i32) -> Self {
        unsafe {
            Self {
                raw: create_oboe_player(channels, sample_rate),
            }
        }
    }

    fn is_null(&self) -> bool {
        self.raw.is_null()
    }

    fn push(&mut self, d: &[f32]) {
        if self.raw.is_null() {
            return;
        }
        unsafe {
            push_oboe_data(self.raw, d.as_ptr(), d.len() as _);
        }
    }
}

impl Drop for OboePlayer {
    fn drop(&mut self) {
        unsafe {
            if !self.raw.is_null() {
                destroy_oboe_player(self.raw);
            }
        }
    }
}

}
}

impl Client {
    pub async fn start(peer: &str, conn_type: ConnType) -> ResultType<(Stream, bool)> {
        match Self::_start(peer, conn_type).await {
            Err(err) => {
                // Refresh the content of api.hoptodest.com
                hbb_common::api::erase_api().await;

                let err_str = err.to_string();
                if err_str.starts_with("Failed") {
                    bail!(err_str + ": Please try later");
                } else {
                    return Err(err);
                }
            }
            Ok(x) => Ok(x),
        }
    }

    async fn _start(peer: &str, conn_type: ConnType) -> ResultType<(Stream, bool)> {
        let rendezvous_server = match crate::get_rendezvous_server(1_000).await {
            Some(server) => server,
            None => bail!("Failed to retrieve rendez-vous server address"),
        };

        let my_peer_id = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let start = std::time::Instant::now();
        let socket = TcpStream::connect(&rendezvous_server).await?;
        let my_addr = socket.local_addr()?;
        let resource = format!("/?user={}", my_peer_id);
        let mut websocket_client =
            soketto::handshake::Client::new(socket.compat(), &rendezvous_server, &resource);
        let (mut sender, mut receiver) = match websocket_client.handshake().await? {
            soketto::handshake::ServerResponse::Accepted { protocol: _ } => {
                websocket_client.into_builder().finish()
            }
            _ => bail!("Websocket handshake failed"),
        };

        let mut id_pk = Vec::new();
        let mut peer_addr = Config::get_any_listen_addr();
        let mut peer_public_addr = peer_addr;
        let mut peer_nat_type = NatType::UNKNOWN_NAT;

        let my_nat_type = crate::get_nat_type(100).await;
        for i in 1..=3 {
            log::info!("#{} punch attempt with {}, id: {}", i, my_addr, peer);
            sender
                .send_text(&rendezvous_messages::ConnectRequest::new(peer, &my_peer_id).to_json())
                .await?;
            use hbb_common::protobuf::Enum;
            let nat_type = NatType::from_i32(my_nat_type).unwrap_or(NatType::UNKNOWN_NAT);
            let mut receive_buff = Vec::new();
            match timeout(RENDEZVOUS_TIMEOUT, receiver.receive_data(&mut receive_buff)).await {
                Ok(r) => match r {
                    Ok(soketto::Data::Text(n)) => {
                        if let Ok(msg) = std::str::from_utf8(&receive_buff[..n]) {
                            if let Ok(listening) =
                                serde_json::from_str::<rendezvous_messages::Listening>(msg)
                            {
                                if let Ok(raw_pk) = base64::decode(listening.pk) {
                                    id_pk = raw_pk;
                                    peer_addr = listening.addr;
                                    peer_public_addr = listening.public_addr;
                                    peer_nat_type = NatType::from_i32(listening.nat_type)
                                        .unwrap_or(peer_nat_type);
                                    break;
                                }
                            }
                        }
                        receive_buff.clear();
                    }
                    Err(e) => {
                        //log::info!("error no text: {}", e);
                        //bail!("Failed to receive next {}", e)
                    }
                    _ => {
                        bail!("Received binary message from signal server")
                    }
                },
                Err(e) => log::info!("timed out connection to signal server"),
            }
        }
        if peer_addr.port() == 0 {
            log::info!("cant connect");
            bail!("Unable to connect to the remote partner.");
        }
        let time_used = start.elapsed().as_millis() as u64;
        log::info!(
            "{} ms used for listening, id_pk size: {}",
            time_used,
            id_pk.len()
        );
        Self::connect(
            peer_addr,
            peer,
            id_pk,
            sender,
            peer_public_addr,
            peer_nat_type,
            my_nat_type,
            time_used,
        )
        .await
    }

    async fn connect(
        peer: SocketAddr,
        peer_id: &str,
        id_pk: Vec<u8>,
        mut sender: soketto::Sender<Compat<TcpStream>>,
        peer_public_addr: SocketAddr,
        peer_nat_type: NatType,
        my_nat_type: i32,
        listening_time_used: u64,
    ) -> ResultType<(Stream, bool)> {
        let direct_failures = PeerConfig::load(peer_id).direct_failures;
        let mut connect_timeout = 0;
        const MIN: u64 = 1000;
        if peer_nat_type == NatType::SYMMETRIC {
            connect_timeout = MIN;
        } else {
            if peer_nat_type == NatType::ASYMMETRIC {
                let mut my_nat_type = my_nat_type;
                if my_nat_type == NatType::UNKNOWN_NAT as i32 {
                    my_nat_type = crate::get_nat_type(100).await;
                }
                if my_nat_type == NatType::ASYMMETRIC as i32 {
                    connect_timeout = CONNECT_TIMEOUT;
                    if direct_failures > 0 {
                        connect_timeout = listening_time_used * 6;
                    }
                } else if my_nat_type == NatType::SYMMETRIC as i32 {
                    connect_timeout = MIN;
                }
            }
            if connect_timeout == 0 {
                let n = if direct_failures > 0 { 3 } else { 6 };
                connect_timeout = listening_time_used * (n as u64);
            }
            if connect_timeout < MIN {
                connect_timeout = MIN;
            }
        }
        log::info!("peer address: {}, timeout: {}", peer, connect_timeout);
        let start = std::time::Instant::now();
        // NOTICE: Socks5 is be used event in intranet. Which may be not a good way.
        let mut direct = true;
        let mut conn =
            match socket_client::connect_tcp(peer, Config::get_any_listen_addr(), connect_timeout)
                .await
            {
                Ok(stream) => stream,
                Err(_) => {
                    direct = false;
                    Self::connect_over_turn_servers(peer_id, peer_public_addr, sender).await?
                }
            };

        let time_used = start.elapsed().as_millis() as u64;
        log::info!("{}ms used to establish connection", time_used);
        Self::secure_connection(peer_id, id_pk, &mut conn).await?;
        Ok((conn, direct))
    }

    async fn connect_over_turn_servers(
        peer_id: &str,
        peer_public_addr: SocketAddr,
        mut sender: soketto::Sender<Compat<TcpStream>>,
    ) -> ResultType<FramedStream> {
        let relay_addrs = turn_client::new_relay_addrs(peer_public_addr).await;
        if relay_addrs.is_empty() {
            bail!("Failed to get a new relay address");
        }
        for (turn_client, relay_addr) in relay_addrs {
            sender
                .send_text(
                    &rendezvous_messages::RelayConnection::new(peer_id, relay_addr).to_json(),
                )
                .await?;
            match turn_client.wait_new_connection().await {
                Ok(stream) => {
                    sender
                        .send_text(&rendezvous_messages::RelayReady::new(peer_id).to_json())
                        .await?;
                    return Ok(stream);
                }
                Err(e) => log::warn!("Failed to connect via relay server: {}", e),
            }
        }
        bail!("Failed to connect via relay server: all condidates are failed!");
    }

    pub async fn secure_connection(
        peer_id: &str,
        id_pk: Vec<u8>,
        conn: &mut Stream,
    ) -> ResultType<()> {
        let mut sign_pk = None;
        if !id_pk.is_empty() {
            let t = get_pk(&id_pk);
            if let Some(pk) = t {
                sign_pk = Some(sign::PublicKey(pk));
            }

            if sign_pk.is_none() {
                log::error!("Handshake failed: invalid public key from rendezvous server");
            }
        }
        let sign_pk = match sign_pk {
            Some(v) => v,
            None => {
                // send an empty message out in case server is setting up secure and waiting for first message
                conn.send(&Message::new()).await?;
                return Ok(());
            }
        };

        match timeout(CONNECT_TIMEOUT, conn.next()).await? {
            Some(res) => {
                let bytes = res?;
                if let Ok(msg_in) = Message::parse_from_bytes(&bytes) {
                    if let Some(message::Union::SignedId(si)) = msg_in.union {
                        if let Ok((id, their_pk_b)) = decode_id_pk(&si.id, &sign_pk) {
                            if id == peer_id {
                                let their_pk_b = box_::PublicKey(their_pk_b);
                                let (our_pk_b, out_sk_b) = box_::gen_keypair();
                                let key = secretbox::gen_key();
                                let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
                                let sealed_key = box_::seal(&key.0, &nonce, &their_pk_b, &out_sk_b);
                                let mut msg_out = Message::new();
                                msg_out.set_public_key(PublicKey {
                                    asymmetric_value: Vec::from(our_pk_b.0).into(),
                                    symmetric_value: sealed_key.into(),
                                    ..Default::default()
                                });
                                timeout(CONNECT_TIMEOUT, conn.send(&msg_out)).await??;
                                conn.set_key(key);
                                log::info!("Connection is secured: {}", conn.is_secured());
                            } else {
                                log::error!("Handshake failed: sign failure");
                                conn.send(&Message::new()).await?;
                            }
                        } else {
                            // fall back to non-secure connection in case pk mismatch
                            log::info!("pk mismatch, fall back to non-secure");
                            let mut msg_out = Message::new();
                            msg_out.set_public_key(PublicKey::new());
                            timeout(CONNECT_TIMEOUT, conn.send(&msg_out)).await??;
                        }
                    } else {
                        log::error!("Handshake failed: invalid message type");
                        conn.send(&Message::new()).await?;
                    }
                } else {
                    log::error!("Handshake failed: invalid message format");
                    conn.send(&Message::new()).await?;
                }
            }
            None => {
                bail!("Reset by the peer");
            }
        }
        Ok(())
    }
}

/*

    async fn request_relay(
        peer: &str,
        relay_server: String,
        rendezvous_server: &str,
        secure: bool,
        key: &str,
        token: &str,
        conn_type: ConnType,
    ) -> ResultType<Stream> {
        let any_addr = Config::get_any_listen_addr();
        let mut succeed = false;
        let mut uuid = "".to_owned();
        for i in 1..=3 {
            // use different socket due to current hbbs implement requiring different nat address for each attempt
            let mut socket =
                socket_client::connect_tcp(rendezvous_server, any_addr, RENDEZVOUS_TIMEOUT)
                    .await
                    .with_context(|| "Failed to connect to rendezvous server")?;

            let mut msg_out = RendezvousMessage::new();
            uuid = Uuid::new_v4().to_string();
            log::info!(
                "#{} request relay attempt, id: {}, uuid: {}, relay_server: {}, secure: {}",
                i,
                peer,
                uuid,
                relay_server,
                secure,
            );
            msg_out.set_request_relay(RequestRelay {
                id: peer.to_owned(),
                token: token.to_owned(),
                uuid: uuid.clone(),
                relay_server: relay_server.clone(),
                secure,
                ..Default::default()
            });
            socket.send(&msg_out).await?;
            if let Some(Ok(bytes)) = socket.next_timeout(CONNECT_TIMEOUT).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    if let Some(rendezvous_message::Union::RelayResponse(rs)) = msg_in.union {
                        if !rs.refuse_reason.is_empty() {
                            bail!(rs.refuse_reason);
                        }
                        succeed = true;
                        break;
                    }
                }
            }
        }
        if !succeed {
            bail!("Timeout");
        }
        Self::create_relay(peer, uuid, relay_server, key, conn_type).await
    }

    async fn create_relay(
        peer: &str,
        uuid: String,
        relay_server: String,
        key: &str,
        conn_type: ConnType,
    ) -> ResultType<Stream> {
        let mut conn = socket_client::connect_tcp(
            crate::check_port(relay_server, RELAY_PORT),
            Config::get_any_listen_addr(),
            CONNECT_TIMEOUT,
        )
        .await
        .with_context(|| "Failed to connect to relay server")?;
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_request_relay(RequestRelay {
            licence_key: key.to_owned(),
            id: peer.to_owned(),
            uuid,
            conn_type: conn_type.into(),
            ..Default::default()
        });
        conn.send(&msg_out).await?;
        Ok(conn)
    }
}
*/

#[derive(Default)]
pub struct AudioHandler {
    audio_decoder: Option<(AudioDecoder, Vec<f32>)>,
    #[cfg(target_os = "android")]
    oboe: Option<OboePlayer>,
    #[cfg(target_os = "linux")]
    simple: Option<psimple::Simple>,
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    audio_buffer: Arc<std::sync::Mutex<std::collections::vec_deque::VecDeque<f32>>>,
    sample_rate: (u32, u32),
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    audio_stream: Option<Box<dyn StreamTrait>>,
    channels: u16,
    latency_controller: Arc<Mutex<LatencyController>>,
}

impl AudioHandler {
    pub fn new(latency_controller: Arc<Mutex<LatencyController>>) -> Self {
        AudioHandler {
            latency_controller,
            ..Default::default()
        }
    }

    #[cfg(target_os = "linux")]
    fn start_audio(&mut self, format0: AudioFormat) -> ResultType<()> {
        use psimple::Simple;
        use pulse::sample::{Format, Spec};
        use pulse::stream::Direction;

        let spec = Spec {
            format: Format::F32le,
            channels: format0.channels as _,
            rate: format0.sample_rate as _,
        };
        if !spec.is_valid() {
            bail!("Invalid audio format");
        }

        self.simple = Some(Simple::new(
            None,                   // Use the default server
            &crate::get_app_name(), // Our application’s name
            Direction::Playback,    // We want a playback stream
            None,                   // Use the default device
            "playback",             // Description of our stream
            &spec,                  // Our sample format
            None,                   // Use default channel map
            None,                   // Use default buffering attributes
        )?);
        self.sample_rate = (format0.sample_rate, format0.sample_rate);
        Ok(())
    }

    #[cfg(target_os = "android")]
    fn start_audio(&mut self, format0: AudioFormat) -> ResultType<()> {
        self.oboe = Some(OboePlayer::new(
            format0.channels as _,
            format0.sample_rate as _,
        ));
        self.sample_rate = (format0.sample_rate, format0.sample_rate);
        Ok(())
    }

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    fn start_audio(&mut self, format0: AudioFormat) -> ResultType<()> {
        let device = AUDIO_HOST
            .default_output_device()
            .with_context(|| "Failed to get default output device")?;
        log::info!(
            "Using default output device: \"{}\"",
            device.name().unwrap_or("".to_owned())
        );
        let config = device.default_output_config().map_err(|e| anyhow!(e))?;
        let sample_format = config.sample_format();
        log::info!("Default output format: {:?}", config);
        log::info!("Remote input format: {:?}", format0);
        let mut config: StreamConfig = config.into();
        config.channels = format0.channels as _;
        match sample_format {
            cpal::SampleFormat::F32 => self.build_output_stream::<f32>(&config, &device)?,
            cpal::SampleFormat::I16 => self.build_output_stream::<i16>(&config, &device)?,
            cpal::SampleFormat::U16 => self.build_output_stream::<u16>(&config, &device)?,
        }
        self.sample_rate = (format0.sample_rate, config.sample_rate.0);
        Ok(())
    }

    pub fn handle_format(&mut self, f: AudioFormat) {
        match AudioDecoder::new(f.sample_rate, if f.channels > 1 { Stereo } else { Mono }) {
            Ok(d) => {
                let buffer = vec![0.; f.sample_rate as usize * f.channels as usize];
                self.audio_decoder = Some((d, buffer));
                self.channels = f.channels as _;
                allow_err!(self.start_audio(f));
            }
            Err(err) => {
                log::error!("Failed to create audio decoder: {}", err);
            }
        }
    }

    pub fn handle_frame(&mut self, frame: AudioFrame) {
        if frame.timestamp != 0 {
            if self
                .latency_controller
                .lock()
                .unwrap()
                .check_audio(frame.timestamp)
                .not()
            {
                return;
            }
        }

        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        if self.audio_stream.is_none() {
            return;
        }
        #[cfg(target_os = "linux")]
        if self.simple.is_none() {
            return;
        }
        #[cfg(target_os = "android")]
        if self.oboe.is_none() {
            return;
        }
        self.audio_decoder.as_mut().map(|(d, buffer)| {
            if let Ok(n) = d.decode_float(&frame.data, buffer, false) {
                let channels = self.channels;
                let n = n * (channels as usize);
                #[cfg(not(any(target_os = "android", target_os = "linux")))]
                {
                    let sample_rate0 = self.sample_rate.0;
                    let sample_rate = self.sample_rate.1;
                    let audio_buffer = self.audio_buffer.clone();
                    // avoiding memory overflow if audio_buffer consumer side has problem
                    if audio_buffer.lock().unwrap().len() as u32 > sample_rate * 120 {
                        *audio_buffer.lock().unwrap() = Default::default();
                    }
                    if sample_rate != sample_rate0 {
                        let buffer = crate::resample_channels(
                            &buffer[0..n],
                            sample_rate0,
                            sample_rate,
                            channels,
                        );
                        audio_buffer.lock().unwrap().extend(buffer);
                    } else {
                        audio_buffer
                            .lock()
                            .unwrap()
                            .extend(buffer[0..n].iter().cloned());
                    }
                }
                #[cfg(target_os = "android")]
                {
                    self.oboe.as_mut().map(|x| x.push(&buffer[0..n]));
                }
                #[cfg(target_os = "linux")]
                {
                    let data_u8 =
                        unsafe { std::slice::from_raw_parts::<u8>(buffer.as_ptr() as _, n * 4) };
                    self.simple.as_mut().map(|x| x.write(data_u8));
                }
            }
        });
    }

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    fn build_output_stream<T: cpal::Sample>(
        &mut self,
        config: &StreamConfig,
        device: &Device,
    ) -> ResultType<()> {
        let err_fn = move |err| {
            // too many errors, will improve later
            log::trace!("an error occurred on stream: {}", err);
        };
        let audio_buffer = self.audio_buffer.clone();
        let stream = device.build_output_stream(
            config,
            move |data: &mut [T], _: &_| {
                let mut lock = audio_buffer.lock().unwrap();
                let mut n = data.len();
                if lock.len() < n {
                    n = lock.len();
                }
                let mut input = lock.drain(0..n);
                for sample in data.iter_mut() {
                    *sample = match input.next() {
                        Some(x) => T::from(&x),
                        _ => T::from(&0.),
                    };
                }
            },
            err_fn,
        )?;
        stream.play()?;
        self.audio_stream = Some(Box::new(stream));
        Ok(())
    }
}

pub struct VideoHandler {
    decoder: Decoder,
    latency_controller: Arc<Mutex<LatencyController>>,
    pub rgb: Vec<u8>,
}

impl VideoHandler {
    pub fn new(latency_controller: Arc<Mutex<LatencyController>>) -> Self {
        VideoHandler {
            decoder: Decoder::new(DecoderCfg {
                vpx: VpxDecoderConfig {
                    codec: VpxVideoCodecId::VP9,
                    num_threads: (num_cpus::get() / 2) as _,
                },
            }),
            latency_controller,
            rgb: Default::default(),
        }
    }

    pub fn handle_frame(&mut self, vf: VideoFrame) -> ResultType<bool> {
        if vf.timestamp != 0 {
            self.latency_controller
                .lock()
                .unwrap()
                .update_video(vf.timestamp);
        }
        match &vf.union {
            Some(frame) => self.decoder.handle_video_frame(frame, &mut self.rgb),
            _ => Ok(false),
        }
    }

    pub fn reset(&mut self) {
        self.decoder = Decoder::new(DecoderCfg {
            vpx: VpxDecoderConfig {
                codec: VpxVideoCodecId::VP9,
                num_threads: 1,
            },
        });
    }
}

#[derive(Default)]
pub struct LoginConfigHandler {
    id: String,
    pub is_file_transfer: bool,
    is_port_forward: bool,
    hash: Hash,
    password: Vec<u8>, // remember password for reconnect
    pub remember: bool,
    config: PeerConfig,
    pub port_forward: (String, i32),
    pub version: i64,
    pub conn_id: i32,
    features: Option<Features>,
    session_id: u64,
    pub supported_encoding: Option<(bool, bool)>,
    pub restarting_remote_device: bool,
}

impl Deref for LoginConfigHandler {
    type Target = PeerConfig;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

#[inline]
pub fn load_config(id: &str) -> PeerConfig {
    PeerConfig::load(id)
}

impl LoginConfigHandler {
    pub fn initialize(&mut self, id: String, is_file_transfer: bool, is_port_forward: bool) {
        self.id = id;
        self.is_file_transfer = is_file_transfer;
        self.is_port_forward = is_port_forward;
        let config = self.load_config();
        self.remember = !config.password.is_empty();
        self.config = config;
        self.session_id = rand::random();
        self.supported_encoding = None;
        self.restarting_remote_device = false;
    }

    // XXX: fix conflicts between with config that introduces by Deref.
    pub fn set_reconnect_password(&mut self, password: Vec<u8>) {
        self.password = password
    }

    // XXX: fix conflicts between with config that introduces by Deref.
    pub fn get_reconnect_password(&self) -> Vec<u8> {
        return self.password.clone();
    }

    pub fn should_auto_login(&self) -> String {
        let l = self.lock_after_session_end;
        let a = !self.get_option("auto-login").is_empty();
        let p = self.get_option("os-password");
        if !p.is_empty() && l && a {
            p
        } else {
            "".to_owned()
        }
    }

    fn load_config(&self) -> PeerConfig {
        load_config(&self.id)
    }

    pub fn save_config(&mut self, config: PeerConfig) {
        config.store(&self.id);
        self.config = config;
    }

    pub fn set_option(&mut self, k: String, v: String) {
        let mut config = self.load_config();
        config.options.insert(k, v);
        self.save_config(config);
    }

    pub fn save_view_style(&mut self, value: String) {
        let mut config = self.load_config();
        config.view_style = value;
        self.save_config(config);
    }

    pub fn toggle_option(&mut self, name: String) -> Option<Message> {
        let mut option = OptionMessage::default();
        let mut config = self.load_config();
        if name == "show-remote-cursor" {
            config.show_remote_cursor = !config.show_remote_cursor;
            option.show_remote_cursor = (if config.show_remote_cursor {
                BoolOption::Yes
            } else {
                BoolOption::No
            })
            .into();
        } else if name == "disable-audio" {
            config.disable_audio = !config.disable_audio;
            option.disable_audio = (if config.disable_audio {
                BoolOption::Yes
            } else {
                BoolOption::No
            })
            .into();
        } else if name == "disable-clipboard" {
            config.disable_clipboard = !config.disable_clipboard;
            option.disable_clipboard = (if config.disable_clipboard {
                BoolOption::Yes
            } else {
                BoolOption::No
            })
            .into();
        } else if name == "lock-after-session-end" {
            config.lock_after_session_end = !config.lock_after_session_end;
            option.lock_after_session_end = (if config.lock_after_session_end {
                BoolOption::Yes
            } else {
                BoolOption::No
            })
            .into();
        } else if name == "privacy-mode" {
            // try toggle privacy mode
            option.privacy_mode = (if config.privacy_mode {
                BoolOption::No
            } else {
                BoolOption::Yes
            })
            .into();
        } else if name == "enable-file-transfer" {
            config.enable_file_transfer = !config.enable_file_transfer;
            option.enable_file_transfer = (if config.enable_file_transfer {
                BoolOption::Yes
            } else {
                BoolOption::No
            })
            .into();
        } else if name == "block-input" {
            option.block_input = BoolOption::Yes.into();
        } else if name == "unblock-input" {
            option.block_input = BoolOption::No.into();
        } else if name == "show-quality-monitor" {
            config.show_quality_monitor = !config.show_quality_monitor;
        } else {
            let v = self.options.get(&name).is_some();
            if v {
                self.config.options.remove(&name);
            } else {
                self.config.options.insert(name, "Y".to_owned());
            }
            self.config.store(&self.id);
            return None;
        }
        if !name.contains("block-input") {
            self.save_config(config);
        }
        let mut misc = Misc::new();
        misc.set_option(option);
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        Some(msg_out)
    }

    fn get_option_message(&self, ignore_default: bool) -> Option<OptionMessage> {
        if self.is_port_forward || self.is_file_transfer {
            return None;
        }
        let mut n = 0;
        let mut msg = OptionMessage::new();
        let q = self.image_quality.clone();
        if let Some(q) = self.get_image_quality_enum(&q, ignore_default) {
            msg.image_quality = q.into();
            n += 1;
        } else if q == "custom" {
            let config = PeerConfig::load(&self.id);
            msg.custom_image_quality = config.custom_image_quality[0] << 8;
            n += 1;
        }
        if self.get_toggle_option("show-remote-cursor") {
            msg.show_remote_cursor = BoolOption::Yes.into();
            n += 1;
        }
        if self.get_toggle_option("lock-after-session-end") {
            msg.lock_after_session_end = BoolOption::Yes.into();
            n += 1;
        }
        if self.get_toggle_option("disable-audio") {
            msg.disable_audio = BoolOption::Yes.into();
            n += 1;
        }
        if self.get_toggle_option("enable-file-transfer") {
            msg.enable_file_transfer = BoolOption::Yes.into();
            n += 1;
        }
        if self.get_toggle_option("disable-clipboard") {
            msg.disable_clipboard = BoolOption::Yes.into();
            n += 1;
        }
        let state = Decoder::video_codec_state(&self.id);
        msg.video_codec_state = hbb_common::protobuf::MessageField::some(state);
        n += 1;

        if n > 0 {
            Some(msg)
        } else {
            None
        }
    }

    pub fn get_option_message_after_login(&self) -> Option<OptionMessage> {
        if self.is_port_forward || self.is_file_transfer {
            return None;
        }
        let mut n = 0;
        let mut msg = OptionMessage::new();
        if self.get_toggle_option("privacy-mode") {
            msg.privacy_mode = BoolOption::Yes.into();
            n += 1;
        }
        if n > 0 {
            Some(msg)
        } else {
            None
        }
    }

    fn get_image_quality_enum(&self, q: &str, ignore_default: bool) -> Option<ImageQuality> {
        if q == "low" {
            Some(ImageQuality::Low)
        } else if q == "best" {
            Some(ImageQuality::Best)
        } else if q == "balanced" {
            if ignore_default {
                None
            } else {
                Some(ImageQuality::Balanced)
            }
        } else {
            None
        }
    }

    pub fn get_toggle_option(&self, name: &str) -> bool {
        if name == "show-remote-cursor" {
            self.config.show_remote_cursor
        } else if name == "lock-after-session-end" {
            self.config.lock_after_session_end
        } else if name == "privacy-mode" {
            self.config.privacy_mode
        } else if name == "enable-file-transfer" {
            self.config.enable_file_transfer
        } else if name == "disable-audio" {
            self.config.disable_audio
        } else if name == "disable-clipboard" {
            self.config.disable_clipboard
        } else if name == "show-quality-monitor" {
            self.config.show_quality_monitor
        } else {
            !self.get_option(name).is_empty()
        }
    }

    pub fn is_privacy_mode_supported(&self) -> bool {
        if let Some(features) = &self.features {
            features.privacy_mode
        } else {
            false
        }
    }

    pub fn refresh() -> Message {
        let mut misc = Misc::new();
        misc.set_refresh_video(true);
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        msg_out
    }

    pub fn save_custom_image_quality(&mut self, image_quality: i32) -> Message {
        let mut misc = Misc::new();
        misc.set_option(OptionMessage {
            custom_image_quality: image_quality << 8,
            ..Default::default()
        });
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        let mut config = self.load_config();
        config.image_quality = "custom".to_owned();
        config.custom_image_quality = vec![image_quality as _];
        self.save_config(config);
        msg_out
    }

    pub fn save_image_quality(&mut self, value: String) -> Option<Message> {
        let mut res = None;
        if let Some(q) = self.get_image_quality_enum(&value, false) {
            let mut misc = Misc::new();
            misc.set_option(OptionMessage {
                image_quality: q.into(),
                ..Default::default()
            });
            let mut msg_out = Message::new();
            msg_out.set_misc(misc);
            res = Some(msg_out);
        }
        let mut config = self.load_config();
        config.image_quality = value;
        self.save_config(config);
        res
    }

    pub fn get_option(&self, k: &str) -> String {
        if let Some(v) = self.config.options.get(k) {
            v.clone()
        } else {
            "".to_owned()
        }
    }

    pub fn handle_login_error(&mut self, err: &str, interface: &impl Interface) -> bool {
        if err == "Wrong Password" || err == "2FA Not Authorized" {
            self.password = Default::default();
            interface.msgbox(
                "re-input-password",
                err,
                &format!("{err} - Do you want to enter again?"),
            );
            true
        } else {
            interface.msgbox("error", "Login Error", err);
            false
        }
    }

    pub fn get_username(&self, pi: &PeerInfo) -> String {
        return if pi.username.is_empty() {
            self.info.username.clone()
        } else {
            pi.username.clone()
        };
    }

    pub fn handle_peer_info(&mut self, username: String, pi: PeerInfo) {
        if !pi.version.is_empty() {
            self.version = hbb_common::get_version_number(&pi.version);
        }
        self.features = pi.features.into_option();
        let serde = PeerInfoSerde {
            username,
            hostname: pi.hostname.clone(),
            platform: pi.platform.clone(),
            mac_address: pi.mac_address,
        };
        let mut config = self.load_config();
        config.info = serde;
        let password = self.password.clone();
        let password0 = config.password.clone();
        let remember = self.remember;
        if remember {
            if !password.is_empty() && password != password0 {
                config.password = password;
                log::debug!("remember password of {}", self.id);
            }
        } else {
            if !password0.is_empty() {
                config.password = Default::default();
                log::debug!("remove password of {}", self.id);
            }
        }
        self.conn_id = pi.conn_id;
        // no matter if change, for update file time
        self.save_config(config);
        #[cfg(feature = "hwcodec")]
        {
            self.supported_encoding = Some((pi.encoding.h264, pi.encoding.h265));
        }
    }

    pub fn get_remote_dir(&self) -> String {
        serde_json::from_str::<HashMap<String, String>>(&self.get_option("remote_dir"))
            .unwrap_or_default()
            .remove(&self.info.username)
            .unwrap_or_default()
    }

    pub fn get_all_remote_dir(&self, path: String) -> String {
        let d = self.get_option("remote_dir");
        let user = self.info.username.clone();
        let mut x = serde_json::from_str::<HashMap<String, String>>(&d).unwrap_or_default();
        if path.is_empty() {
            x.remove(&user);
        } else {
            x.insert(user, path);
        }
        serde_json::to_string::<HashMap<String, String>>(&x).unwrap_or_default()
    }

    fn create_login_msg(&self, password: Vec<u8>) -> Message {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let my_id = Config::get_id_or(crate::common::MOBILE_INFO1.lock().unwrap().clone());
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let my_id = Config::get_id();
        let mut lr = LoginRequest {
            username: self.id.clone(),
            password: password.into(),
            my_id,
            my_name: crate::username(),
            option: self.get_option_message(true).into(),
            session_id: self.session_id,
            version: crate::VERSION.to_string(),
            ..Default::default()
        };
        if self.is_file_transfer {
            lr.set_file_transfer(FileTransfer {
                dir: self.get_remote_dir(),
                show_hidden: !self.get_option("remote_show_hidden").is_empty(),
                ..Default::default()
            });
        } else if self.is_port_forward {
            lr.set_port_forward(PortForward {
                host: self.port_forward.0.clone(),
                port: self.port_forward.1,
                ..Default::default()
            });
        }
        let mut msg_out = Message::new();
        msg_out.set_login_request(lr);
        msg_out
    }

    pub fn change_prefer_codec(&self) -> Message {
        let state = scrap::codec::Decoder::video_codec_state(&self.id);
        let mut misc = Misc::new();
        misc.set_option(OptionMessage {
            video_codec_state: hbb_common::protobuf::MessageField::some(state),
            ..Default::default()
        });
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        msg_out
    }

    pub fn restart_remote_device(&self) -> Message {
        let mut misc = Misc::new();
        misc.set_restart_remote_device(true);
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        msg_out
    }
}

pub enum MediaData {
    VideoFrame(VideoFrame),
    AudioFrame(AudioFrame),
    AudioFormat(AudioFormat),
    Reset,
}

pub type MediaSender = mpsc::Sender<MediaData>;

pub fn start_video_audio_threads<F>(video_callback: F) -> (MediaSender, MediaSender)
where
    F: 'static + FnMut(&[u8]) + Send,
{
    let (video_sender, video_receiver) = mpsc::channel::<MediaData>();
    let (audio_sender, audio_receiver) = mpsc::channel::<MediaData>();
    let mut video_callback = video_callback;

    let latency_controller = LatencyController::new();
    let latency_controller_cl = latency_controller.clone();
    // Create video_handler out of the thread below to ensure that the handler exists before client start.
    // It will take a few tenths of a second for the first time, and then tens of milliseconds.
    let mut video_handler = VideoHandler::new(latency_controller);

    std::thread::spawn(move || {
        loop {
            if let Ok(data) = video_receiver.recv() {
                match data {
                    MediaData::VideoFrame(vf) => {
                        if let Ok(true) = video_handler.handle_frame(vf) {
                            video_callback(&video_handler.rgb);
                        }
                    }
                    MediaData::Reset => {
                        video_handler.reset();
                    }
                    _ => {}
                }
            } else {
                break;
            }
        }
        log::info!("Video decoder loop exits");
    });
    std::thread::spawn(move || {
        let mut audio_handler = AudioHandler::new(latency_controller_cl);
        loop {
            if let Ok(data) = audio_receiver.recv() {
                match data {
                    MediaData::AudioFrame(af) => {
                        audio_handler.handle_frame(af);
                    }
                    MediaData::AudioFormat(f) => {
                        audio_handler.handle_format(f);
                    }
                    _ => {}
                }
            } else {
                break;
            }
        }
        log::info!("Audio decoder loop exits");
    });
    return (video_sender, audio_sender);
}

pub async fn handle_test_delay(t: TestDelay, peer: &mut Stream) {
    if !t.from_client {
        let mut msg_out = Message::new();
        msg_out.set_test_delay(t);
        allow_err!(peer.send(&msg_out).await);
    }
}

// mask = buttons << 3 | type
// type, 1: down, 2: up, 3: wheel
// buttons, 1: left, 2: right, 4: middle
#[inline]
pub fn send_mouse(
    mask: i32,
    x: i32,
    y: i32,
    alt: bool,
    ctrl: bool,
    shift: bool,
    command: bool,
    interface: &impl Interface,
) {
    let mut msg_out = Message::new();
    let mut mouse_event = MouseEvent {
        mask,
        x,
        y,
        ..Default::default()
    };
    if alt {
        mouse_event.modifiers.push(ControlKey::Alt.into());
    }
    if shift {
        mouse_event.modifiers.push(ControlKey::Shift.into());
    }
    if ctrl {
        mouse_event.modifiers.push(ControlKey::Control.into());
    }
    if command {
        mouse_event.modifiers.push(ControlKey::Meta.into());
    }
    msg_out.set_mouse_event(mouse_event);
    interface.send(Data::Message(msg_out));
}

fn activate_os(interface: &impl Interface) {
    send_mouse(0, 0, 0, false, false, false, false, interface);
    std::thread::sleep(Duration::from_millis(50));
    send_mouse(0, 3, 3, false, false, false, false, interface);
    std::thread::sleep(Duration::from_millis(50));
    send_mouse(1 | 1 << 3, 0, 0, false, false, false, false, interface);
    send_mouse(2 | 1 << 3, 0, 0, false, false, false, false, interface);
    /*
    let mut key_event = KeyEvent::new();
    // do not use Esc, which has problem with Linux
    key_event.set_control_key(ControlKey::RightArrow);
    key_event.press = true;
    let mut msg_out = Message::new();
    msg_out.set_key_event(key_event.clone());
    interface.send(Data::Message(msg_out.clone()));
    */
}

pub fn input_os_password(p: String, activate: bool, interface: impl Interface) {
    std::thread::spawn(move || {
        _input_os_password(p, activate, interface);
    });
}

fn _input_os_password(p: String, activate: bool, interface: impl Interface) {
    if activate {
        activate_os(&interface);
        std::thread::sleep(Duration::from_millis(1200));
    }
    let mut key_event = KeyEvent::new();
    key_event.press = true;
    let mut msg_out = Message::new();
    key_event.set_seq(p);
    msg_out.set_key_event(key_event.clone());
    interface.send(Data::Message(msg_out.clone()));
    key_event.set_control_key(ControlKey::Return);
    msg_out.set_key_event(key_event);
    interface.send(Data::Message(msg_out));
}

pub async fn handle_hash(
    lc: Arc<RwLock<LoginConfigHandler>>,
    password_preset: &str,
    hash: Hash,
    interface: &impl Interface,
    peer: &mut Stream,
) {
    let mut password = lc.read().unwrap().get_reconnect_password();
    if password.is_empty() {
        if !password_preset.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(password_preset);
            hasher.update(&hash.salt);
            let res = hasher.finalize();
            password = res[..].into();
        }
    }
    if password.is_empty() {
        password = lc.read().unwrap().config.password.clone();
    }
    if password.is_empty() {
        // login without password, the remote side can click accept
        send_login(lc.clone(), Vec::new(), peer).await;
        interface.msgbox("input-password", "Password Required", "");
    } else {
        let mut hasher = Sha256::new();
        hasher.update(&password);
        hasher.update(&hash.challenge);
        send_login(lc.clone(), hasher.finalize()[..].into(), peer).await;
    }
    lc.write().unwrap().hash = hash;
}

async fn send_login(lc: Arc<RwLock<LoginConfigHandler>>, password: Vec<u8>, peer: &mut Stream) {
    let msg_out = lc.read().unwrap().create_login_msg(password);
    allow_err!(peer.send(&msg_out).await);
}

pub async fn handle_login_from_ui(
    lc: Arc<RwLock<LoginConfigHandler>>,
    password: String,
    remember: bool,
    peer: &mut Stream,
) {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(&lc.read().unwrap().hash.salt);
    let res = hasher.finalize();
    lc.write().unwrap().remember = remember;
    lc.write().unwrap().set_reconnect_password(res[..].into());
    let mut hasher2 = Sha256::new();
    hasher2.update(&res[..]);
    hasher2.update(&lc.read().unwrap().hash.challenge);
    send_login(lc.clone(), hasher2.finalize()[..].into(), peer).await;
}

#[async_trait]
pub trait Interface: Send + Clone + 'static + Sized {
    fn send(&self, data: Data);
    fn msgbox(&self, msgtype: &str, title: &str, text: &str);
    fn handle_login_error(&mut self, err: &str) -> bool;
    fn handle_peer_info(&mut self, pi: PeerInfo);
    async fn handle_hash(&mut self, pass: &str, hash: Hash, peer: &mut Stream);
    async fn handle_login_from_ui(&mut self, password: String, remember: bool, peer: &mut Stream);
    async fn handle_test_delay(&mut self, t: TestDelay, peer: &mut Stream);
}

#[derive(Clone)]
pub enum Data {
    Close,
    Login((String, bool)),
    Message(Message),
    SendFiles((i32, String, String, i32, bool, bool)),
    RemoveDirAll((i32, String, bool)),
    ConfirmDeleteFiles((i32, i32)),
    SetNoConfirm(i32),
    RemoveDir((i32, String)),
    RemoveFile((i32, String, i32, bool)),
    CreateDir((i32, String, bool)),
    CancelJob(i32),
    RemovePortForward(i32),
    AddPortForward((i32, String, i32)),
    ToggleClipboardFile,
    NewRDP,
    SetConfirmOverrideFile((i32, i32, bool, bool, bool)),
    AddJob((i32, String, String, i32, bool, bool)),
    ResumeJob((i32, bool)),
}

#[derive(Clone)]
pub enum Key {
    ControlKey(ControlKey),
    Chr(u32),
    _Raw(u32),
}

lazy_static::lazy_static! {
    pub static ref KEY_MAP: HashMap<&'static str, Key> =
    [
        ("VK_A", Key::Chr('a' as _)),
        ("VK_B", Key::Chr('b' as _)),
        ("VK_C", Key::Chr('c' as _)),
        ("VK_D", Key::Chr('d' as _)),
        ("VK_E", Key::Chr('e' as _)),
        ("VK_F", Key::Chr('f' as _)),
        ("VK_G", Key::Chr('g' as _)),
        ("VK_H", Key::Chr('h' as _)),
        ("VK_I", Key::Chr('i' as _)),
        ("VK_J", Key::Chr('j' as _)),
        ("VK_K", Key::Chr('k' as _)),
        ("VK_L", Key::Chr('l' as _)),
        ("VK_M", Key::Chr('m' as _)),
        ("VK_N", Key::Chr('n' as _)),
        ("VK_O", Key::Chr('o' as _)),
        ("VK_P", Key::Chr('p' as _)),
        ("VK_Q", Key::Chr('q' as _)),
        ("VK_R", Key::Chr('r' as _)),
        ("VK_S", Key::Chr('s' as _)),
        ("VK_T", Key::Chr('t' as _)),
        ("VK_U", Key::Chr('u' as _)),
        ("VK_V", Key::Chr('v' as _)),
        ("VK_W", Key::Chr('w' as _)),
        ("VK_X", Key::Chr('x' as _)),
        ("VK_Y", Key::Chr('y' as _)),
        ("VK_Z", Key::Chr('z' as _)),
        ("VK_0", Key::Chr('0' as _)),
        ("VK_1", Key::Chr('1' as _)),
        ("VK_2", Key::Chr('2' as _)),
        ("VK_3", Key::Chr('3' as _)),
        ("VK_4", Key::Chr('4' as _)),
        ("VK_5", Key::Chr('5' as _)),
        ("VK_6", Key::Chr('6' as _)),
        ("VK_7", Key::Chr('7' as _)),
        ("VK_8", Key::Chr('8' as _)),
        ("VK_9", Key::Chr('9' as _)),
        ("VK_COMMA", Key::Chr(',' as _)),
        ("VK_SLASH", Key::Chr('/' as _)),
        ("VK_SEMICOLON", Key::Chr(';' as _)),
        ("VK_QUOTE", Key::Chr('\'' as _)),
        ("VK_LBRACKET", Key::Chr('[' as _)),
        ("VK_RBRACKET", Key::Chr(']' as _)),
        ("VK_BACKSLASH", Key::Chr('\\' as _)),
        ("VK_MINUS", Key::Chr('-' as _)),
        ("VK_PLUS", Key::Chr('=' as _)), // it is =, but sciter return VK_PLUS
        ("VK_DIVIDE", Key::ControlKey(ControlKey::Divide)), // numpad
        ("VK_MULTIPLY", Key::ControlKey(ControlKey::Multiply)), // numpad
        ("VK_SUBTRACT", Key::ControlKey(ControlKey::Subtract)), // numpad
        ("VK_ADD", Key::ControlKey(ControlKey::Add)), // numpad
        ("VK_DECIMAL", Key::ControlKey(ControlKey::Decimal)), // numpad
        ("VK_F1", Key::ControlKey(ControlKey::F1)),
        ("VK_F2", Key::ControlKey(ControlKey::F2)),
        ("VK_F3", Key::ControlKey(ControlKey::F3)),
        ("VK_F4", Key::ControlKey(ControlKey::F4)),
        ("VK_F5", Key::ControlKey(ControlKey::F5)),
        ("VK_F6", Key::ControlKey(ControlKey::F6)),
        ("VK_F7", Key::ControlKey(ControlKey::F7)),
        ("VK_F8", Key::ControlKey(ControlKey::F8)),
        ("VK_F9", Key::ControlKey(ControlKey::F9)),
        ("VK_F10", Key::ControlKey(ControlKey::F10)),
        ("VK_F11", Key::ControlKey(ControlKey::F11)),
        ("VK_F12", Key::ControlKey(ControlKey::F12)),
        ("VK_ENTER", Key::ControlKey(ControlKey::Return)),
        ("VK_CANCEL", Key::ControlKey(ControlKey::Cancel)),
        ("VK_BACK", Key::ControlKey(ControlKey::Backspace)),
        ("VK_TAB", Key::ControlKey(ControlKey::Tab)),
        ("VK_CLEAR", Key::ControlKey(ControlKey::Clear)),
        ("VK_RETURN", Key::ControlKey(ControlKey::Return)),
        ("VK_SHIFT", Key::ControlKey(ControlKey::Shift)),
        ("VK_CONTROL", Key::ControlKey(ControlKey::Control)),
        ("VK_MENU", Key::ControlKey(ControlKey::Alt)),
        ("VK_PAUSE", Key::ControlKey(ControlKey::Pause)),
        ("VK_CAPITAL", Key::ControlKey(ControlKey::CapsLock)),
        ("VK_KANA", Key::ControlKey(ControlKey::Kana)),
        ("VK_HANGUL", Key::ControlKey(ControlKey::Hangul)),
        ("VK_JUNJA", Key::ControlKey(ControlKey::Junja)),
        ("VK_FINAL", Key::ControlKey(ControlKey::Final)),
        ("VK_HANJA", Key::ControlKey(ControlKey::Hanja)),
        ("VK_KANJI", Key::ControlKey(ControlKey::Kanji)),
        ("VK_ESCAPE", Key::ControlKey(ControlKey::Escape)),
        ("VK_CONVERT", Key::ControlKey(ControlKey::Convert)),
        ("VK_SPACE", Key::ControlKey(ControlKey::Space)),
        ("VK_PRIOR", Key::ControlKey(ControlKey::PageUp)),
        ("VK_NEXT", Key::ControlKey(ControlKey::PageDown)),
        ("VK_END", Key::ControlKey(ControlKey::End)),
        ("VK_HOME", Key::ControlKey(ControlKey::Home)),
        ("VK_LEFT", Key::ControlKey(ControlKey::LeftArrow)),
        ("VK_UP", Key::ControlKey(ControlKey::UpArrow)),
        ("VK_RIGHT", Key::ControlKey(ControlKey::RightArrow)),
        ("VK_DOWN", Key::ControlKey(ControlKey::DownArrow)),
        ("VK_SELECT", Key::ControlKey(ControlKey::Select)),
        ("VK_PRINT", Key::ControlKey(ControlKey::Print)),
        ("VK_EXECUTE", Key::ControlKey(ControlKey::Execute)),
        ("VK_SNAPSHOT", Key::ControlKey(ControlKey::Snapshot)),
        ("VK_INSERT", Key::ControlKey(ControlKey::Insert)),
        ("VK_DELETE", Key::ControlKey(ControlKey::Delete)),
        ("VK_HELP", Key::ControlKey(ControlKey::Help)),
        ("VK_SLEEP", Key::ControlKey(ControlKey::Sleep)),
        ("VK_SEPARATOR", Key::ControlKey(ControlKey::Separator)),
        ("VK_NUMPAD0", Key::ControlKey(ControlKey::Numpad0)),
        ("VK_NUMPAD1", Key::ControlKey(ControlKey::Numpad1)),
        ("VK_NUMPAD2", Key::ControlKey(ControlKey::Numpad2)),
        ("VK_NUMPAD3", Key::ControlKey(ControlKey::Numpad3)),
        ("VK_NUMPAD4", Key::ControlKey(ControlKey::Numpad4)),
        ("VK_NUMPAD5", Key::ControlKey(ControlKey::Numpad5)),
        ("VK_NUMPAD6", Key::ControlKey(ControlKey::Numpad6)),
        ("VK_NUMPAD7", Key::ControlKey(ControlKey::Numpad7)),
        ("VK_NUMPAD8", Key::ControlKey(ControlKey::Numpad8)),
        ("VK_NUMPAD9", Key::ControlKey(ControlKey::Numpad9)),
        ("Apps", Key::ControlKey(ControlKey::Apps)),
        ("Meta", Key::ControlKey(ControlKey::Meta)),
        ("RAlt", Key::ControlKey(ControlKey::RAlt)),
        ("RWin", Key::ControlKey(ControlKey::RWin)),
        ("RControl", Key::ControlKey(ControlKey::RControl)),
        ("RShift", Key::ControlKey(ControlKey::RShift)),
        ("CTRL_ALT_DEL", Key::ControlKey(ControlKey::CtrlAltDel)),
        ("LOCK_SCREEN", Key::ControlKey(ControlKey::LockScreen)),
    ].iter().cloned().collect();
}

#[inline]
pub fn check_if_retry(msgtype: &str, title: &str, text: &str) -> bool {
    msgtype == "error"
        && title == "Connection Error"
        && !text.to_lowercase().contains("offline")
        && !text.to_lowercase().contains("exist")
        && !text.to_lowercase().contains("handshake")
        && !text.to_lowercase().contains("failed")
        && !text.to_lowercase().contains("resolve")
        && !text.to_lowercase().contains("mismatch")
        && !text.to_lowercase().contains("manually")
        && !text.to_lowercase().contains("not allowed")
}

#[inline]
fn get_pk(pk: &[u8]) -> Option<[u8; 32]> {
    if pk.len() == 32 {
        let mut tmp = [0u8; 32];
        tmp[..].copy_from_slice(&pk);
        Some(tmp)
    } else {
        None
    }
}

#[inline]
fn get_rs_pk(str_base64: &str) -> Option<sign::PublicKey> {
    if let Ok(pk) = base64::decode(str_base64) {
        get_pk(&pk).map(|x| sign::PublicKey(x))
    } else {
        None
    }
}

fn decode_id_pk(signed: &[u8], key: &sign::PublicKey) -> ResultType<(String, [u8; 32])> {
    let res = IdPk::parse_from_bytes(
        &sign::verify(signed, key).map_err(|_| anyhow!("Signature mismatch"))?,
    )?;
    if let Some(pk) = get_pk(&res.pk) {
        Ok((res.id, pk))
    } else {
        bail!("Wrong public length");
    }
}