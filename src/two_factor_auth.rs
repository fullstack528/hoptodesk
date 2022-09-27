// 2FA

use crate::two_factor_auth::sockets::{AuthAnswer, TFAChecker};
use futures::lock::Mutex;
use hbb_common::{log, tokio};
use std::collections::HashMap;
use std::sync::Arc;

pub mod utils {
    use crate::two_factor_auth::api_access;
    use hbb_common::config::Config;
    use hbb_common::rand::random;
    use image::{Luma, Rgba};
    use qrcode::QrCode;
    use sha2::{Digest, Sha256, Sha512};

    pub fn random_alphanum(length: usize) -> String {
        (0..)
            .map(|_| random::<char>())
            .filter(|c| c.is_ascii_alphanumeric() && (c.is_ascii_lowercase() || c.is_ascii_digit()))
            .take(length)
            .collect::<String>()
    }

    pub fn make_2fa_link(string: &str) -> String {
        format!("https://www.hoptodesk.com/2fa/#{}", string)
    }

    pub fn make_qr_code(string: &str) -> QrCode {
        let link = make_2fa_link(string);
        QrCode::new(link).unwrap()
    }

    pub fn qr_code_to_raw_img(qr: QrCode) -> String {
        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("secret_qr.png");

        let image = qr.render::<Rgba<u8>>().build();
        image.save(&path).unwrap();

        let base64 = image_base64::to_base64(path.to_str().unwrap());

        tmp_dir.close().unwrap();

        base64
    }

    pub fn get_secret() -> String {
        Config::get_option("2fa-secret")
    }

    pub fn is_2fa_enabled() -> bool {
        &get_secret() != ""
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    enum HashAlgorithm {
        MD5,
        SHA256,
        SHA512,
    }

    impl From<&str> for HashAlgorithm {
        fn from(x: &str) -> Self {
            match x {
                "md5" | "MD5" => HashAlgorithm::MD5,
                "sha256" | "SHA256" => HashAlgorithm::SHA256,
                "sha512" | "SHA512" => HashAlgorithm::SHA512,
                _ => HashAlgorithm::MD5,
            }
        }
    }

    impl HashAlgorithm {
        pub fn hash_str(&self, s: &str) -> String {
            match self {
                HashAlgorithm::MD5 => format!("{:x}", md5::compute(s)),
                HashAlgorithm::SHA256 => format!("{:x}", Sha256::digest(s)),
                HashAlgorithm::SHA512 => format!("{:x}", Sha512::digest(s)),
            }
        }
    }

    pub async fn hash_str(s: &str) -> String {
        HashAlgorithm::from(api_access::get_hash_algorithm().await.as_str()).hash_str(s)
    }

    pub async fn challenge_answer(challenge: &str) -> String {
        let string = get_secret()
            .chars()
            .chain(challenge.chars())
            .collect::<String>();
        hash_str(&string).await
    }
}

mod api_access {
    use serde_derive::{Deserialize, Serialize};

    #[derive(Deserialize)]
    struct WebsocketsURL {
        url: String,
    }

    #[derive(Deserialize)]
    struct APIWebsockets {
        websockets: WebsocketsURL,
    }

    pub async fn get_ws_uri() -> String {
        let body = serde_json::from_value::<APIWebsockets>(hbb_common::api::call_api().await.unwrap());

        body.expect("Could not get Websockets URI from API.")
            .websockets
            .url
    }

    #[derive(Deserialize)]
    struct API2FA {
        hash_algorithm: Option<String>,
        ping_time: Option<f64>,
    }

    #[derive(Deserialize)]
    struct API2FAWrapper {
        #[serde(rename = "2fa")]
        tfa: Option<API2FA>,
    }

    pub async fn get_hash_algorithm() -> String {
        let body = serde_json::from_value::<API2FAWrapper>(hbb_common::api::call_api().await.unwrap());
		
        body.map(|x| x.tfa.and_then(|x| x.hash_algorithm))
            .unwrap_or(Some("md5".to_owned()))
            .unwrap_or("md5".to_owned())
    }

    pub async fn get_ping_time() -> f64 {
        let body = serde_json::from_value::<API2FAWrapper>(hbb_common::api::call_api().await.unwrap());

        body.map(|x| x.tfa.and_then(|x| x.ping_time))
            .unwrap_or(Some(10.0))
            .unwrap_or(10.0)
    }
}

pub mod sockets {
    use crate::two_factor_auth::api_access;
    use crate::two_factor_auth::utils::*;
    use futures::lock::Mutex;
    use futures::{FutureExt, SinkExt, StreamExt, TryStreamExt};
    use hbb_common::tokio::net::TcpStream;
    use hbb_common::tokio::time::sleep;
    use hbb_common::{log, tokio};
    use serde_derive::{Deserialize, Serialize};
    use std::fmt::{Display, Formatter, Write};
    use std::future::Future;
    use std::ops::{Deref, DerefMut};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio_tungstenite::tungstenite::{Error, Message};
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

    pub async fn create_socket() -> WebSocketStream<MaybeTlsStream<TcpStream>> {
        let websockets_uri = api_access::get_ws_uri().await;
        let (socket, _) = tokio_tungstenite::connect_async(&websockets_uri)
            .await
            .unwrap();
        socket
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum CheckerStatus {
        Active,
        Inactive,
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub enum AuthAnswer {
        Allowed,
        Denied,
    }

    impl Display for AuthAnswer {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                AuthAnswer::Allowed => f.write_str("ALLOWED"),
                AuthAnswer::Denied => f.write_str("DENIED"),
            }
        }
    }

    // idempotent per object
    #[derive(Clone)]
    pub struct TFAChecker {
        status: Arc<Mutex<CheckerStatus>>,
        answer: Arc<Mutex<Option<AuthAnswer>>>,
        callbacks: Arc<Mutex<Vec<Box<dyn FnOnce(AuthAnswer) + Send + Sync>>>>,
    }

    impl TFAChecker {
        pub fn new() -> Self {
            Self {
                status: Arc::new(Mutex::new(CheckerStatus::Inactive)),
                answer: Arc::new(Mutex::new(None)),
                callbacks: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub async fn check_async(&mut self) -> AuthAnswer {
            if self.is_finished().await {
                // if already waiting for a challenge, or already complete one, then just do nothing
                return self.get_answer().await.unwrap(); // cannot panic
            }

            let status = self.status.clone();
            let final_answer = self.answer.clone();
            let callbacks = self.callbacks.clone();

            // spawn a thread to check the challenge
            let fut = async move {
                // activate
                *status.lock().await.deref_mut() = CheckerStatus::Active;

                let challenge = random_alphanum(16);
                let answer = challenge_answer(&challenge).await;
                let (mut write, read) = create_socket().await.split();

                let mut last_sent_challenge = Instant::now();
                // send challenge
                write.send(Message::Text(challenge.clone())).await.unwrap();
                log::info!("Sent challenge!");

                let success = Arc::new(Mutex::new(false));
                let read_success = success.clone();
                let read_answer = answer.clone();
                let read_status = status.clone();
                let write_success = success.clone();
                let write_status = status.clone();

                let read_fut = async move {
                    let status = read_status;
                    let success = read_success;
                    let answer = read_answer;

                    let mut fut = read.map(|message| async {
                        log::info!("Got message {:?}", message);
                        match message {
                            _ if *status.lock().await.deref() == CheckerStatus::Inactive => {
                                log::info!("Checker Inactive, exiting reader");
                                Some(false)
                            }
                            Ok(Message::Text(s)) // allow
                                if !success.lock().await.clone() && s == answer =>
                            {
                                log::info!("Got allow!");
                                *status.lock().await.deref_mut() = CheckerStatus::Inactive;
                                Some(true)
                            }
                            Ok(Message::Text(s)) // deny
                                if !success.lock().await.clone() && s == format!("-{answer}") => {
                                log::info!("Got deny!");
                                *status.lock().await.deref_mut() = CheckerStatus::Inactive;
                                Some(false)
                            }
                            Ok(Message::Text(s)) => {
                                log::info!("Got wrong answer {}, expected {}.", s, answer);
                                None
                            }
                            Ok(Message::Ping(_)) => {
                                log::debug!("ping");
                                None
                            }
                            Ok(m) => {
                                log::debug!("Unexpected message {:?}", m);
                                None
                            }
                            // ignore errors
                            Err(e) => {
                                log::error!("Unexpected error {:?}", e);
                                None
                            }
                        }
                    });

                    let mut out = false;

                    // break on Some
                    loop {
                        let next = fut.next().await;

                        if let Some(x) = next {
                            if let Some(x) = x.await {
                                out = x;
                                break;
                            }
                        }
                    }

                    log::info!("Reader exited successfully");
                    out
                };
                let write_fut = async move {
                    let status = write_status;
                    let success = write_success;

                    'base: while *status.lock().await.deref() == CheckerStatus::Active {
                        if success.lock().await.clone() {
                            // deactivate
                            *status.lock().await.deref_mut() = CheckerStatus::Inactive;
                            break 'base;
                        }

                        sleep(Duration::from_secs_f64(0.020)).await;

                        if Instant::now()
                            .duration_since(last_sent_challenge)
                            .as_secs_f64()
                            >= api_access::get_ping_time().await
                        {
                            // send challenge
                            if let Ok(()) = write.send(Message::Text(challenge.clone())).await {
                                last_sent_challenge = Instant::now();
                                log::info!("Sent challenge!");
                            }
                        };
                    }

                    log::info!("Writer process exited successfully.")
                };

                let write_handle = tokio::spawn(write_fut);
                log::info!("Spawned writer");
                let read_handle = tokio::spawn(read_fut);
                log::info!("Spawned reader");

                let succ = read_handle.await;
                let succ = succ.unwrap_or(false);
                *success.lock().await.deref_mut() = succ;

                let answer = if succ {
                    AuthAnswer::Allowed
                } else {
                    AuthAnswer::Denied
                };

                *final_answer.lock().await.deref_mut() = Some(answer);

                log::info!("Resolving callbacks...");
                {
                    let mut callbacks = callbacks.lock().await;
                    for callback in callbacks.drain(0..).collect::<Vec<_>>() {
                        callback(answer);
                    }
                }
                log::info!("Callbacks resolved!");

                answer
            };

            fut.await
        }

        pub async fn stop_checking(&mut self) {
            // set active to false
            *self.status.lock().await.deref_mut() = CheckerStatus::Inactive;
        }

        // returns a copy
        pub async fn get_answer(&self) -> Option<AuthAnswer> {
            self.answer.lock().await.clone()
        }

        pub async fn is_finished(&self) -> bool {
            self.answer.lock().await.is_some()
        }

        pub async fn add_callback(&mut self, callback: Box<dyn FnOnce(AuthAnswer) + Send + Sync>) {
            if let Some(answer) = self.get_answer().await {
                callback(answer);
            } else {
                self.callbacks.lock().await.push(callback);
            }
        }
    }
}

lazy_static::lazy_static! {
    static ref TFA_MANAGER: Arc<Mutex<TFAManager>> = Arc::new(Mutex::new(TFAManager::new()));
}

pub struct TFAManager {
    checkers: HashMap<String, TFAChecker>,
}

impl TFAManager {
    pub fn is_2fa_enabled() -> bool {
        utils::is_2fa_enabled()
    }

    fn new() -> Self {
        Self {
            checkers: HashMap::new(),
        }
    }

    pub async fn add_callback(id: &str, callback: Box<dyn FnOnce(AuthAnswer) + Send + Sync>) {
        log::info!("Adding Callback for id {id}");

        if let Some(checker) = TFA_MANAGER.lock().await.checkers.get_mut(id) {
            checker.add_callback(callback).await;
        } else {
            log::info!("No checker for id {id}");
        }
    }
    pub async fn get_answer(id: &str) -> Option<AuthAnswer> {
        TFA_MANAGER
            .lock()
            .await
            .checkers
            .keys()
            .for_each(|k| log::info!("  * Checker {k}"));

        log::info!("getting answer for id {id}");

        if let Some(checker) = TFA_MANAGER.lock().await.checkers.get(id) {
            checker.get_answer().await
        } else {
            log::info!("No checker for id {id}");
            None
        }
    }

    // not for ui side
    pub async fn start_checking(id: &str) -> TFAChecker {
        log::info!("Starting to check id {id}...");

        let checkers = &mut TFA_MANAGER.lock().await.checkers;

        if let Some(checker) = checkers.get_mut(id) {
            checker.stop_checking().await;
        }

        let checker = TFAChecker::new();

        let mut checker_clone = checker.clone();

        tokio::spawn(async move { checker_clone.check_async().await });

        checkers.insert(id.to_string(), checker.clone());

        checker
    }
    pub async fn remove_checker(id: &str) -> Option<()> {
        log::info!("Trying to remove id {id}");
        match TFA_MANAGER.lock().await.checkers.remove(id) {
            Some(mut checker) => {
                checker.stop_checking().await;
                Some(())
            }
            None => None,
        }
    }
}

pub mod ui {
    use crate::two_factor_auth::sockets::*;
    use crate::two_factor_auth::utils::*;
    use crate::two_factor_auth::{TFAManager, TFA_MANAGER};
    use hbb_common::config::Config;
    use hbb_common::{log};
    use sciter::{EventHandler, Value, HELEMENT};
    use std::time::Instant;

    struct Enable2FA;

    impl EventHandler for Enable2FA {
        fn on_script_call(&mut self, root: HELEMENT, name: &str, args: &[Value]) -> Option<Value> {
            match name {
                "is_2fa_enabled" => Some(Value::from(is_2fa_enabled())),
                "enable_2fa" => {
                    let secret = random_alphanum(32);
                    let qr = make_qr_code(&secret);
                    let qr_base64_img = qr_code_to_raw_img(qr);

                    let mut out = Value::map();
                    out.set_item("img_base64", qr_base64_img);
                    out.set_item("link", make_2fa_link(&secret));

                    Config::set_option("2fa-secret".to_owned(), secret);

                    Some(out)
                }
                "disable_2fa" => {
                    // forget secret
                    Config::set_option("2fa-secret".to_owned(), "".to_owned());

                    Some(Value::null())
                }

                _ => None,
            }
        }
    }

    pub struct Manage2FA;

    impl EventHandler for Manage2FA {
        fn on_script_call(&mut self, root: HELEMENT, name: &str, args: &[Value]) -> Option<Value> {
            match name {
                "is_2fa_enabled" => Some(Value::from(is_2fa_enabled())),

                "add_callback" => {
                    if args.len() < 2 {
                        log::error!(
                            "Error in TFAManager::add_callback: not enough arguments supplied.\n\
                        Expected 2 arguments, found {}.",
                            args.len()
                        );
                        return None;
                    }

                    let id = args[0].to_string();
                    let callback = args[1].clone();

                    if !callback.is_function()
                        && !callback.is_native_function()
                        && !callback.is_object_function()
                    {
                        log::error!(
                            "Error in TFAManager::add_callback: callback is not a function.\n\
                        Callback is of type {:?}.",
                            callback.full_type()
                        );
                        return None;
                    }

                    futures::executor::block_on(async move {
                        TFAManager::add_callback(
                            &id,
                            Box::new(move |answer| {
                                let _ =
                                    callback.call(None, &[Value::from(answer.to_string())], None);
                            }),
                        )
                        .await;
                    });

                    Some(Value::null())
                }
                "get_answer" => {
                    if args.len() < 1 {
                        log::error!(
                            "Error in TFAManager::add_callback: not enough arguments supplied.\n\
                        Expected 1 arguments, found {}.",
                            args.len()
                        );
                        return None;
                    }

                    let id = args[0].to_string();

                    Some(
                        match futures::executor::block_on(async move {
                            TFAManager::get_answer(&id).await
                        }) {
                            Some(answer) => Value::from(answer.to_string()),
                            None => Value::null(),
                        },
                    )
                }
                _ => None,
            }
        }
    }

    pub fn enable_2fa_behaviour_factory() -> Box<dyn EventHandler> {
        Box::new(Enable2FA)
    }

    pub fn manage_2fa_behaviour_factory() -> Box<dyn EventHandler> {
        Box::new(Manage2FA)
    }
}
