use lazy_static::lazy_static;
use std::sync::{Arc};
use tokio::sync::Mutex;

const API_URI: &'static str = "https://api.hoptodesk.com/";

#[derive(Debug, Clone)]
pub struct ApiError(String);

impl<E: std::error::Error> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self(e.to_string())
    }
}

#[derive(Default)]
struct OnceAPI {
    response: Arc<Mutex<Option<serde_json::Value>>>,
}

impl OnceAPI {
    async fn call(&self) -> Result<serde_json::Value, ApiError> {
        let mut r = self.response.lock().await;
        if let Some(r) = &*r {
            return Ok(r.clone());
        }
        let body = reqwest::get(API_URI).await?.text().await?;
        let ret: serde_json::Value = serde_json::from_str(&body)?;
        *r = Some(ret.clone());
        Ok(ret)
    }

    async fn erase(&self) {
        let mut r = self.response.lock().await;
        *r = None
    }
}

lazy_static! {
    static ref ONCE: OnceAPI = OnceAPI::default();
}

pub async fn call_api() -> Result<serde_json::Value, ApiError> {
    (*ONCE).call().await
}

pub async fn erase_api() {
    (*ONCE).erase().await
}