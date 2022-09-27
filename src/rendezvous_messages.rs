use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

const PROTOCOL: &str = "one-to-one";

#[derive(Serialize, Deserialize)]
pub struct ConnectRequest<'a> {
    protocol: &'a str,
    endpoint: &'a str,
    pub sender_id: &'a str,
}

impl<'a> ConnectRequest<'a> {
    pub fn new(endpoint: &'a str, sender_id: &'a str) -> Self {
        Self {
            protocol: PROTOCOL,
            endpoint,
            sender_id,
        }
    }
}

// Sent by the receiver, indicates which address he is listening to
#[derive(Serialize, Deserialize)]
pub struct Listening<'a> {
    protocol: &'a str,
    endpoint: &'a str,
    pub addr: SocketAddr,
    pub public_addr: SocketAddr,
    pub pk: String,

    #[serde(default)]
    pub nat_type: i32,
}

impl<'a> Listening<'a> {
    pub fn new(
        endpoint: &'a str,
        addr: SocketAddr,
        public_addr: SocketAddr,
        pk: Vec<u8>,
        nat_type: i32,
    ) -> Self {
        Self {
            protocol: PROTOCOL,
            endpoint,
            addr,
            public_addr,
            pk: base64::encode(pk),
            nat_type,
        }
    }
}

// Sent by the initiator, indicates the ralay address
#[derive(Serialize, Deserialize)]
pub struct RelayConnection<'a> {
    protocol: &'a str,
    endpoint: &'a str,
    pub addr: SocketAddr,
}

impl<'a> RelayConnection<'a> {
    pub fn new(endpoint: &'a str, addr: SocketAddr) -> Self {
        Self {
            protocol: PROTOCOL,
            endpoint,
            addr,
        }
    }
}

// Sent by the initiator when he receives a new connection on the relay address
#[derive(Serialize, Deserialize)]
pub struct RelayReady<'a> {
    protocol: &'a str,
    endpoint: &'a str,
}

impl<'a> RelayReady<'a> {
    pub fn new(endpoint: &'a str) -> Self {
        Self {
            protocol: PROTOCOL,
            endpoint,
        }
    }
}

pub trait ToJson {
    fn to_json(&self) -> String;
}

impl<T: Serialize> ToJson for T {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}
