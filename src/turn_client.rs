use hbb_common::{tcp::FramedStream, tokio::net::TcpStream, ResultType};
use std::{net::SocketAddr, sync::Arc};
use turn::client::{tcp::TcpSplit, ClientConfig};
use webrtc_util::conn::Conn;

#[derive(Debug)]
pub struct TurnConfig {
    addr: String,
    username: String,
    password: String,
}

async fn get_turn_servers() -> Option<Vec<TurnConfig>> {
    let map = hbb_common::api::call_api().await.ok()?;
    let mut servers = Vec::new();
    for server in map["turnservers"].as_array()? {
        if server["protocol"].as_str()? == "turn" {
            servers.push(TurnConfig {
                addr: format!("{}:{}", server["host"].as_str()?, server["port"].as_str()?),
                username: server["username"].as_str()?.to_string(),
                password: server["password"].as_str()?.to_string(),
            });
        }
    }
    Some(servers)
}

pub async fn new_relay_addrs(peer_addr: SocketAddr) -> Vec<(TurnClient, SocketAddr)> {
    let mut client_addrs = vec![];
    if let Some(turn_servers) = get_turn_servers().await {
        for config in turn_servers {
            if let Ok(turn_client) = TurnClient::new(config).await {
                if let Ok(relay_addr) = turn_client.create_relay_connection(peer_addr).await {
                    client_addrs.push((turn_client, relay_addr));
                }
            }
        }
    }
    client_addrs
}

pub async fn get_public_ip() -> Option<SocketAddr> {
    let servers = get_turn_servers().await?;
    for config in servers {
        if let Ok(turn_client) = TurnClient::new(config).await {
            if let Ok(addr) = turn_client.get_public_ip().await {
                return Some(addr);
            }
        }
    }
    None
}

pub struct TurnClient {
    client: turn::client::Client,
}

impl TurnClient {
    pub async fn new(config: TurnConfig) -> ResultType<Self> {
        let tcp_split = TcpSplit::from(TcpStream::connect(&config.addr).await?);
        let mut client = turn::client::Client::new(ClientConfig {
            stun_serv_addr: config.addr.clone(),
            turn_serv_addr: config.addr,
            username: config.username,
            password: config.password,
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 0,
            conn: Arc::new(tcp_split),
            vnet: None,
        })
        .await?;
        client.listen().await?;
        Ok(Self { client })
    }

    pub async fn get_public_ip(&self) -> ResultType<SocketAddr> {
        Ok(self.client.send_binding_request().await?)
    }

    pub async fn create_relay_connection(&self, peer_addr: SocketAddr) -> ResultType<SocketAddr> {
        let relay_connection = self.client.allocate().await?;
        relay_connection.send_to(b"init", peer_addr).await?;
        Ok(relay_connection.local_addr().await?)
    }

    pub async fn wait_new_connection(&self) -> ResultType<FramedStream> {
        let tcp_stream = self.client.wait_new_connection().await.unwrap();
        let addr = tcp_stream.local_addr()?;
        Ok(FramedStream::from(tcp_stream, addr))
    }
}
