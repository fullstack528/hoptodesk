use std::{net::SocketAddr, convert::TryInto, fmt::Display};

use async_trait::async_trait;
use stun::{message::{Getter, Setter}, attributes::ATTR_CONNECTION_ID};
use tokio::{net::{TcpStream, tcp::{OwnedWriteHalf, OwnedReadHalf, ReuniteError}}, io::{AsyncReadExt, AsyncWriteExt}, sync::RwLock};
use util::{Conn};

#[derive(Debug)]
pub struct TcpSplit {
    reader: RwLock<Option<OwnedReadHalf>>,
    writer: RwLock<Option<OwnedWriteHalf>>,
}

impl TcpSplit {
    pub async fn into_stream(&self) -> Result<TcpStream, ReuniteError> {
        self.reader.write().await.take().unwrap().reunite(self.writer.write().await.take().unwrap())
    }
}

impl From<TcpStream> for TcpSplit {
    fn from(stream: TcpStream) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            reader: RwLock::new(Some(reader)),
            writer: RwLock::new(Some(writer)),
        }
    }
}

#[async_trait]
impl Conn for TcpSplit {
    async fn connect(&self, _: SocketAddr) -> util::Result<()> {
        unimplemented!();
    }

    async fn recv(&self, buf: &mut [u8]) -> util::Result<usize> {
        Ok(self.reader.write().await.as_mut().unwrap().read(buf).await?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> util::Result<(usize, SocketAddr)> {
        Ok((self.recv(buf).await?, self.reader.read().await.as_ref().unwrap().peer_addr()?))
    }

    async fn send(&self, buf: &[u8]) -> util::Result<usize> {
        Ok(self.writer.write().await.as_mut().unwrap().write(buf).await?)
    }

    async fn send_to(&self, buf: &[u8], _: SocketAddr) -> util::Result<usize> {
        self.send(buf).await
    }

    async fn local_addr(&self) -> util::Result<SocketAddr> {
        Ok(self.reader.read().await.as_ref().unwrap().local_addr()?)
    }

    async fn remote_addr(&self) -> Option<SocketAddr> {
        self.reader.read().await.as_ref().unwrap().peer_addr().ok()
    }

    async fn close(&self) -> util::Result<()> {
        Ok(())
    }
}


#[derive(Default)]
pub struct ConnectionID(u32);

impl Display for ConnectionID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Getter for ConnectionID {
    fn get_from(&mut self, m: &stun::message::Message) -> Result<(), stun::Error> {
        let value = m.get(ATTR_CONNECTION_ID)?;
        self.0 = u32::from_be_bytes(value.try_into().map_err(|_| stun::Error::ErrAttributeSizeInvalid)?);
        Ok(())
    }
}

impl Setter for ConnectionID {
    fn add_to(&self, m: &mut stun::message::Message) -> Result<(), stun::Error> {
        m.add(ATTR_CONNECTION_ID, &self.0.to_be_bytes());
        Ok(())
    }
}