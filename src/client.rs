use super::cli::{Common, TlsType};
use crate::state::State;
use crate::statistics::LatencyHistogram;
use crate::subscription::Subscription;
use anyhow::{anyhow, Context};
use byteorder::ReadBytesExt;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::{debug, error, trace};
use mqtt::AsyncClient;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use paho_mqtt as mqtt;
use rumqttc::{
    check, Connect, ConnectReturnCode, Error, FixedHeader, PacketType, PingReq, Protocol,
};
use std::io::Cursor;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_openssl::SslStream;

const MAX_PACKET_SIZE: usize = 1024 * 64;
pub(crate) const MQTT_DEFAULT_TLS_PORT: u16 = 8883;
pub(crate) const MQTT_DEFAULT_PORT: u16 = 1883;

pub struct Client<S> {
    opts: Common,
    client_id: String,
    subscription: OnceLock<Subscription>,
    pub inner: AsyncClient,
    latency: LatencyHistogram,
    state: Arc<State>,
    stream: Option<S>,
    buffer: BytesMut,
}

impl Client<TcpStream> {
    pub async fn stream_connect(&mut self) -> Result<(), anyhow::Error> {
        let addr = format!(
            "{}:{}",
            self.opts.host,
            self.opts.port.unwrap_or(MQTT_DEFAULT_PORT)
        );

        let start = minstant::Instant::now();
        debug!("Connecting to {}", addr);
        let tcp_stream = TcpStream::connect(&addr)
            .await
            .context("Failed to connect")?;
        debug!("Connected to {}", addr);
        self.stream = Some(tcp_stream);
        let elapsed = start.elapsed().as_millis() as f64;
        self.latency.connect.observe(elapsed);
        Ok(())
    }
}

impl Client<SslStream<TcpStream>> {
    pub async fn stream_connect(&mut self) -> Result<(), anyhow::Error> {
        let addr = format!(
            "{}:{}",
            self.opts.host,
            self.opts.port.unwrap_or(MQTT_DEFAULT_TLS_PORT)
        );

        let mut ssl_context_builder = SslContext::builder(SslMethod::tls_client())?;
        let start = minstant::Instant::now();
        let tcp_stream = TcpStream::connect(&addr).await?;
        match self.opts.tls_config.tls_type {
            TlsType::None => return Err(anyhow!("Unreachable")),

            TlsType::TLS => {
                ssl_context_builder.set_verify(SslVerifyMode::NONE);
            }

            TlsType::MTLS | TlsType::BYOC => {
                let mut key = None;
                let mut cert = None;
                if let Some((ca_key, ca_cert)) = self
                    .opts
                    .tls_config
                    .ca_key
                    .as_ref()
                    .zip(self.opts.tls_config.ca_cert.as_ref())
                {
                    let (dev_cert, dev_key) =
                        crate::cert::mk_ca_signed_cert(ca_cert, ca_key, &self.client_id)?;
                    key = Some(dev_key);
                    cert = Some(dev_cert);
                }
                if let Some((cert, key)) = cert.as_ref().zip(key.as_ref()) {
                    ssl_context_builder.set_certificate(cert)?;
                    ssl_context_builder.set_private_key(key)?;
                }
                ssl_context_builder.set_verify(SslVerifyMode::PEER);
            }
        }
        let ssl_context = ssl_context_builder.build();
        let ssl = Ssl::new(&ssl_context)?;
        let mut ssl_stream = SslStream::new(ssl, tcp_stream)?;
        let pin_ssl_stream = Pin::new(&mut ssl_stream);
        pin_ssl_stream.connect().await?;
        let elapsed = start.elapsed().as_millis() as f64;
        self.latency.connect.observe(elapsed);
        self.stream = Some(ssl_stream);
        Ok(())
    }
}

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(
        opts: Common,
        client_id: String,
        stream: Option<S>,
        latency: LatencyHistogram,
        state: Arc<State>,
    ) -> Result<Self, anyhow::Error> {
        let server_uri = if opts.ssl {
            format!("ssl://{}:{}", opts.host, opts.port.unwrap_or(8883))
        } else {
            format!("tcp://{}:{}", opts.host, opts.port.unwrap_or(1883))
        };

        let create_opts = mqtt::CreateOptionsBuilder::new_v3()
            .client_id(&client_id)
            .server_uri(server_uri)
            .mqtt_version(mqtt::MQTT_VERSION_3_1_1)
            .persistence(mqtt::PersistenceType::None)
            .send_while_disconnected(false)
            .allow_disconnected_send_at_anytime(false)
            .finalize();

        let client = AsyncClient::new(create_opts).context("Failed to create MQTT AsyncClient")?;
        let e2e_histogram = latency.subscribe.clone();
        let _state = Arc::clone(&state);
        client.set_message_callback(move |_client, message| {
            if let Some(message) = message {
                _state.on_receive();
                let payload = message.payload();
                let mut cursor = Cursor::new(payload);
                if cursor.remaining() > size_of::<u128>() {
                    match ReadBytesExt::read_u128::<byteorder::LittleEndian>(&mut cursor) {
                        Ok(ts) => {
                            let now = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_millis();
                            if now >= ts {
                                e2e_histogram.observe((now - ts) as f64);
                            }
                        }
                        Err(e) => {
                            error!("Failed to read timestamp from payload: {}", e);
                        }
                    }
                }
                trace!("Received message, topic={}", message.topic());
            }
        });

        Ok(Self {
            opts,
            client_id,
            subscription: OnceLock::new(),
            inner: client,
            latency,
            state,
            stream,
            buffer: BytesMut::new(),
        })
    }

    async fn write(&mut self, src: &[u8]) -> Result<bool, anyhow::Error> {
        if let Some(stream) = self.stream.as_mut() {
            stream.write_all(src).await?;
            stream.flush().await?;
            trace!("{} wrote {} bytes to server", &self.client_id, src.len());
            return Ok(true);
        }
        Err(anyhow!("Missing stream"))
    }

    async fn read(&mut self) -> Result<(FixedHeader, Bytes), anyhow::Error> {
        if let Some(stream) = self.stream.as_mut() {
            let mut buf = [0u8; 16];
            loop {
                let limit = AsyncReadExt::read(stream, &mut buf).await?;
                if 0 == limit {
                    return Err(anyhow::anyhow!("EOF"));
                }
                trace!("{} read {limit} bytes from network", &self.client_id);
                self.buffer.put_slice(&buf[..limit]);

                match check(self.buffer.iter(), MAX_PACKET_SIZE) {
                    Ok(fixed_header) => {
                        let packet_buf = self.buffer.split_to(fixed_header.frame_length()).freeze();
                        return Ok((fixed_header, packet_buf));
                    }
                    Err(Error::PayloadSizeLimitExceeded(n)) => {
                        return Err(anyhow!(format!("PayloadSizeLimitExceeded: {}", n)));
                    }
                    Err(Error::InsufficientBytes(_n)) => {}
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
        }
        Err(anyhow::anyhow!("Missing stream"))
    }

    pub async fn mqtt_connect(&mut self) -> Result<(), anyhow::Error> {
        let mut connect = Connect::new(&self.client_id);
        connect.protocol = Protocol::V4;
        connect.set_login(&self.opts.username, &self.opts.password);
        let mut buf = BytesMut::new();
        connect
            .write(&mut buf)
            .context("Failed to serialize CONNECT packet")?;
        self.write(&buf).await?;
        debug!("{} sent Connect packet", self.client_id);
        loop {
            let (fixed_header, packet_buf) = self.read().await?;
            if fixed_header.packet_type()? == PacketType::ConnAck {
                trace!("{} received ConnAck packet", self.client_id);
                let conn_ack = rumqttc::ConnAck::read(fixed_header, packet_buf)?;
                if ConnectReturnCode::Success == conn_ack.code {
                    self.state.on_connected();
                    return Ok(());
                }
                return Err(anyhow!(format!("Failed to connect: {:?}", conn_ack.code)));
            }
        }
    }

    pub async fn mqtt_disconnect(&mut self) -> Result<(), anyhow::Error> {
        let mut buf = BytesMut::new();
        rumqttc::Disconnect.write(&mut buf)?;
        debug!("{} attempts to disconnect", self.client_id);
        self.write(&buf).await.context("Failed to disconnect")?;
        Ok(())
    }

    pub async fn mqtt_ping(&mut self) -> Result<(), anyhow::Error> {
        let mut buf = BytesMut::new();
        PingReq
            .write(&mut buf)
            .context("Failed to serialize CONNECT packet")?;

        self.write(&buf).await?;
        trace!("{} PingReq sent", self.client_id);
        loop {
            let (fixed_header, _buf) = self.read().await?;
            if PacketType::PingResp == fixed_header.packet_type()? {
                trace!("{} PingResp packet received", self.client_id);
                break;
            }
        }
        Ok(())
    }
}

impl<S> Client<S> {
    pub fn client_id(&self) -> String {
        self.inner.client_id()
    }

    pub fn keep_alive_interval(&self) -> u64 {
        self.opts.keep_alive_interval
    }
    pub fn connected(&self) -> bool {
        self.inner.is_connected()
    }

    pub async fn connect(&self) -> Result<(), anyhow::Error> {
        let connect_opts = mqtt::ConnectOptionsBuilder::new_v3()
            .clean_session(true)
            .user_name(&self.opts.username)
            .password(&self.opts.password)
            .connect_timeout(Duration::from_secs(self.opts.connect_timeout))
            .keep_alive_interval(Duration::from_secs(self.opts.keep_alive_interval))
            .max_inflight(self.opts.max_inflight)
            .automatic_reconnect(Duration::from_millis(100), Duration::from_secs(3))
            .ssl_options(
                mqtt::SslOptionsBuilder::new()
                    .verify(self.opts.verify)
                    .enable_server_cert_auth(self.opts.auth_server_certificate)
                    .ssl_version(mqtt::SslVersion::Tls_1_2)
                    .finalize(),
            )
            .finalize();

        let connected_state = Arc::clone(&self.state);
        let sub = self.subscription.get().cloned();
        self.inner.set_connected_callback(move |cli| {
            debug!(
                "Client[client-id={}] connected to server_uri={}",
                cli.client_id(),
                cli.server_uri()
            );
            connected_state.on_connected();
            if let Some(subscription) = &sub {
                cli.subscribe(&subscription.topic_filter, subscription.qos);
            }
        });

        let state_ = Arc::clone(&self.state);
        self.inner.set_connection_lost_callback(move |c| {
            debug!(
                "Client[client-id={}] lost connection, reconnecting...",
                c.client_id()
            );
            c.reconnect();
            state_.on_disconnected();
        });

        if self.state.stopped() {
            return Ok(());
        }

        let instant = Instant::now();
        self.inner
            .connect(connect_opts)
            .await
            .context("Failed to connect to the MQTT server")?;

        self.latency
            .connect
            .observe(instant.elapsed().as_millis() as f64);
        Ok(())
    }

    pub async fn publish(&self, message: mqtt::Message) -> Result<(), anyhow::Error> {
        let topic = message.topic().to_owned();
        let instant = Instant::now();
        if let Err(e) = self
            .inner
            .publish(message)
            .await
            .context("Failed to publish message")
        {
            self.state.on_publish_failure();
            return Err(e);
        }

        self.latency
            .publish
            .observe(instant.elapsed().as_millis() as f64);
        self.state.on_publish();
        trace!("{} published a message to {}", self.client_id(), topic);
        Ok(())
    }

    pub fn subscribe(&self, topic: &str, qos: i32) {
        let subscription = Subscription::new(topic.to_owned(), qos);
        self.subscription.get_or_init(|| subscription);
    }
}

impl<S> Drop for Client<S> {
    fn drop(&mut self) {
        if self.connected() {
            if let Err(e) = self.inner.disconnect(None).wait() {
                error!("Failed to disconnect client: {}", e);
            }
        }
    }
}
