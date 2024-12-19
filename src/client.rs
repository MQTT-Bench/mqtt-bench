use super::cli::{Common, TlsType};
use crate::cert;
use crate::state::State;
use crate::statistics::LatencyHistogram;
use crate::subscription::Subscription;
use anyhow::Context;
use byteorder::ReadBytesExt;
use bytes::{Buf, BufMut, BytesMut};
use log::{debug, error, info, trace, warn};
use mqtt::AsyncClient;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use paho_mqtt as mqtt;
use rumqttc::{check, Connect, Error, PacketType, PingReq, Protocol};
use std::io::Cursor;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_openssl::SslStream;

const MAX_PACKET_SIZE: usize = 1024 * 64;

pub struct Client {
    opts: Common,
    client_id: String,
    subscription: OnceLock<Subscription>,
    pub inner: AsyncClient,
    latency: LatencyHistogram,
    state: Arc<State>,
    key: Option<PKey<Private>>,
    cert: Option<X509>,
    stream: Option<SslStream<TcpStream>>,
    buffer: BytesMut,
}

impl Client {
    pub fn new(
        opts: Common,
        client_id: String,
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
                if cursor.remaining() > std::mem::size_of::<u128>() {
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

        let mut key = None;
        let mut cert = None;

        if opts.tls_config.tls_type == TlsType::MTLS || TlsType::BYOC == opts.tls_config.tls_type {
            if let Some((ca_key, ca_cert)) = opts
                .tls_config
                .ca_key
                .as_ref()
                .zip(opts.tls_config.ca_cert.as_ref())
            {
                let (dev_cert, dev_key) = cert::mk_ca_signed_cert(ca_cert, ca_key, &client_id)?;
                key = Some(dev_key);
                cert = Some(dev_cert);
            }
        }

        Ok(Self {
            opts,
            client_id,
            subscription: OnceLock::new(),
            inner: client,
            latency,
            state,
            key,
            cert,
            stream: None,
            buffer: BytesMut::new(),
        })
    }

    pub fn client_id(&self) -> String {
        self.inner.client_id()
    }

    pub fn keep_alive_interval(&self) -> u64 {
        self.opts.keep_alive_interval
    }

    pub async fn tls_connect(&mut self) -> Result<(), anyhow::Error> {
        let addr = format!("{}:{}", self.opts.host, self.opts.port.unwrap_or(8883));
        let mut tcp_stream = TcpStream::connect(&addr).await?;
        let mut ssl_context_builder = SslContext::builder(SslMethod::tls_client())?;
        if let Some((cert, key)) = self.cert.as_ref().zip(self.key.as_ref()) {
            ssl_context_builder.set_certificate(cert)?;
            ssl_context_builder.set_private_key(&key)?;
        }
        ssl_context_builder.set_verify(SslVerifyMode::NONE);
        let ssl_context = ssl_context_builder.build();
        let ssl = Ssl::new(&ssl_context)?;
        let mut ssl_stream = SslStream::new(ssl, tcp_stream)?;
        let pin_ssl_stream = Pin::new(&mut ssl_stream);
        pin_ssl_stream.connect().await?;
        self.stream = Some(ssl_stream);
        Ok(())
    }

    pub async fn mqtt_connect(&mut self) -> Result<(), anyhow::Error> {
        if let Some(ssl_stream) = self.stream.as_mut() {
            let mut connect = Connect::new(&self.client_id);
            connect.protocol = Protocol::V4;
            connect.set_login(&self.opts.username, &self.opts.password);
            let mut buf = BytesMut::new();
            connect
                .write(&mut buf)
                .context("Failed to serialize CONNECT packet")?;
            ssl_stream.write_all(&buf).await?;
            ssl_stream.flush().await?;
            info!("{} Connect packet sent", self.client_id);
            let mut buf = [0u8; 16];
            loop {
                let limit = AsyncReadExt::read(ssl_stream, &mut buf).await?;
                if 0 == limit {
                    warn!("{} Reached EOF while awaiting ConnAck", self.client_id);
                    break;
                }
                trace!("{} Read {limit} bytes from network", self.client_id);
                self.buffer.put_slice(&buf[..limit]);

                match check(self.buffer.iter(), MAX_PACKET_SIZE) {
                    Ok(fixed_header) => {
                        let packet_buf = self.buffer.split_to(fixed_header.frame_length()).freeze();
                        match fixed_header.packet_type() {
                            Ok(PacketType::ConnAck) => {
                                info!("{} ConnAck packet received", self.client_id);
                                break;
                            }
                            _ => {
                                continue;
                            }
                        }
                    }
                    Err(Error::PayloadSizeLimitExceeded(_n)) => {
                        break;
                    }
                    Err(Error::InsufficientBytes(_n)) => {}
                    Err(e) => {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn mqtt_ping(&mut self) -> Result<(), anyhow::Error> {
        if let Some(ssl_stream) = self.stream.as_mut() {
            let mut buf = BytesMut::new();
            PingReq
                .write(&mut buf)
                .context("Failed to serialize CONNECT packet")?;
            ssl_stream.write_all(&buf).await?;
            ssl_stream.flush().await?;
            trace!("{} PingReq sent", self.client_id);
            let mut buf = [0u8; 16];
            loop {
                let limit = AsyncReadExt::read(ssl_stream, &mut buf).await?;
                if limit == 0 {
                    warn!("{} Reached EOF while awaiting PingResp", self.client_id);
                    break;
                }

                trace!("{} Read {limit} bytes from network", self.client_id);
                self.buffer.put_slice(&buf[..limit]);
                match check(self.buffer.iter(), MAX_PACKET_SIZE) {
                    Ok(fixed_header) => {
                        let packet_buf = self.buffer.split_to(fixed_header.frame_length()).freeze();
                        match fixed_header.packet_type() {
                            Ok(PacketType::PingResp) => {
                                trace!("{} PingResp packet received", self.client_id);
                                break;
                            }
                            _ => {
                                continue;
                            }
                        }
                    }
                    Err(Error::PayloadSizeLimitExceeded(_n)) => {
                        break;
                    }
                    Err(Error::InsufficientBytes(_n)) => {}
                    Err(e) => {
                        break;
                    }
                }
            }
        }
        Ok(())
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

    pub fn connected(&self) -> bool {
        self.inner.is_connected()
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

impl Drop for Client {
    fn drop(&mut self) {
        if self.connected() {
            if let Err(e) = self.inner.disconnect(None).wait() {
                error!("Failed to disconnect client: {}", e);
            }
        }
    }
}
