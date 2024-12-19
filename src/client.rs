use super::cli::{Common, TlsType};
use crate::state::State;
use crate::statistics::LatencyHistogram;
use crate::subscription::Subscription;
use anyhow::Context;
use byteorder::ReadBytesExt;
use bytes::Buf;
use log::{debug, error, trace};
use mqtt::AsyncClient;
use paho_mqtt as mqtt;
use std::io::Cursor;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use tokio::time::Instant;
use crate::cert;

pub struct Client {
    opts: Common,
    subscription: OnceLock<Subscription>,
    pub inner: AsyncClient,
    latency: LatencyHistogram,
    state: Arc<State>,
    key: Option<PKey<Private>>,
    cert: Option<X509>,
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
                    match cursor.read_u128::<byteorder::LittleEndian>() {
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
            if let Some((ca_key, ca_cert)) = opts.tls_config.ca_key.as_ref().zip(opts.tls_config.ca_cert.as_ref()) {
                let (dev_cert, dev_key) = cert::mk_ca_signed_cert(ca_cert, ca_key, &client_id)?;
                key = Some(dev_key);
                cert = Some(dev_cert);
            }
        }
        
        Ok(Self {
            opts,
            subscription: OnceLock::new(),
            inner: client,
            latency,
            state,
            key,
            cert,
        })
    }

    pub fn client_id(&self) -> String {
        self.inner.client_id()
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
