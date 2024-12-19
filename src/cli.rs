use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use log::{debug, info};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

const CA_KEY_NAME: &str = "CA.key";
const CA_CERT_NAME: &str = "CA.crt";

#[derive(Debug, Parser)]
#[command(name = "mqtt-bench", author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq)]
pub enum TlsType {
    None,
    TLS,
    MTLS,
    BYOC,
}

#[derive(Debug, Clone, Args)]
pub struct TlsConfig {
    /// Mode of TLS
    ///
    /// - None for clear-text TCP
    ///
    /// - TLS when client uses plain TLS
    ///
    /// - mTLS when mutable-TLS and use the same key/cert for all clients
    ///
    /// - BYOC when mTLS and each client uses its own key/cert pair
    #[arg(long, default_value_t = TlsType::None, value_enum)]
    pub tls_type: TlsType,

    /// Absolute path to the directory where CA.key, CA.cert and device certs are stored
    #[arg(long)]
    pub tls_path: Option<String>,

    #[clap(skip)]
    pub ca_cert: Option<X509>,

    #[clap(skip)]
    pub ca_key: Option<PKey<Private>>,

    #[clap(skip)]
    pub trusted_ca_certs: Vec<X509>,
}

impl TlsConfig {
    pub fn try_load_ca(&mut self) -> Result<(), anyhow::Error> {
        match self.tls_type {
            TlsType::None => {
                debug!("TLS is disabled");
                return Ok(());
            }
            TlsType::TLS => {
                debug!("TLS");
                return Ok(());
            }
            TlsType::MTLS => {
                info!("mTLS");
            }
            TlsType::BYOC => {
                info!("BYOC");
            }
        }
        let path = self
            .tls_path
            .as_ref()
            .ok_or(anyhow::anyhow!("TLS config path required"))?;

        let entries = std::fs::read_dir(path).context("Failed to list directory {path}")?;

        for entry in entries {
            let entry = entry.context("Failed to visit directory entry")?;
            let file_type = entry.file_type().context("Failed to acquire file type")?;
            if !file_type.is_file() {
                continue;
            }

            if let Some(file_name) = entry.file_name().to_str() {
                if file_name == CA_KEY_NAME {
                    let ca_key_path = entry.path();
                    self.ca_key = Some(crate::cert::load_ca_pkey(&ca_key_path)?);
                }

                if file_name == CA_CERT_NAME {
                    let ca_cert_path = entry.path();
                    self.ca_cert = Some(crate::cert::load_ca_cert(&ca_cert_path)?);
                }
            }

            if self.ca_cert.is_some() && self.ca_key.is_some() {
                break;
            }
        }
        Ok(())
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            tls_type: TlsType::None,
            tls_path: None,
            ca_cert: None,
            ca_key: None,
            trusted_ca_certs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct Common {
    #[arg(long)]
    pub host: String,

    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    #[arg(short = 'u', long)]
    pub username: String,

    #[arg(short = 'P', long)]
    pub password: String,

    #[arg(short = 's', long)]
    pub ssl: bool,

    #[arg(short, long)]
    pub verify: bool,

    #[arg(short, long)]
    pub auth_server_certificate: bool,

    #[arg(short = 'q', long, default_value_t = 1)]
    pub qos: i32,

    #[arg(short = 'n', long, default_value_t = 0)]
    pub start_number: usize,

    /// Total number of client to create
    #[arg(long, default_value_t = 16)]
    pub total: usize,

    /// The number of clients to create in parallel for each iteration
    #[arg(short = 'c', long, default_value_t = 4)]
    pub concurrency: usize,

    /// The interval between each message publishing for each client in milliseconds.
    #[arg(short = 'i', long, default_value_t = 100)]
    pub interval: u64,

    /// The duration of the test in seconds.
    #[arg(long, default_value_t = 60)]
    pub time: usize,

    #[arg(long, default_value_t = String::from("BenchClient%d"))]
    pub client_id: String,

    #[arg(long, default_value_t = true)]
    pub show_statistics: bool,

    #[arg(long, default_value_t = 5)]
    pub connect_timeout: u64,

    #[arg(long, default_value_t = 3)]
    pub keep_alive_interval: u64,

    #[arg(long, default_value_t = 1024)]
    pub max_inflight: i32,

    #[command(flatten)]
    pub tls_config: TlsConfig,
}

impl Common {
    pub fn connection_string(&self) -> String {
        if self.ssl {
            format!("ssl://{}:{}", self.host, self.port.unwrap_or(8883))
        } else {
            format!("tcp://{}:{}", self.host, self.port.unwrap_or(1883))
        }
    }

    pub fn client_id_of(&self, id: usize) -> String {
        if self.client_id.contains("%d") {
            return self.client_id.replace("%d", &id.to_string());
        }
        self.client_id.clone()
    }
}

#[derive(Debug, Clone, Args)]
pub struct PubOptions {
    /// Topic pattern to publish messages to.
    ///
    /// The topic pattern can contain a `%d` placeholder which will be replaced by an ID.
    ///
    /// For example, if the topic pattern is `home/%d`, the actual topic will be `home/0`, `home/1`, etc.
    #[arg(long, default_value_t = String::from("home/%d"))]
    pub topic: String,

    /// If `topic` contains `%i`, this is the number of topics to publish messages to.
    ///
    /// If `topic_total` is less than number of the clients: `total`, the topics will be reused;
    /// If the `topic_total` is greater than the number of clients, only the first `total` topics
    /// will be used during benchmark;
    ///
    /// If `topic_total` is 0, it will be set to `total`.
    #[arg(long, default_value_t = 0)]
    pub topic_total: usize,

    #[arg(long, default_value_t = 64)]
    pub message_size: u32,

    #[arg(long)]
    pub payload: Option<String>,
}

impl PubOptions {
    pub fn topic_of(&self, id: usize) -> String {
        if self.topic.contains("%d") {
            return self.topic.replace("%d", &id.to_string());
        }
        self.topic.clone()
    }
}

#[derive(Debug, Clone, Args)]
pub struct SubOptions {
    #[arg(long)]
    pub topic: String,

    /// If `topic` contains `%i`, this is the number of topics to publish messages to.
    ///
    /// If `topic_total` is less than number of the clients: `total`, the topics will be reused;
    /// If the `topic_total` is greater than the number of clients,
    /// only the first `total` topics will be used during the benchmark.
    ///
    /// If `topic_total` is 0, it will be set to `total`.
    #[arg(long, default_value_t = 0)]
    pub topic_total: usize,
}

impl SubOptions {
    pub fn topic_of(&self, id: usize) -> String {
        if self.topic.contains("%d") {
            return self.topic.replace("%d", &id.to_string());
        }
        self.topic.clone()
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Connect {
        #[command(flatten)]
        common: Common,
    },

    Pub {
        #[command(flatten)]
        common: Common,

        #[command(flatten)]
        pub_options: PubOptions,
    },

    Sub {
        #[command(flatten)]
        common: Common,

        #[command(flatten)]
        sub_options: SubOptions,
    },

    Benchmark {
        #[command(flatten)]
        common: Common,

        #[command(flatten)]
        pub_options: PubOptions,
    },
}
