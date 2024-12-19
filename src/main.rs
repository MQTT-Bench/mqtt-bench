use std::sync::Arc;

use clap::Parser;
use log::{info, trace};

use mqtt_bench::cli::{Cli, Commands};
use mqtt_bench::state::{ctrl_c, print_stats, State};

use mqtt_bench::command::{benchmark, connect, publish, subscribe};
use mqtt_bench::statistics::Statistics;
use tokio::sync::mpsc::{channel, Receiver};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn watch_state(state: Arc<State>, rx: Receiver<()>) {
    ctrl_c(Arc::clone(&state));
    print_stats(state, rx);
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::builder().format_timestamp_millis().init();

    console_subscriber::init();

    let cli = Cli::parse();
    let (tx, rx) = channel::<()>(1);
    let statistics = Statistics::new();

    let state;
    match cli.command {
        Some(cmd) => match cmd {
            Commands::Connect { mut common } => {
                common.tls_config.try_load_ca()?;
                state = State::new(common.total);
                watch_state(Arc::clone(&state), rx);
                connect(&common, &state, &statistics).await?;
            }

            Commands::Pub {
                mut common,
                mut pub_options,
            } => {
                common.tls_config.try_load_ca()?;
                state = State::new(common.total);
                watch_state(Arc::clone(&state), rx);
                if 0 == pub_options.topic_total {
                    pub_options.topic_total = common.total;
                    info!(
                        "Now that --topic-total is 0, it will be set to --topic-total={}",
                        common.total
                    );
                }

                publish(&common, &state, &statistics, &pub_options).await?;
            }

            Commands::Sub {
                mut common,
                mut sub_options,
            } => {
                common.tls_config.try_load_ca()?;
                state = State::new(common.total);
                watch_state(Arc::clone(&state), rx);
                if 0 == sub_options.topic_total {
                    sub_options.topic_total = common.total;
                    info!(
                        "Now that --topic-total is 0, it will be set to --topic-total={}",
                        common.total
                    );
                }

                subscribe(&common, &state, &statistics, &sub_options).await?;
            }

            Commands::Benchmark {
                mut common,
                mut pub_options,
            } => {
                common.tls_config.try_load_ca()?;
                state = State::new(common.total);
                watch_state(Arc::clone(&state), rx);
                if 0 == pub_options.topic_total {
                    pub_options.topic_total = common.total;
                    info!(
                        "Now that --topic-total is 0, it will be set to --topic-total={}",
                        common.total
                    );
                }

                benchmark(&common, &state, &statistics, &pub_options).await?;
            }
        },

        None => {
            println!("No command specified");
        }
    }

    // Attempt to signal task that is printing statistics.
    if let Err(_e) = tx.send(()).await {
        trace!("Should have received Ctrl-C signal");
    }

    Ok(())
}
