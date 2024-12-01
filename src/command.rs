use crate::cli::{Common, PubOptions, SubOptions};
use crate::state::State;
use crate::statistics::Statistics;
use anyhow::Context;
use byteorder::WriteBytesExt;
use log::{debug, error, info, trace, warn};
use paho_mqtt::MessageBuilder;
use std::io::Cursor;
use std::mem::size_of;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Semaphore;
use tokio::time::sleep;

pub async fn connect(
    common: &Common,
    state: &Arc<State>,
    statistics: &Statistics,
) -> Result<(), anyhow::Error> {
    let semaphore = Arc::new(Semaphore::new(common.concurrency));
    for id in common.start_number..common.total + common.start_number {
        if state.stopped() {
            break;
        }

        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("Failed to acquire connect permit")?;
        let client = match crate::client::Client::new(
            common.clone(),
            common.client_id_of(id),
            statistics.latency.clone(),
            Arc::clone(state),
        )
        .context(format!("Failed to create MQTT client client_{}", id))
        {
            Ok(client) => client,
            Err(e) => {
                error!("{}", e.to_string());
                break;
            }
        };

        let client_state = Arc::clone(state);
        let _ = tokio::task::Builder::new()
            .name(&client.client_id())
            .spawn(async move {
                // Retry till client connected
                loop {
                    if client.connect().await.is_err() {
                        if client_state.stopped() {
                            break;
                        }
                        continue
                    }
                    break;
                }
                drop(permit);

                let mut warning_count = 0;
                loop {
                    if client_state.stopped() {
                        break;
                    }

                    if client.connected() {
                        trace!("Client[client-id={}] ping...", client.client_id());
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    if warning_count % 100 == 0 {
                        warn!("Client[client-id={}] is disconnected, awaiting reconnect", client.client_id());
                    }
                    warning_count += 1;
                }
            });
    }

    await_connection(common.total, state).await;
    await_running(common, state).await;

    if common.show_statistics {
        statistics.show_statistics();
    }
    Ok(())
}

/// Await clients to connect.
///
async fn await_connection(total: usize, state: &Arc<State>) {
    loop {
        if state.connected() < total && !state.stopped() {
            debug!("{}/{} clients have connected", state.connected(), total);
            tokio::time::sleep(Duration::from_secs(1)).await;
        } else {
            break;
        }
    }

    if !state.stopped() {
        info!("All clients have connected and it is time to count down running time.");
    } else {
        info!("Got signal to stop.");
    }
}

pub async fn publish(
    common: &Common,
    state: &Arc<State>,
    statistics: &Statistics,
    pub_options: &PubOptions,
) -> Result<(), anyhow::Error> {
    let semaphore = Arc::new(Semaphore::new(common.concurrency));
    for id in common.start_number..common.total + common.start_number {
        if state.stopped() {
            break;
        }
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("Failed to acquire publish permit")?;
        let client = match crate::client::Client::new(
            common.clone(),
            common.client_id_of(id),
            statistics.latency.clone(),
            Arc::clone(state),
        )
        .context(format!("Failed to create MQTT client client_{}", id))
        {
            Ok(client) => client,
            Err(e) => {
                error!("{}", e.to_string());
                break;
            }
        };
        let payload = pub_options
            .payload
            .clone()
            .unwrap_or_else(|| "a".repeat(pub_options.message_size as usize));

        let topic = pub_options.topic_of(id);

        let pub_interval = Duration::from_millis(common.interval);
        let qos = common.qos;

        let client_state = Arc::clone(state);
        let _ = tokio::task::Builder::new()
            .name(&client.client_id())
            .spawn(async move {
                // Retry till client connected
                loop {
                    if client.connect().await.is_err() {
                        if client_state.stopped() {
                            break;
                        }
                        continue
                    }
                    break;
                }
                drop(permit);

                let mut payload: Vec<u8> = payload.into();

                let mut warning_count = 0;
                loop {
                    if let Err(e) = tag_timestamp(&mut payload[..]) {
                        error!("{}", e.to_string());
                        break;
                    }

                    let message = MessageBuilder::new()
                        .topic(&topic)
                        .payload(&payload[..])
                        .qos(qos)
                        .finalize();
                    if client_state.stopped() {
                        break;
                    }

                    if client.connected() {
                        if let Err(e) = client.publish(message.clone()).await {
                            error!("Failed to publish message: {}", e.to_string());
                            break;
                        }

                        if pub_interval.as_millis() > 0 {
                            tokio::time::sleep(pub_interval).await;
                        }
                        continue;
                    }
                    if warning_count % 100 == 0 {
                        warn!("Client[client-id={}] is disconnected, awaiting reconnect", client.client_id());
                    }
                    warning_count += 1;
                }
            });
    }

    await_connection(common.total, state).await;
    await_running(common, state).await;

    if common.show_statistics {
        statistics.show_statistics();
    }
    Ok(())
}

pub async fn subscribe(
    common: &Common,
    state: &Arc<State>,
    statistics: &Statistics,
    sub_options: &SubOptions,
) -> Result<(), anyhow::Error> {
    let semaphore = Arc::new(Semaphore::new(common.concurrency));
    for id in common.start_number..common.total + common.start_number {
        if state.stopped() {
            break;
        }
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("Failed to acquire subscribe permit")?;
        let client = match crate::client::Client::new(
            common.clone(),
            common.client_id_of(id),
            statistics.latency.clone(),
            Arc::clone(state),
        )
        .context(format!("Failed to create MQTT client client_{}", id))
        {
            Ok(client) => client,
            Err(e) => {
                error!("{}", e.to_string());
                break;
            }
        };
        let topic = sub_options.topic_of(id);
        let client_state = Arc::clone(state);
        let qos = common.qos;
        let _ = tokio::task::Builder::new()
            .name(&client.client_id())
            .spawn(async move {
                // Retry till client connected
                loop {
                    if client.connect().await.is_err() {
                        if client_state.stopped() {
                            break;
                        }
                        continue
                    }
                    break;
                }
                drop(permit);

                // Retry till client subscribed
                loop {
                    if client_state.stopped() {
                        break;
                    }
                    if client.subscribe(&topic, qos).await.is_err() {
                        sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    break;
                }

                let mut warning_count = 0;
                loop {
                    if client_state.stopped() {
                        break;
                    }

                    if client.connected() {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    if warning_count % 100 == 0 {
                        warn!("Client[client-id={}] is disconnected, awaiting reconnect", client.client_id());
                    }
                    warning_count += 1;
                }
            });
    }

    await_connection(common.total, state).await;
    await_running(common, state).await;

    if common.show_statistics {
        statistics.show_statistics();
    }
    Ok(())
}

pub async fn benchmark(
    common: &Common,
    state: &Arc<State>,
    statistics: &Statistics,
    pub_options: &PubOptions,
) -> Result<(), anyhow::Error> {
    let semaphore = Arc::new(Semaphore::new(common.concurrency));
    for id in common.start_number..common.total + common.start_number {
        if state.stopped() {
            break;
        }
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("Failed to acquire publish permit")?;
        let client = match crate::client::Client::new(
            common.clone(),
            common.client_id_of(id),
            statistics.latency.clone(),
            Arc::clone(state),
        )
        .context(format!("Failed to create MQTT client client_{}", id))
        {
            Ok(client) => client,
            Err(e) => {
                error!("{}", e.to_string());
                break;
            }
        };

        let payload = pub_options
            .payload
            .clone()
            .unwrap_or_else(|| "a".repeat(pub_options.message_size as usize));

        let topic = pub_options.topic_of(id);

        let pub_interval = Duration::from_millis(common.interval);
        let qos = common.qos;

        let client_state = Arc::clone(state);
        let _ = tokio::task::Builder::new()
            .name(&client.client_id())
            .spawn(async move {
                // Retry till client connected
                loop {
                    if let Err(e) = client.connect().await {
                        error!("{}", e.to_string());
                        if client_state.stopped() {
                            break;
                        }
                        continue
                    }
                    break;
                }
                drop(permit);

                // Retry till client subscribed
                loop {
                    if client_state.stopped() {
                        break;
                    }
                    if client.subscribe(&topic, qos).await.is_err() {
                        sleep(Duration::from_millis(10)).await; 
                        continue;
                    }
                    break;
                }
                
                let mut payload: Vec<u8> = payload.into();

                let mut warning_count = 0;
                loop {
                    if client_state.stopped() {
                        break;
                    }

                    if let Err(e) = tag_timestamp(&mut payload[..]) {
                        error!("{}", e.to_string());
                        break;
                    }

                    let message = MessageBuilder::new()
                        .topic(&topic)
                        .payload(&payload[..])
                        .qos(qos)
                        .finalize();

                    if client.connected() {
                        if let Err(_) = client.publish(message.clone()).await {
                            client_state.on_publish_failure();
                            break;
                        }

                        if pub_interval.as_millis() > 0 {
                            tokio::time::sleep(pub_interval).await;
                        }
                        continue;
                    }
                    
                    if warning_count % 100 == 0 {
                        warn!("Client[client-id={}] is disconnected, awaiting reconnect", client.client_id());                        
                    }
                    warning_count += 1;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
    }

    await_connection(common.total, state).await;
    await_running(common, state).await;

    if common.show_statistics {
        statistics.show_statistics();
    }
    Ok(())
}

async fn await_running(common: &Common, state: &Arc<State>) {
    for i in 0..common.time {
        if state.stopped() {
            break;
        }
        if i % 10 == 0 {
            debug!("Running {}s, {}s to go", i, common.time - i);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn tag_timestamp(data: &mut [u8]) -> anyhow::Result<()> {
    if data.len() < size_of::<u128>() {
        return Ok(());
    }

    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    let mut cursor = Cursor::new(data);
    cursor
        .write_u128::<byteorder::LittleEndian>(ts)
        .context("Failed to tag timestamp")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use byteorder::ReadBytesExt;

    #[test]
    fn test_tag_timestamp() -> anyhow::Result<()> {
        let mut data = [0u8; 32];
        super::tag_timestamp(&mut data)?;

        let mut cursor = Cursor::new(&data);
        let ts = cursor.read_u128::<byteorder::LittleEndian>()?;

        let current_ts = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_millis();
        assert!(current_ts - ts < 100);
        Ok(())
    }
}
