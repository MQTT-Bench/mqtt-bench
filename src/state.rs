use log::info;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

pub struct State {
    /// Number of CONNECT attempts
    attempted: AtomicUsize,
    /// Number of successful CONNECT
    connected: AtomicUsize,
    /// Number of failing CONNECT
    disconnected: AtomicUsize,
    stopped: AtomicBool,
    published: AtomicUsize,
    pub_failures: AtomicUsize,
    published_total: AtomicUsize,
    received: AtomicUsize,
    received_total: AtomicUsize,
}

impl State {
    pub fn new(total: usize) -> Arc<State> {
        let state = Self {
            attempted: AtomicUsize::new(0),
            connected: AtomicUsize::new(0),
            disconnected: AtomicUsize::new(total),
            stopped: AtomicBool::new(false),
            published: AtomicUsize::new(0),
            pub_failures: AtomicUsize::new(0),
            published_total: AtomicUsize::new(0),
            received: AtomicUsize::new(0),
            received_total: AtomicUsize::new(0),
        };
        Arc::new(state)
    }

    pub fn connected(&self) -> usize {
        self.connected.load(Ordering::Relaxed)
    }

    pub fn disconnected(&self) -> usize {
        self.disconnected.load(Ordering::Relaxed)
    }

    pub fn attempted(&self) -> usize {
        self.attempted.load(Ordering::Relaxed)
    }

    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    pub fn on_connected(&self) {
        self.attempted.fetch_add(1, Ordering::Relaxed);
        self.connected.fetch_add(1, Ordering::Relaxed);
        self.disconnected.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn on_disconnected(&self) {
        self.attempted.fetch_add(1, Ordering::Relaxed);
        self.disconnected.fetch_add(1, Ordering::Relaxed);
        self.connected.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn on_publish(&self) {
        self.published.fetch_add(1, Ordering::Relaxed);
        self.published_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn publish_success_count(&self) -> usize {
        let count = self.published.load(Ordering::Relaxed);
        if count > 0 {
            self.published.fetch_sub(count, Ordering::Relaxed);
        }
        count
    }

    pub fn on_publish_failure(&self) {
        self.pub_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn publish_failure_count(&self) -> usize {
        let count = self.pub_failures.load(Ordering::Relaxed);
        if count > 0 {
            self.pub_failures.fetch_sub(count, Ordering::Relaxed);
        }
        count
    }

    pub fn on_receive(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
        self.received_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn received(&self) -> usize {
        let rcv = self.received.load(Ordering::Relaxed);
        if rcv > 0 {
            self.received.fetch_sub(rcv, Ordering::Relaxed);
        }
        rcv
    }

    pub fn stop_flag(&self) -> &AtomicBool {
        &self.stopped
    }
}

pub fn ctrl_c(state: Arc<State>) {
    let _ = tokio::task::Builder::new()
        .name("ctrl_c")
        .spawn(async move {
            if let Ok(()) = tokio::signal::ctrl_c().await {
                info!("Ctrl-C received, stopping");
                state.stop_flag().store(true, Ordering::Relaxed);
            }
        });
}

pub fn print_stats(state: Arc<State>) {
    let _ = tokio::task::Builder::new().name("stats_printer").spawn({
        async move {
            loop {
                tokio::select! {
                    _ = sleep(Duration::from_secs(1)) => {
                        info!("Client Summary[Attempted:{}, Connected: {}, Disconnected: {}] Publish: [Success: {}, Failure: {}], Subscribed: {}", 
                            state.attempted(), state.connected(), state.disconnected(),
                            state.publish_success_count(), state.publish_failure_count(), state.received());
                        if state.stopped() {
                            break;
                        }
                    }
                }
            }
        }
    });
}
