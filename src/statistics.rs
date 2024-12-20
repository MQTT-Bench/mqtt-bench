use log::info;
use prometheus::{
    labels, linear_buckets, proto::MetricType, Encoder, Histogram, HistogramOpts, Registry,
    TextEncoder,
};

#[derive(Debug, Clone)]
pub struct LatencyHistogram {
    pub connect: Histogram,
    pub publish: Histogram,
    pub subscribe: Histogram,
}

pub struct Statistics {
    pub registry: Registry,
    pub latency: LatencyHistogram,
}

impl Statistics {
    pub fn new() -> Self {
        let r = Registry::new();
        let conn_histogram_opts = HistogramOpts::new("conn_histogram", "Connect Latency Histogram")
            .buckets(linear_buckets(0.0, 1.0, 100).unwrap())
            .const_labels(labels! {"type".to_string() => "connect".to_string(), "unit".to_string() => "ms".to_string()});
        let connect = Histogram::with_opts(conn_histogram_opts).unwrap();
        r.register(Box::new(connect.clone())).unwrap();

        let pub_histogram_opts =
            HistogramOpts::new("pub_histogram", "Publish MQTT Message Latency")
                .buckets(linear_buckets(0.0, 10.0, 20).unwrap())
                .const_labels(labels! {"type".to_string() => "publish".to_string(), "unit".to_string() => "ms".to_string()});
        let publish = Histogram::with_opts(pub_histogram_opts).unwrap();
        r.register(Box::new(publish.clone())).unwrap();

        let sub_histogram_opts =
            HistogramOpts::new("sub_histogram", "E2E MQTT Message Delivery Latency")
                .buckets(linear_buckets(0.0, 10.0, 20).unwrap())
                .const_labels(labels! {"type".to_string() => "subscribe".to_string(), "unit".to_string() => "ms".to_string()});
        let subscribe = Histogram::with_opts(sub_histogram_opts).unwrap();
        r.register(Box::new(subscribe.clone())).unwrap();

        let latency_histogram = LatencyHistogram {
            connect,
            publish,
            subscribe,
        };

        Self {
            registry: r,
            latency: latency_histogram,
        }
    }

    pub fn show_statistics(&self) {
        let metric_families = self.registry.gather();
        for family in metric_families.iter() {
            let metric_type = family.get_field_type();
            for metric in family.get_metric() {
                if MetricType::HISTOGRAM != metric_type {
                    continue;
                }
                let histogram = metric.get_histogram();

                let mut p90 = 0.0;
                let mut p95 = 0.0;
                let mut p99 = 0.0;

                let mut percentiles = [false; 3];
                let mut result = [0.0; 3];

                let buckets = histogram.get_bucket();
                if let Some(bucket) = buckets.last() {
                    if 0 == bucket.get_cumulative_count() {
                        continue;
                    }
                    p90 = bucket.get_cumulative_count() as f64 * 0.9;
                    p95 = bucket.get_cumulative_count() as f64 * 0.95;
                    p99 = bucket.get_cumulative_count() as f64 * 0.99;
                }

                for bucket in buckets {
                    let upper_bound = bucket.get_upper_bound();
                    let cumulative_count = bucket.get_cumulative_count();
                    if !percentiles[0] && cumulative_count >= p90 as u64 {
                        result[0] = upper_bound;
                        percentiles[0] = true;
                    }

                    if !percentiles[1] && cumulative_count >= p95 as u64 {
                        result[1] = upper_bound;
                        percentiles[1] = true;
                    }

                    if !percentiles[2] && cumulative_count >= p99 as u64 {
                        result[2] = upper_bound;
                        break;
                    }
                }

                info!(
                    "{} P90: {}ms, P95: {}ms, P99: {}ms",
                    family.get_help(),
                    result[0],
                    result[1],
                    result[2]
                );
            }
        }

        for family in metric_families.iter() {
            if family.get_field_type() == MetricType::HISTOGRAM {
                continue;
            }

            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            encoder
                .encode(std::slice::from_ref(family), &mut buffer)
                .unwrap();
            info!("{}", String::from_utf8(buffer).unwrap());
        }
    }
}

impl Default for Statistics {
    fn default() -> Self {
        Self::new()
    }
}
