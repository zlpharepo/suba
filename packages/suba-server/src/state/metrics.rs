//! What the machine this instance runs on is doing, sampled when asked.
//!
//! CPU usage and network throughput are rates, so they need two samples. The
//! previous sample is kept here and each request is measured against it; the
//! first request after start has nothing to compare with and answers no rate
//! rather than an invented zero.

use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;
use sysinfo::{Disks, Networks, System};

/// The machine, as one request sees it.
#[derive(Debug, Serialize)]
pub struct Metrics {
    pub host: Host,
    pub cpu: Cpu,
    pub memory: Memory,
    pub disk: Option<Disk>,
    pub network: Network,
}

#[derive(Debug, Serialize)]
pub struct Host {
    pub name: Option<String>,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub arch: String,
    /// Seconds since the machine booted.
    pub uptime: u64,
}

#[derive(Debug, Serialize)]
pub struct Cpu {
    pub cores: usize,
    /// Percent of all cores, since the previous request; absent on the first.
    pub usage: Option<f32>,
    /// One, five and fifteen minutes; all zero on systems that do not keep one.
    pub load: [f64; 3],
}

#[derive(Debug, Serialize)]
pub struct Memory {
    pub total: u64,
    pub used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
}

/// The disk the data directory lives on.
#[derive(Debug, Serialize)]
pub struct Disk {
    pub total: u64,
    pub available: u64,
}

#[derive(Debug, Serialize)]
pub struct Network {
    /// Bytes since boot, every interface but loopback.
    pub received: u64,
    pub transmitted: u64,
    /// Bytes per second since the previous request; absent on the first.
    pub receive_rate: Option<f64>,
    pub transmit_rate: Option<f64>,
}

struct Sampler {
    system: System,
    networks: Networks,
    disks: Disks,
    /// When the previous sample was taken, which makes the counters a rate.
    previous: Option<Instant>,
}

/// The sampler behind a lock: two requests at once must not both reset the
/// baseline the other is measuring against.
pub(crate) struct MetricsStore {
    sampler: Mutex<Sampler>,
    data_dir: std::path::PathBuf,
}

impl MetricsStore {
    pub(crate) fn new(data_dir: &std::path::Path) -> Self {
        Self {
            sampler: Mutex::new(Sampler {
                system: System::new(),
                networks: Networks::new_with_refreshed_list(),
                disks: Disks::new_with_refreshed_list(),
                previous: None,
            }),
            data_dir: data_dir.to_path_buf(),
        }
    }

    /// Sample now. Blocking: reads `/proc`, `sysctl` and friends.
    pub(crate) fn sample(&self) -> Metrics {
        let mut sampler = self
            .sampler
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let elapsed = sampler
            .previous
            .map(|previous| now.duration_since(previous).as_secs_f64())
            .filter(|seconds| *seconds > 0.0);

        sampler.system.refresh_cpu_usage();
        sampler.system.refresh_memory();
        sampler.networks.refresh(true);
        sampler.disks.refresh(true);

        let (mut received, mut transmitted, mut delta_in, mut delta_out) = (0, 0, 0, 0);
        for (name, data) in sampler.networks.list() {
            if is_loopback(name) {
                continue;
            }
            received += data.total_received();
            transmitted += data.total_transmitted();
            delta_in += data.received();
            delta_out += data.transmitted();
        }

        let load = System::load_average();
        let metrics = Metrics {
            host: Host {
                name: System::host_name(),
                os: System::long_os_version(),
                kernel: System::kernel_version(),
                arch: System::cpu_arch(),
                uptime: System::uptime(),
            },
            cpu: Cpu {
                cores: sampler.system.cpus().len(),
                usage: elapsed.map(|_| sampler.system.global_cpu_usage()),
                load: [load.one, load.five, load.fifteen],
            },
            memory: Memory {
                total: sampler.system.total_memory(),
                used: sampler.system.used_memory(),
                swap_total: sampler.system.total_swap(),
                swap_used: sampler.system.used_swap(),
            },
            disk: disk_of(&sampler.disks, &self.data_dir),
            network: Network {
                received,
                transmitted,
                receive_rate: elapsed.map(|seconds| delta_in as f64 / seconds),
                transmit_rate: elapsed.map(|seconds| delta_out as f64 / seconds),
            },
        };

        sampler.previous = Some(now);

        metrics
    }
}

fn is_loopback(name: &str) -> bool {
    name == "lo" || name == "lo0"
}

/// The disk whose mount point is the longest prefix of the data directory.
fn disk_of(disks: &Disks, data_dir: &std::path::Path) -> Option<Disk> {
    let data_dir = data_dir
        .canonicalize()
        .unwrap_or_else(|_| data_dir.to_path_buf());

    disks
        .iter()
        .filter(|disk| data_dir.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(|disk| Disk {
            total: disk.total_space(),
            available: disk.available_space(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rate needs two samples: the first answers none rather than a zero that
    /// would read as an idle machine.
    #[test]
    fn rates_appear_from_the_second_sample() {
        let store = MetricsStore::new(&std::env::temp_dir());

        let first = store.sample();
        assert_eq!(first.cpu.usage, None);
        assert_eq!(first.network.receive_rate, None);

        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        let second = store.sample();
        assert!(second.cpu.usage.is_some());
        assert!(second.network.receive_rate.is_some());
        assert!(second.memory.total > 0);
        assert!(second.cpu.cores > 0);
    }

    #[test]
    fn loopback_is_left_out_of_the_totals() {
        assert!(is_loopback("lo"));
        assert!(is_loopback("lo0"));
        assert!(!is_loopback("eth0"));
        assert!(!is_loopback("en0"));
    }
}
