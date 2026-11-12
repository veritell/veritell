//! Measurements: `cargo run --release -p veritell-agg --example measure`.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use veritell_agg::{Aggregates, Config, Observation};

const T0: u64 = 1_700_000_000;

fn net(n: u32) -> IpAddr {
    let n = n + 0x0100_0000;
    IpAddr::V4(Ipv4Addr::new((n >> 16) as u8, (n >> 8) as u8, n as u8, 9))
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn main() {
    let default = Aggregates::new(Config::default()).unwrap();
    println!("memory_bound_bytes (default) = {} ({:.1} MiB)", default.memory_bound_bytes(), default.memory_bound_bytes() as f64 / 1048576.0);

    // Speed: 20,000 fingerprints x 20,000 networks, random traffic, time advancing.
    let a = Aggregates::new(Config { warmup_secs: 0, ..Config::default() }).unwrap();
    let fps: Vec<String> = (0..20_000).map(|i| format!("fp-{i:05}-0123456789abcdef0123456789abcdef")).collect();
    let mut rng = Rng(1);
    let run = |a: &Aggregates, n: u64, base: u64, rng: &mut Rng, rotate: bool| {
        let t = Instant::now();
        let mut hits = 0usize;
        for i in 0..n {
            let r = rng.next();
            let fp = if rotate { &fps[0] } else { &fps[(r % 20_000) as usize] };
            let ip = if rotate { net((i % 20_000) as u32) } else { net(((r >> 20) % 20_000) as u32) };
            hits += a
                .observe(&Observation { fingerprint: fp, ip, client: [(r >> 8) as u8; 16], route: if r & 3 == 0 { "/" } else { "/api" } }, base + i / 5_000)
                .len();
        }
        (t.elapsed().as_nanos() as f64 / n as f64, hits)
    };
    run(&a, 1_000_000, T0, &mut rng, false); // fill the tables
    let (ns, hits) = run(&a, 2_000_000, T0 + 200, &mut rng, false);
    println!("observe, random 20k fp x 20k nets (tracked {}): {ns:.0} ns avg ({hits} detections)", a.tracked());
    let b = Aggregates::new(Config { warmup_secs: 0, ..Config::default() }).unwrap();
    let (ns, hits) = run(&b, 1_000_000, T0, &mut rng, true);
    println!("observe, one fingerprint rotating 20k networks (worst case): {ns:.0} ns avg ({hits} detections)");

    // Accuracy over random hash keys.
    for n in [100u32, 1_000, 20_000] {
        let mut worst = 0.0f64;
        let mut worst_abs = 0u64;
        for trial in 0..200u64 {
            let mut seed = [0u8; 16];
            seed[..8].copy_from_slice(&Rng(trial * 7919 + 13).next().to_le_bytes());
            seed[8..].copy_from_slice(&Rng(trial + 99).next().to_le_bytes());
            let a = Aggregates::new(Config { warmup_secs: 0, max_keys: 100, hash_seed: Some(seed), ..Config::default() }).unwrap();
            for i in 0..n {
                a.observe(&Observation { fingerprint: "fp", ip: net(i), client: [0; 16], route: "/" }, T0 + u64::from(i % 3) * 10);
            }
            let got = a.networks("fp", T0 + 25);
            worst = worst.max(got.abs_diff(u64::from(n)) as f64 / f64::from(n));
            worst_abs = worst_abs.max(got.abs_diff(u64::from(n)));
        }
        println!("n = {n}: worst relative error over 200 random keys = {:.1}% (abs {worst_abs})", worst * 100.0);
    }
}
