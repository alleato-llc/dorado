//! Rust throughput runner. Times the from-scratch primitives under the uniform
//! protocol (see ../README.md) and emits one JSON line per benchmark.

use std::time::{Duration, Instant};

use dorado::{blake3, skein, Threefish1024, Threefish256, Threefish512};

// Report peak throughput across many batches. The clock is read only at batch
// boundaries (robust to clock cost), and the maximum MB/s over the batches is the
// reproducible rate: scheduling jitter, frequency scaling, and contention only ever
// make a batch slower, never faster, so the fastest batch reflects the code running
// unimpeded. The batch size is grown until a batch takes >= 100ms.
fn bench(buf_bytes: usize, warmup: Duration, measure: Duration, mut op: impl FnMut()) -> (f64, u64) {
    let start = Instant::now();
    while start.elapsed() < warmup {
        op();
    }
    let mut batch: u64 = 1;
    loop {
        let s = Instant::now();
        for _ in 0..batch {
            op();
        }
        if s.elapsed() >= Duration::from_millis(100) {
            break;
        }
        batch = batch.saturating_mul(2);
    }
    let mut best = 0.0f64;
    let mut total: u64 = 0;
    let start = Instant::now();
    while start.elapsed() < measure {
        let s = Instant::now();
        for _ in 0..batch {
            op();
        }
        let mbps = (buf_bytes as f64) * (batch as f64) / 1e6 / s.elapsed().as_secs_f64();
        if mbps > best {
            best = mbps;
        }
        total += batch;
    }
    (best, total)
}

fn emit(bench: &str, mbps: f64, iters: u64) {
    println!(
        "{{\"impl\":\"rust\",\"bench\":\"{bench}\",\"mbps\":{mbps:.2},\"iters\":{iters}}}"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let buf_bytes: usize = args.get(1).map_or(1_048_576, |s| s.parse().unwrap());
    let warmup = Duration::from_secs_f64(args.get(2).map_or(0.5, |s| s.parse().unwrap()));
    let measure = Duration::from_secs_f64(args.get(3).map_or(2.0, |s| s.parse().unwrap()));

    let mut data = vec![0u8; buf_bytes];

    let c256 = Threefish256::new(&[7u8; 32], &[0u8; 16]);
    let iv256 = [1u8; 32];
    let (m, i) = bench(buf_bytes, warmup, measure, || c256.ctr_apply(&iv256, &mut data));
    emit("threefish-256-ctr", m, i);

    let c512 = Threefish512::new(&[7u8; 64], &[0u8; 16]);
    let iv512 = [1u8; 64];
    let (m, i) = bench(buf_bytes, warmup, measure, || c512.ctr_apply(&iv512, &mut data));
    emit("threefish-512-ctr", m, i);

    let c1024 = Threefish1024::new(&[7u8; 128], &[0u8; 16]);
    let iv1024 = [1u8; 128];
    let (m, i) = bench(buf_bytes, warmup, measure, || c1024.ctr_apply(&iv1024, &mut data));
    emit("threefish-1024-ctr", m, i);

    let mut out32 = [0u8; 32];
    let (m, i) = bench(buf_bytes, warmup, measure, || skein::hash_into(&mut out32, &data));
    emit("skein-512", m, i);

    let (m, i) = bench(buf_bytes, warmup, measure, || blake3::hash_into(&mut out32, &data));
    emit("blake3", m, i);
}
