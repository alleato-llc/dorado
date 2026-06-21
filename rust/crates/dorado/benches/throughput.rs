//! Throughput benchmarks for the cipher and the from-scratch hashes.
//!
//! Run with `cargo bench -p dorado`. criterion saves each run and reports the
//! change against the previous one, so this also serves as a regression guard.
//! These produce *measured* numbers on the machine that runs them; do not quote
//! them as universal figures.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use dorado::{Threefish1024, Threefish256, Threefish512};

/// Encrypt a single block, per variant.
fn block_encrypt(c: &mut Criterion) {
    let mut g = c.benchmark_group("threefish_block_encrypt");

    let t256 = Threefish256::new(&[0x11; 32], &[0x22; 16]);
    g.bench_function("256", |b| {
        let mut blk = [0u8; 32];
        b.iter(|| t256.encrypt_block(black_box(&mut blk)));
    });

    let t512 = Threefish512::new(&[0x11; 64], &[0x22; 16]);
    g.bench_function("512", |b| {
        let mut blk = [0u8; 64];
        b.iter(|| t512.encrypt_block(black_box(&mut blk)));
    });

    let t1024 = Threefish1024::new(&[0x11; 128], &[0x22; 16]);
    g.bench_function("1024", |b| {
        let mut blk = [0u8; 128];
        b.iter(|| t1024.encrypt_block(black_box(&mut blk)));
    });

    g.finish();
}

/// Stream throughput over a 64 KiB buffer (Threefish-CTR per variant). The
/// group reports bytes/second.
fn stream_throughput(c: &mut Criterion) {
    const LEN: usize = 64 * 1024;
    let mut g = c.benchmark_group("stream_throughput");
    g.throughput(Throughput::Bytes(LEN as u64));

    let t256 = Threefish256::new(&[0x11; 32], &[0x22; 16]);
    let iv256 = [0u8; 32];
    g.bench_function("threefish256_ctr", |b| {
        let mut d = vec![0u8; LEN];
        b.iter(|| t256.ctr_apply(&iv256, black_box(&mut d)));
    });

    let t512 = Threefish512::new(&[0x11; 64], &[0x22; 16]);
    let iv512 = [0u8; 64];
    g.bench_function("threefish512_ctr", |b| {
        let mut d = vec![0u8; LEN];
        b.iter(|| t512.ctr_apply(&iv512, black_box(&mut d)));
    });

    let t1024 = Threefish1024::new(&[0x11; 128], &[0x22; 16]);
    let iv1024 = [0u8; 128];
    g.bench_function("threefish1024_ctr", |b| {
        let mut d = vec![0u8; LEN];
        b.iter(|| t1024.ctr_apply(&iv1024, black_box(&mut d)));
    });

    g.finish();
}

/// Hash throughput over a 64 KiB buffer (Skein-512 and BLAKE3, 32-byte output).
fn hash_throughput(c: &mut Criterion) {
    const LEN: usize = 64 * 1024;
    let data = vec![0xa5u8; LEN];
    let mut g = c.benchmark_group("hash_throughput");
    g.throughput(Throughput::Bytes(LEN as u64));

    g.bench_function("skein512", |b| {
        b.iter(|| dorado::skein::hash(32, black_box(&data)))
    });
    g.bench_function("blake3", |b| {
        b.iter(|| dorado::blake3::hash(32, black_box(&data)))
    });

    g.finish();
}

criterion_group!(benches, block_encrypt, stream_throughput, hash_throughput);
criterion_main!(benches);
