# Rust throughput runner

Times the Rust port's from-scratch primitives and prints one JSON line per
benchmark. See [`../README.md`](../README.md) for the shared protocol and the honest
framing (these are naive, unoptimized implementations).

## Build and run

```
cargo build --release
./target/release/dorado-bench [buffer_bytes] [warmup_seconds] [measure_seconds]
# defaults: 1048576 0.5 2.0
```

## How it works

It path-depends the `dorado` crate (`../../rust/crates/dorado`) and calls its public
API directly:

- `Threefish256/512/1024::new(key, tweak).ctr_apply(iv, &mut data)` for the cipher,
- `skein::hash_into(&mut out, &data)` and `blake3::hash_into(&mut out, &data)` for
  the hashes.

A generic `bench()` helper runs a closure in a loop (warm up to `warmup_seconds`,
then measure to `measure_seconds`, counting iterations) and reports
`buffer_bytes * iters / 1e6 / elapsed` as MB/s. `emit()` prints the JSON line.

## Language notes

- Built `--release` with LTO and a single codegen unit (`Cargo.toml`), so the
  numbers reflect the optimized cipher, comparable to the C `-O2` and Zig
  `ReleaseFast` runners.
- Timing uses `std::time::Instant` (monotonic). No warmup is strictly needed for an
  AOT-compiled language, but the uniform protocol runs it anyway for fairness with
  the JIT/VM ports.
- The cipher is re-created each iteration (`new(...)` then `ctr_apply`), matching the
  other runners; with a 1 MiB buffer the key-schedule setup is negligible against
  the per-byte work.
