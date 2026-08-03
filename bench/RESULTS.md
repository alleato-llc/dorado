# Benchmark results

Throughput in MB/s (decimal). Measured on **Apple M4 Max** (Darwin arm64), 2026-08-02, commit `38a0d6c`. Buffer 65536 bytes; 0.5s warmup, 2.0s measured.

These are naive, from-scratch, **unoptimized** implementations. The numbers show language/runtime overhead on identical ARX code, not how fast cryptography can go (a tuned library with SIMD is far faster). Not a language speed contest. Each value is the **peak throughput** over many batches (the fastest batch is the reproducible rate, since scheduling jitter and frequency scaling only ever slow a batch). Regenerate with `python3 run.py`.

| Implementation | Threefish-256 CTR | Threefish-512 CTR | Threefish-1024 CTR | Skein-512 | BLAKE3 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rust | 80.9 | 118.5 | 138.8 | 116.8 | 1217.3 |
| C | 79.6 | 96.0 | 135.3 | 94.5 | 1199.0 |
| C++ | 71.2 | 84.9 | 119.6 | 80.2 | 1199.8 |
| Zig | 75.7 | 105.5 | 68.2 | 106.4 | 1146.2 |
| Go | 77.4 | 90.5 | 87.5 | 84.5 | 352.0 |
| Java | 65.1 | 83.6 | 93.8 | 77.1 | 472.4 |
| Haskell | 7.9 | 8.4 | 8.2 | 8.6 | 37.0 |
| Python | 0.6 | 0.7 | 0.7 | 0.7 | 1.4 |
| TypeScript (pure) | 3.2 | 3.3 | 3.0 | 3.1 | 63.6 |
