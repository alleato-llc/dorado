# Benchmark results

Throughput in MB/s (decimal). Measured on **Apple M4 Max** (Darwin arm64), 2026-06-20, commit `6be147c`. Buffer 65536 bytes; 0.5s warmup, 2.0s measured.

These are naive, from-scratch, **unoptimized** implementations. The numbers show language/runtime overhead on identical ARX code, not how fast cryptography can go (a tuned library with SIMD is far faster). Not a language speed contest. Each value is the **peak throughput** over many batches (the fastest batch is the reproducible rate, since scheduling jitter and frequency scaling only ever slow a batch). Regenerate with `./run.sh`.

| Implementation | Threefish-256 CTR | Threefish-512 CTR | Threefish-1024 CTR | Skein-512 | BLAKE3 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rust | 80.9 | 116.7 | 134.5 | 115.5 | 1197.5 |
| C | 78.8 | 95.7 | 136.9 | 94.9 | 1188.6 |
| Zig | 76.8 | 24.6 | 53.5 | 24.4 | 1172.0 |
| Go | 77.8 | 90.5 | 88.1 | 85.3 | 352.7 |
| Java | 61.9 | 81.3 | 90.7 | 81.0 | 468.9 |
| Python | 0.6 | 0.7 | 0.7 | 0.6 | 1.4 |
| TypeScript (pure) | 3.2 | 3.3 | 3.1 | 3.1 | 62.0 |
