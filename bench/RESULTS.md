# Benchmark results

Throughput in MB/s (decimal). Measured on **Apple M4 Max** (Darwin arm64), 2026-06-20, commit `559b449`. Buffer 65536 bytes; 0.5s warmup, 2.0s measured.

These are naive, from-scratch, **unoptimized** implementations. The numbers show language/runtime overhead on identical ARX code, not how fast cryptography can go (a tuned library with SIMD is far faster). Not a language speed contest. Each value is the **peak throughput** over many batches (the fastest batch is the reproducible rate, since scheduling jitter and frequency scaling only ever slow a batch). Regenerate with `python3 run.py`.

| Implementation | Threefish-256 CTR | Threefish-512 CTR | Threefish-1024 CTR | Skein-512 | BLAKE3 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rust | 84.3 | 117.2 | 136.4 | 115.1 | 1185.0 |
| C | 79.9 | 92.2 | 131.7 | 90.7 | 1186.9 |
| Zig | 75.4 | 24.1 | 52.2 | 24.2 | 1174.0 |
| Go | 77.9 | 90.5 | 88.0 | 83.8 | 354.4 |
| Java | 64.1 | 83.2 | 96.3 | 83.1 | 467.0 |
| Python | 0.6 | 0.7 | 0.7 | 0.7 | 1.3 |
| TypeScript (pure) | 3.2 | 3.3 | 3.1 | 3.1 | 63.0 |
