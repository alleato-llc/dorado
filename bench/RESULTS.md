# Benchmark results

Throughput in MB/s (decimal). Measured on **Apple M4 Max** (Darwin arm64), 2026-08-03, commit `3e1abf5`. Buffer 65536 bytes; 0.5s warmup, 2.0s measured.

These are naive, from-scratch, **unoptimized** implementations. The numbers show language/runtime overhead on identical ARX code, not how fast cryptography can go (a tuned library with SIMD is far faster). Not a language speed contest. Each value is the **peak throughput** over many batches (the fastest batch is the reproducible rate, since scheduling jitter and frequency scaling only ever slow a batch). Regenerate with `python3 run.py`.

| Implementation | Threefish-256 CTR | Threefish-512 CTR | Threefish-1024 CTR | Skein-512 | BLAKE3 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rust | 77.4 | 113.9 | 135.3 | 113.0 | 1143.2 |
| C | 75.5 | 91.5 | 132.1 | 89.7 | 1146.5 |
| C++ | 68.5 | 81.3 | 112.8 | 78.7 | 1155.6 |
| Zig | 73.2 | 103.5 | 148.6 | 103.1 | 1118.6 |
| Go | 76.3 | 88.0 | 86.1 | 79.9 | 348.2 |
| Java | 63.1 | 81.9 | 92.5 | 81.4 | 456.9 |
| Haskell | 7.7 | 8.3 | 8.0 | 8.5 | 35.4 |
| Python | 0.6 | 0.6 | 0.6 | 0.6 | 1.3 |
| TypeScript (pure) | 3.1 | 3.2 | 3.0 | 3.1 | 60.2 |
