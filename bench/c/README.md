# C throughput runner

Times the C port's from-scratch primitives and prints one JSON line per benchmark.
See [`../README.md`](../README.md) for the shared protocol and framing.

## Build and run

```
cc -std=c17 -O2 -I../../c/include main.c \
   ../../c/src/threefish.c ../../c/src/skein.c ../../c/src/blake3.c -o dorado-bench
./dorado-bench [buffer_bytes] [warmup_seconds] [measure_seconds]
# defaults: 1048576 0.5 2.0
```

## How it works

It includes the C port's primitive headers (`dorado/threefish.h`, `skein.h`,
`blake3.h`) and is compiled **directly against the three primitive source files** in
`../../c/src`. It deliberately does not link `libdorado.a` or the engine, so it needs
neither `libargon2` nor OpenSSL.

`run_op()` dispatches to one primitive; `bench()` runs it in a warmup-then-measure
loop and prints `buffer_bytes * iters / 1e6 / elapsed` MB/s as JSON.

## Language notes

- Compiled `-O2` for an optimized comparison with the Rust release and Zig
  `ReleaseFast` runners.
- Timing uses `clock_gettime(CLOCK_MONOTONIC)`.
- Because it pulls in only the primitive translation units (which are
  allocation-free and OS-free, see `make freestanding` in the C port), the runner is
  self-contained and has no third-party dependencies.
