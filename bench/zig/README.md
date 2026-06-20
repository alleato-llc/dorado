# Zig throughput runner

Times the Zig port's from-scratch primitives and prints one JSON line per benchmark.
See [`../README.md`](../README.md) for the shared protocol and framing.

## Build and run

```
zig build
./zig-out/bin/dorado-bench [buffer_bytes] [warmup_seconds] [measure_seconds]
# defaults: 1048576 0.5 2.0
```

## How it works

`build.zig` adds the Zig port's library as the `dorado` module (rooted at
`../../zig/src/root.zig`) and builds `main.zig` against it. The runner calls
`dorado.threefish.Threefish.init(.t256/.t512/.t1024, key, tweak).newCtr(iv).apply(data)`
for the cipher and `dorado.skein.hash` / `dorado.blake3.hash` for the hashes. A
generic `bench()` runs the warmup-then-measure loop and prints the JSON.

## Language notes

- Built `ReleaseFast` (overridden in this `build.zig`), so the throughput number is
  apples-to-apples with the Rust release and C `-O2` runners. Note this differs from
  the shipped Zig CLI, which defaults to `ReleaseSafe` (safety checks kept); that
  safety overhead is a separate concern from raw throughput.
- Zig 0.16 moved clocks into the `Io` interface, so timing reads
  `std.Io.Clock.now(.awake, io)` (the monotonic clock) via the `io` handed to
  `main(init: std.process.Init)`; there is no `std.time.Timer`.

### Known anomaly

Threefish-512 (and therefore Skein-512, which is built on it) currently measures
several times slower than Threefish-256/1024 in this runner, while C and Rust show
512 in line with the other sizes. The cause is in how `ReleaseFast` compiles the
`nw = 8` path; it is a real, reproducible finding from this benchmark and is being
investigated separately. The numbers here report it honestly rather than hiding it.
