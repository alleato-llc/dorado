# C++ throughput runner

Times the C++ port's from-scratch primitives and prints one JSON line per benchmark.
See [`../README.md`](../README.md) for the shared protocol and framing.

## Build and run

```
c++ -std=c++23 -O2 -I../../cpp/include main.cpp \
    ../../cpp/src/threefish.cpp ../../cpp/src/skein.cpp ../../cpp/src/blake3.cpp \
    -o dorado-bench
./dorado-bench [buffer_bytes] [warmup_seconds] [measure_seconds]
# defaults: 1048576 0.5 2.0
```

## How it works

It includes the C++ port's primitive headers (`dorado/threefish.hpp`, `skein.hpp`,
`blake3.hpp`) and is compiled **directly against the three primitive translation
units** in `../../cpp/src`. Like the C runner it deliberately avoids the engine, so it
needs neither libargon2 nor OpenSSL — the CMake build is not involved.

`run_op()` dispatches to one primitive; `bench()` runs it in a warmup-then-measure loop
and prints `buffer_bytes * iters / 1e6 / elapsed` MB/s as JSON.

## Language notes

- Compiled `-O2` at C++23 (the standard the port's `CMakeLists.txt` sets), for an
  optimized comparison with the C, Rust release, and Zig `ReleaseFast` runners.
- Timing uses `std::chrono::steady_clock`, which is monotonic.
- The CTR path constructs a `dorado::Threefish` per call, matching the C runner's
  re-key-per-op shape so the two measure the same work.
- The hash benchmarks xor one output byte back into the buffer. `dorado::skein::hash`
  and `dorado::blake3::hash` return a `std::vector`, and without a sink an optimizer is
  free to drop a result nothing reads.
