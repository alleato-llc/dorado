# Go throughput runner

Times the Go port's from-scratch primitives and prints one JSON line per benchmark.
See [`../README.md`](../README.md) for the shared protocol and framing.

## Build and run

```
go build -o dorado-bench .
./dorado-bench [buffer_bytes] [warmup_seconds] [measure_seconds]
# defaults: 1048576 0.5 2.0
```

## How it works

This directory is its own Go module (`go.mod`) with a `replace` directive pointing
at the Go port (`../../go`), so it imports the port's packages directly:

- `threefish.New256/512/1024(key, tweak)` wrapped in `cipher.NewCTR(block, iv)` for
  the cipher (the standard library `crypto/cipher` CTR, exactly as the engine uses
  it),
- `skein.Hash(32, data)` and `blake3.Hash(out, data)` for the hashes.

`bench()` runs the peak-of-batches protocol and prints the JSON.

## Language notes

- Built with the default Go compiler optimization (Go has no `-O` levels).
- Timing uses `time.Now()` / `time.Since` (monotonic).
- The BLAKE3 number is markedly lower than Rust/C here; Go's bounds checking on the
  hot compression loop is the likely cause (a real, measured difference, not a
  benchmark artifact).
