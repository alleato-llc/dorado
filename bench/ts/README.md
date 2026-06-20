# TypeScript throughput runner

Times the **pure-TypeScript** from-scratch primitives (the readable BigInt cipher)
and prints one JSON line per benchmark. See [`../README.md`](../README.md) for the
shared protocol and framing.

This measures the pure-TS code, **not** the WASM backend the Node CLI ships. The
WASM path is the Rust cipher compiled to WebAssembly and would be benchmarked
separately (as `wasm`) to show the WASM overhead; the browser runs that same WASM.

## Build and run

It runs with the TypeScript port's `tsx` (no build step), so the port's
`node_modules` must exist:

```
# one-time: install the TS port's dev deps
(cd ../../ts && npm install)
# run
../../ts/node_modules/.bin/tsx runner.ts [buffer_bytes] [warmup_seconds] [measure_seconds]
# defaults: 1048576 0.5 2.0
```

## How it works

It imports the pure-TS backend and primitives from `../../ts/src` and calls
`tsBackend.ctr(variant, key, tweak, iv, data)` (the pure-TS CTR), `skein.hash`, and
`blake3.hash`. `bench()` runs the peak-of-batches protocol and writes the JSON.

## Language notes

- Timing uses `performance.now()` (sub-millisecond) under Node via `tsx`.
- The warmup phase lets V8's JIT reach steady state before measuring.
- The cipher is ~3 MB/s: the 64-bit ARX uses `BigInt`, which is far slower than
  native math. BLAKE3 is ~20x faster (~60 MB/s) because its 32-bit words use ordinary
  JS numbers, not `BigInt`. That gap is exactly why the shipped Node CLI and the
  browser demo run the cipher through WASM instead of the pure-TS path.
