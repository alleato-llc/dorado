# Benchmarks

Cross-language throughput benchmarks for the from-scratch primitives, plus an
end-to-end reality check. The point of these is an honest, *comparable* picture:
how fast each implementation's own cipher and hash code runs, and how little that
matters next to the KDF in a real password operation.

These are educational, unoptimized implementations. The numbers show
**language/runtime overhead on identical naive ARX code**, not how fast
cryptography can go (a tuned library with SIMD is far faster). Do not read them as a
language speed contest.

## Two sections

- **Throughput** (`run.sh`): a uniform micro-benchmark of each port's *own* code:
  Threefish-256/512/1024 in CTR mode, Skein-512, and BLAKE3, in MB/s. This is the
  comparable part. It deliberately does not touch the KDFs (those are delegated
  libraries, not our code) and isolates the primitive from process startup and I/O.
- **End-to-end** (`endtoend.sh`): the real `dorado` CLI timed with `hyperfine`.
  This includes process startup + the KDF + the cipher + I/O, i.e. what a user
  actually waits for. It covers only the ports that ship a CLI, and its differences
  are dominated by runtime startup and the KDF library, *not* the implementation, so
  it is a reality check, not a per-language race.

## The uniform protocol (Throughput)

Every runner is native to its language (you cannot time Zig's cipher without Zig
code), but they all follow one recipe so the numbers are comparable. Each runner
takes the same three arguments from the orchestrator:

```
runner <buffer_bytes> <warmup_seconds> <measure_seconds>
```

and for each benchmark:

1. fills a `buffer_bytes` buffer once,
2. warms up by running the operation in a loop until `warmup_seconds` have elapsed
   (this lets JIT/VM runtimes reach steady state, so Java and pure-TS are measured
   fairly),
3. then runs the operation in a loop until `measure_seconds` have elapsed, counting
   iterations,
4. reports `MB/s = buffer_bytes * iterations / 1e6 / elapsed_seconds`.

MB is decimal (1e6 bytes); the buffer is 1 MiB (1048576 bytes) by default. Each
runner emits one JSON line per benchmark:

```json
{"impl":"rust","bench":"threefish-256-ctr","mbps":412.7,"iters":820}
```

The runner emits **only** these stats. Rounding, framing, and caveats are applied
later, in the report and on the website, never in the measurement.

## Runners

Each runner is a small program native to its language (it cannot time another
language's code) that follows the protocol above. The timing scaffolding and the
JSON output are the same everywhere; only the calls into that port's primitives
differ. Each directory has its own README with build and run details.

| Runner | Language | Build / run | Notes |
| --- | --- | --- | --- |
| [`rust/`](rust/README.md) | Rust | `cargo build --release` then `./target/release/dorado-bench` | release + LTO; path-deps the `dorado` crate |
| [`c/`](c/README.md) | C | `cc -O2 -I../../c/include main.c ../../c/src/{threefish,skein,blake3}.c -o dorado-bench` | links only the primitive sources (no engine, no OpenSSL) |
| [`zig/`](zig/README.md) | Zig | `zig build` then `./zig-out/bin/dorado-bench` | `ReleaseFast`; imports the `dorado` module |

Each runner takes `<buffer_bytes> <warmup_seconds> <measure_seconds>` (defaults
`1048576 0.5 2.0`) and prints one JSON line per benchmark to stdout.

Planned: Go, Python, Java, and the pure-TypeScript cipher runners, then an
orchestrator (`run.sh`) that builds and invokes them all with identical arguments,
collects the JSON into `results.json` (with machine spec, date, and git commit),
and generates `RESULTS.md`. An `endtoend.sh` will drive the real CLIs through
`hyperfine` for the end-to-end section. A reference-library runner (an optimized
crate such as RustCrypto) is also planned, to show the naive-vs-tuned gap.

`results.json` will be a committed snapshot from one stated machine. It is not
produced by CI, whose hardware varies; to refresh it, run the orchestrator on a
chosen machine and commit the result.

## What is and isn't covered

- Throughput covers all distinct implementations: the six native ports plus the
  pure-TypeScript cipher (BigInt). The WASM backend used by the Node CLI and the
  browser is the Rust cipher compiled to WebAssembly; it is measured separately as
  `wasm` to show the WASM overhead, and the browser runs that same code.
- The KDFs are never benchmarked here: they are the same delegated libraries across
  ports, and Argon2id/scrypt are intentionally slow, so a single reference cost is
  noted in the end-to-end section instead of a per-language column.
