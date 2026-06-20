# Benchmarks

Cross-language throughput benchmarks for the from-scratch primitives, plus an
end-to-end reality check. The point of these is an honest, *comparable* picture:
how fast each implementation's own cipher and hash code runs, and how little that
matters next to the KDF in a real password operation.

These are educational, unoptimized implementations. The numbers show
**language/runtime overhead on identical naive ARX code**, not how fast
cryptography can go (a tuned library with SIMD is far faster). Do not read them as a
language speed contest.

## Examples

Run everything and regenerate the results table:

```
$ cd bench
$ ./run.sh
  rust: building (release)
  c: building (-O2)
  zig: building (ReleaseFast)
  go: building
  java: building (gradle classes + javac)
  python: running (../python/.venv/bin/python)
  ts: running (pure-TS via tsx)
wrote results.json and RESULTS.md (35 measurements, 7 implementations)

$ cat RESULTS.md
| Implementation | Threefish-256 CTR | ... | BLAKE3 |
| Rust           |              80.9 | ... | 1197.5 |
| Python         |               0.6 | ... |    1.4 |
...
```

A quick run (shorter warmup/measure, or a smaller buffer) while iterating:

```
$ BENCH_WARMUP=0.3 BENCH_MEASURE=0.8 ./run.sh
$ BENCH_BUF=1048576 ./run.sh            # 1 MiB buffer instead of the 64 KiB default
```

Run one implementation directly and see its raw JSON (here Rust, 64 KiB buffer,
0.3s warmup, 0.5s measured):

```
$ cd rust && cargo build --release
$ ./target/release/dorado-bench 65536 0.3 0.5
{"impl":"rust","bench":"threefish-256-ctr","mbps":84.07,"iters":640}
{"impl":"rust","bench":"threefish-512-ctr","mbps":117.91,"iters":1024}
{"impl":"rust","bench":"threefish-1024-ctr","mbps":139.53,"iters":1280}
{"impl":"rust","bench":"skein-512","mbps":116.56,"iters":1024}
{"impl":"rust","bench":"blake3","mbps":1204.55,"iters":10240}
```

The same idea for the others (each prints the same JSON shape; full setup in each
runner's README):

```
$ cd c    && cc -O2 -I../../c/include main.c ../../c/src/{threefish,skein,blake3}.c -o dorado-bench && ./dorado-bench 65536 0.3 0.5
$ cd zig  && zig build && ./zig-out/bin/dorado-bench 65536 0.3 0.5
$ cd go   && go build -o dorado-bench . && ./dorado-bench 65536 0.3 0.5
$ ../../python/.venv/bin/python python/runner.py 65536 0.3 0.5     # from bench/
$ ../ts/node_modules/.bin/tsx ts/runner.ts 65536 0.3 0.5           # from bench/
```

`results.json` carries the provenance you would cite:

```
$ python3 -c "import json;d=json.load(open('results.json'));print(d['machine'],d['date'],d['git_commit'],d['params'])"
Apple M4 Max 2026-06-20 6be147c {'buffer_bytes': 65536, 'warmup_seconds': 0.5, 'measure_seconds': 2.0}
```

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
3. grows a batch size until one batch takes at least 100ms (so the clock is read only
   at batch boundaries, not per iteration, which keeps the measurement robust even
   where the clock is expensive, e.g. Zig's `Io`-based clock),
4. runs that batch repeatedly for `measure_seconds` and reports the **peak**
   `MB/s = buffer_bytes * batch / 1e6 / batch_seconds`.

Reporting the peak (fastest) batch rather than an average is deliberate: scheduling
jitter, CPU frequency scaling, and (on Apple Silicon) performance-vs-efficiency core
placement only ever make a batch *slower*, so the maximum throughput is the
reproducible rate of the code running unimpeded. Without this, the same Zig
Threefish-256 benchmark measured ~75 MB/s on an idle machine but ~17 MB/s under the
orchestrator's sustained load; peak-of-batches removes that variance.

MB is decimal (1e6 bytes); the buffer is 64 KiB (65536 bytes) by default (small
enough that the slow ports still complete many batches, large enough that cipher
setup is negligible and the work stays compute-bound). Each runner emits one JSON
line per benchmark:

```json
{"impl":"rust","bench":"threefish-256-ctr","mbps":412.7,"iters":820}
```

The runner emits **only** these stats. Rounding, framing, and caveats are applied
later, in the report and on the website, never in the measurement.

## Running

### All implementations (the orchestrator)

```
./run.sh
```

`run.sh` builds and runs every available throughput runner with identical
parameters, collects the JSON, records the machine spec / date / git commit, and
writes `results.json` and `RESULTS.md`. A runner whose toolchain is missing is
skipped with a warning, so a partial run still works. Override the parameters with
environment variables, for example a quick check:

```
BENCH_WARMUP=0.3 BENCH_MEASURE=0.8 ./run.sh    # also BENCH_BUF=<bytes>
```

The committed run uses the defaults (64 KiB buffer, 0.5s warmup, 2.0s measured) and
takes a few minutes, almost all of it in the slow ports (Python).

### Prerequisites

The orchestrator uses whatever toolchains are present. For a full run, have:

| Runner | Needs | One-time setup |
| --- | --- | --- |
| Rust | `cargo` | none (builds on first run) |
| C | a C compiler (`cc`) | needs only the C port's primitive sources (no `libargon2`/OpenSSL) |
| Zig | `zig` 0.16 | none |
| Go | `go` | none |
| Java | a JDK (`java`, `javac`) + Gradle | the orchestrator runs `./gradlew classes` in `../java` |
| Python | the Python port's venv | `cd ../python && python3 -m venv .venv && . .venv/bin/activate && pip install -e .` |
| TypeScript | the TS port's `tsx` | `cd ../ts && npm install` |

### A single implementation

Each runner is standalone; see its directory README for the exact build and run
commands. For example:

```
cd rust && cargo build --release && ./target/release/dorado-bench 65536 0.5 2.0
```

Every runner takes `<buffer_bytes> <warmup_seconds> <measure_seconds>` (defaults
`1048576 0.5 2.0`) and prints one JSON line per benchmark to stdout.

## Runners

Each runner is a small program native to its language (it cannot time another
language's code) that follows the protocol above. The timing scaffolding and the
JSON output are the same everywhere; only the calls into that port's primitives
differ. Each directory has its own README with build and run details.

| Runner | Language | Notes |
| --- | --- | --- |
| [`rust/`](rust/README.md) | Rust | release + LTO; path-deps the `dorado` crate |
| [`c/`](c/README.md) | C | links only the primitive sources (no engine, no OpenSSL) |
| [`zig/`](zig/README.md) | Zig | `ReleaseFast`; imports the `dorado` module |
| [`go/`](go/README.md) | Go | a module with a `replace` to the Go port |
| [`java/`](java/README.md) | Java | `Bench.java` compiled against the port's classes (no Bouncy Castle) |
| [`python/`](python/README.md) | Python | imports the installed `dorado` package |
| [`ts/`](ts/README.md) | TypeScript | the pure-TS BigInt cipher, run via `tsx` |

Still planned: an `endtoend.sh` to drive the real CLIs through `hyperfine` for the
end-to-end section, and a reference-library runner (an optimized crate such as
RustCrypto) to show the naive-vs-tuned gap.

`results.json` and `RESULTS.md` are a committed snapshot from one stated machine.
They are not produced by CI, whose hardware varies; to refresh them, run `./run.sh`
on a chosen machine and commit the result.

## What is and isn't covered

- Throughput covers all distinct implementations: the six native ports plus the
  pure-TypeScript cipher (BigInt). The WASM backend used by the Node CLI and the
  browser is the Rust cipher compiled to WebAssembly; it is measured separately as
  `wasm` to show the WASM overhead, and the browser runs that same code.
- The KDFs are never benchmarked here: they are the same delegated libraries across
  ports, and Argon2id/scrypt are intentionally slow, so a single reference cost is
  noted in the end-to-end section instead of a per-language column.
