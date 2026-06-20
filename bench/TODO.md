# Benchmark: remaining work

A record of what is built and what is left, for review. The throughput section is
complete and committed; the items below are not yet done.

## Done

- **Throughput runners** for all seven implementations (Rust, C, Zig, Go, Java,
  Python, pure-TypeScript), each native to its language under one uniform protocol.
- **Peak-of-batches methodology** (robust to clock cost and Apple Silicon P/E-core
  scheduling), with the rationale documented in `README.md`.
- **Orchestrator** (`run.py`) + engine (`harness.py`) producing `results.json` and
  `RESULTS.md`, with machine/date/commit provenance, plus an HTML report (`report.py`
  + `report_template.html`) producing `report.html`.
- **Built on Gota**: `harness.py`, `report.py`, and `report_template.html` are copies
  from github.com/alleato-llc/gota (the protocol and generic tooling live there);
  `run.py` and the runners are the dorado-specific parts.
- **Docs**: top-level `README.md`, a per-runner README each, worked examples,
  prerequisites, and a mention in the project README and `CLAUDE.md`.

## Remaining

### 1. End-to-end section (`endtoend.py`)
The "where the time goes" reality check: the real `dorado` CLIs timed with
`hyperfine`, so the table reflects process startup + KDF + cipher + I/O, i.e. what a
user actually waits for. Covers only the five ports with a CLI (not Java SDK, not
the browser).
- **Why:** the throughput numbers alone are misleading about the *tool* (a real
  password operation is dominated by the KDF, ~100ms fixed). This section corrects
  that.
- **Decisions to make:**
  - Raw-key mode (isolates cipher + startup + I/O, no KDF) vs password mode (shows
    the KDF dominating)? Probably **both**: raw-key for a fair end-to-end, password
    for the KDF-dominance point.
  - Surface a single **KDF cost reference** (Argon2id at default params, ~the same
    across ports since it is the same library) rather than a per-language KDF race.
  - Framing: this is explicitly **not a language race** (differences are startup +
    KDF library, not our code).
- **Needs:** `hyperfine` installed; the CLIs built.
- **Effort:** small-to-medium (a Python script reusing `harness.py` + framing).

### 2. Reference-library runner
Measure an optimized library under the *same* protocol (e.g. RustCrypto's
`threefish`/`blake3` crates, or OpenSSL) to show the naive-vs-tuned gap.
- **Why:** turns the "these are unoptimized; real crypto with SIMD is far faster"
  caveat into a **measured number** instead of a hand-wave. The most useful "other
  solution" to point this at.
- **Decisions to make:** which library (RustCrypto is easiest, toolchain already
  present); which primitives (Threefish has few optimized impls; BLAKE3's official
  crate is a dramatic SIMD contrast).
- **Effort:** small (one extra runner reusing the scaffolding) + a new dependency,
  so it needs the usual ask.

### 3. Website integration
Render the Throughput table (and, if wanted, the end-to-end section) on the Astro
landing page, fed from `results.json` at build time (static, committed, like the
comparison table), with the honest framing and caveats.
- **Decisions to make:** how prominent; table vs simple bars; whether to include the
  end-to-end section; how to show the pure-TS-vs-WASM split.
- **Effort:** medium (an Astro section + styling, mirroring the comparison table).

### 4. WASM / browser measurement
A `wasm` row: the Rust cipher compiled to WebAssembly, run in Node, to show the WASM
overhead vs native Rust (and ≈ the browser's speed). The `README.md` already
mentions this as a separate measurement.
- **Why:** completes the picture for the Node CLI and the browser demo, which run
  WASM, not the pure-TS code.
- **Effort:** small (load the existing `rust/wasm` build in a Node runner).

### 5. Investigate the Zig Threefish-512 anomaly
Zig's Threefish-512 (and therefore Skein-512) is a stable ~4x slower than 256/1024
under `ReleaseFast`, while C and Rust show 512 in line. This is a genuine codegen
finding (the peak-of-batches methodology confirmed it is real, not measurement
noise), documented in `zig/README.md`.
- **Why:** it is a real performance bug in the Zig port worth understanding; may be
  fixable (loop unrolling / `inline`) or reportable upstream.
- **Effort:** unknown (profiling + possibly a source tweak); investigation first.

### 6. Provenance refresh (minor)
`results.json` currently records the *parent* commit (`6be147c`), because the
snapshot was generated before the harness commit. Re-running `python3 run.py` on the
current commit and committing the refreshed results makes them cite their own commit.
- **Effort:** trivial (a ~4-minute run + one commit).

### 7. Lab-grade environment control (optional)
If absolute (not just relative) numbers are ever needed: pin to performance cores
(`taskpolicy`/`taskset`), lock CPU frequency, run on a dedicated quiescent machine
with cooldowns between runners. Peak-of-batches is sufficient for the current
relative-comparison goal, so this is only for a future "lab-grade" need.
- **Effort:** medium, and platform-specific.
