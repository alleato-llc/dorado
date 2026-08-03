# Changelog - bench

Changes to the **benchmark harness only** (`bench/`). Cross-cutting changes live in the
[Core CHANGELOG](../CHANGELOG.md); [VERSIONS.md](../VERSIONS.md) is the master table.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

`bench/` is a consumer of [Gota](https://github.com/alleato-llc/gota); `harness.py`,
`report.py`, and `report_template.html` are copies from Gota (change them there and
re-copy, do not edit in place).

## [Unreleased]

### Added

- **Re-copied `harness.py`, `report.py`, and `report_template.html` from Gota**, which
  had been frozen at an old revision. The orchestrator gains toolchain-version
  provenance (`gather_metadata(toolchains=...)`, now wired into `run.py`), a per-runner
  timeout, the `Metric` kind, and the comparison helpers; `report.py` gains baseline
  comparison, `--markdown`, and `--fail-on-regression`. Only the provenance docstrings
  are adapted, per the note those files carry.
- **All nine runners emit the current protocol line**
  (`{"impl","bench","mbps","mbps_median","iters","protocol"}`, Gota protocol 1.2.0).
  They were still on the original four-field line: no `mbps_median`, so no stability
  signal, and no version, so nothing said they were behind. Each now collects per-batch
  rates and reports their median beside the peak.

- **C++ and Haskell throughput runners** (`bench/cpp/`, `bench/haskell/`), closing a gap
  that had been open since those ports landed: `bench/` was last touched 2026-06-20, the
  Haskell port arrived 06-21 and C++ on 06-22, so the published table claimed to cover
  the project while measuring 7 of 9 implementations. Both are wired into `run.py`
  (`RunnerSpec`, `IMPL_ORDER`, `IMPL_LABELS`), and `RESULTS.md`/`results.json`/
  `report.html` are regenerated as a nine-implementation run.
  - C++ compiles directly against the port's three primitive translation units (no
    engine, so no libargon2/OpenSSL), mirroring the C runner.
  - Haskell compiles against the port's library sources with plain `ghc` — the
    primitives need only boot packages, so cabal and `crypton` stay out of it. Every op
    forces its result and feeds a byte into an accumulator, because a returned thunk
    nothing inspects would measure nothing.

- An HTML report (`report.py` + `report_template.html`, copied from Gota) that renders
  `results.json` into a self-contained, sortable `report.html` with a file picker,
  per-language colors, magnitude bars, and formatted MB/s.

### Changed

- Benchmark artifacts regenerated under the new harness, so `results.json` now records
  the toolchain versions that produced the numbers and the protocol each runner
  implements. This is what was missing when Zig's Threefish-512 and Skein-512 rates
  quadrupled between the 2026-06-20 and 2026-08-02 snapshots and the cause could not be
  pinned down.
- On that note: Zig's **Threefish-1024** has now read 52.2, 68.2, and 148.6 MB/s across
  three snapshots, while every other measurement moved only a few percent. Its
  peak-to-median gap *within* this run is small, so it is not noise inside a run; the
  variance is between runs. Unexplained, recorded rather than smoothed over, and now at
  least measurable, since the toolchain that produced each number is captured.

- Regenerated `RESULTS.md` / `results.json` / `report.html` as a nine-implementation run
  (2026-08-02). The seven previously-measured ports all land within a few percent of the
  2026-06-20 snapshot except **Zig**, whose Threefish-512 and Skein-512 rates are ~4x
  higher (24.1 -> 105.5 and 24.2 -> 106.4 MB/s) and Threefish-1024 ~30% higher. That is
  not machine noise — every other port moved <7% in the same run — but this harness copy
  predates Gota's `toolchains=` provenance, so neither snapshot records the compiler
  versions and the change cannot be attributed here. Most likely a Zig toolchain move
  (the port targets 0.16 now); re-copying the current Gota `harness.py` would record
  toolchains and make the next such jump self-explaining.
- `bench/` now consumes Gota: `harness.py`, `report.py`, and `report_template.html` are
  copies from `github.com/alleato-llc/gota` and carry a provenance note.
- Replaced the shell orchestrator (`run.sh`) with the Python `run.py` plus the generic
  `harness.py`; subprocess capture isolates each runner's output, fixing a shell
  append-race that could scramble it.

### Fixed

- `report.html` was regenerated empty; rebuilt it from `results.json` with the data
  embedded. Reworded `report_template.html`'s comment (synced from Gota) so the
  substitution tokens it documented no longer get replaced into the comment.
