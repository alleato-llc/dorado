# Changelog - bench

Changes to the **benchmark harness only** (`bench/`). Cross-cutting changes live in the
[Core CHANGELOG](../CHANGELOG.md); [VERSIONS.md](../VERSIONS.md) is the master table.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

`bench/` is a consumer of [Gota](https://github.com/alleato-llc/gota); `harness.py`,
`report.py`, and `report_template.html` are copies from Gota (change them there and
re-copy, do not edit in place).

## [Unreleased]

### Added

- An HTML report (`report.py` + `report_template.html`, copied from Gota) that renders
  `results.json` into a self-contained, sortable `report.html` with a file picker,
  per-language colors, magnitude bars, and formatted MB/s.

### Changed

- `bench/` now consumes Gota: `harness.py`, `report.py`, and `report_template.html` are
  copies from `github.com/alleato-llc/gota` and carry a provenance note.
- Replaced the shell orchestrator (`run.sh`) with the Python `run.py` plus the generic
  `harness.py`; subprocess capture isolates each runner's output, fixing a shell
  append-race that could scramble it.

### Fixed

- `report.html` was regenerated empty; rebuilt it from `results.json` with the data
  embedded. Reworded `report_template.html`'s comment (synced from Gota) so the
  substitution tokens it documented no longer get replaced into the comment.
