# Changelog

Notable changes to the dorado monorepo. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); when releases are cut they
get a dated version heading below `Unreleased`. This changelog starts in 2026-06; for
earlier history see the git log.

**Rule:** any change worth noting (a feature, a fix, a wire-format or behavior change,
a notable doc change) adds a bullet to the `Unreleased` section **in the same commit or
PR**, grouped under Added / Changed / Fixed / Removed. Wire-format or algorithm changes
must say so explicitly, since they affect cross-compatibility across all ports.

## [Unreleased]

### Fixed

- `bench/report.html` was regenerated empty; rebuilt it from `results.json` with the
  data embedded. Also reworded `report_template.html`'s comment (synced from Gota) so
  the substitution tokens it documented no longer get replaced into the comment.

### Added

- `bench/`: an HTML report (`report.py` + `report_template.html`) that renders
  `results.json` into a self-contained `report.html` (sortable, per-language colors,
  magnitude bars, formatted MB/s, with a file picker).

### Changed

- `bench/` is now a consumer of [Gota](https://github.com/alleato-llc/gota), the
  standalone cross-language micro-benchmark reference extracted from this harness.
  `harness.py`, `report.py`, and `report_template.html` are copies from Gota (do not
  edit in place; change them in Gota and re-copy).
- `bench/`: replaced the shell orchestrator (`run.sh`) with the Python `run.py` plus
  the generic `harness.py`; subprocess capture isolates each runner's output, fixing a
  shell append-race that could scramble it.
