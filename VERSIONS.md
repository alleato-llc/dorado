# Versions

dorado is versioned **per component**, not as one monolith: a change to one port does
not move the others. Each component carries its own [semantic version](https://semver.org/)
and its own changelog; this table is the index. A change is recorded in the changelog of
whatever it touches, per the routing rule in [CLAUDE.md](CLAUDE.md) and
[README.md](README.md#changelog).

The **Core** row covers the cross-cutting pieces: the project-wide docs (`docs/`,
`SECURITY.md`), the repo-wide CI, and cross-port decisions (the policy framing recorded
once and pointed to from each port). The **Container format** row is special: it is the
on-disk wire format that all ports must agree on byte-for-byte, versioned by the integer
`format::VERSION` rather than semver. Changing it is a coordinated change across every
port and a bump of that integer.

| Component | Version | Changelog | Covers |
| --- | --- | --- | --- |
| Core | 0.1.0 | [CHANGELOG.md](CHANGELOG.md) | `docs/`, `SECURITY.md`, CI, cross-port decisions |
| Container format | v4 | [docs/spec.md](docs/spec.md) | the on-disk `.mahi` wire format (all ports) |
| Rust port | 0.1.4 | [rust/CHANGELOG.md](rust/CHANGELOG.md) | `rust/` (the reference implementation) |
| Go port | 0.1.0 | [go/CHANGELOG.md](go/CHANGELOG.md) | `go/` |
| Java port | 0.1.0 | [java/CHANGELOG.md](java/CHANGELOG.md) | `java/` |
| Python port | 0.1.0 | [python/CHANGELOG.md](python/CHANGELOG.md) | `python/` |
| C port | 0.1.0 | [c/CHANGELOG.md](c/CHANGELOG.md) | `c/` |
| Zig port | 0.1.0 | [zig/CHANGELOG.md](zig/CHANGELOG.md) | `zig/` |
| Haskell port | 0.1.0 | [haskell/CHANGELOG.md](haskell/CHANGELOG.md) | `haskell/` |
| C++ port | 0.1.0 | [cpp/CHANGELOG.md](cpp/CHANGELOG.md) | `cpp/` |
| TypeScript port | 0.1.0 | [ts/CHANGELOG.md](ts/CHANGELOG.md) | `ts/` |
| bench | 0.1.0 | [bench/CHANGELOG.md](bench/CHANGELOG.md) | `bench/` (the Gota consumer) |
| web | 0.1.0 | [web/CHANGELOG.md](web/CHANGELOG.md) | `web/` (the landing page) |

Every component but the Rust port is still at `0.1.0` and unreleased; their current work
sits in each changelog's `Unreleased` section. When a component's first release is cut,
the `Unreleased` entries get a dated version heading (see
[rust/CHANGELOG.md](rust/CHANGELOG.md) for the Rust port's `0.1.1`, its first, cut via
the salpa-driven auto-release track) and this table tracks it from there. The Rust port
is the only component with an actual release track today (`rust-v*` tags,
`rust/docs/RELEASING.md`); its version here must be kept in sync by hand against
`git tag -l "rust-v*"`, since salpa's automation creates the tag and GitHub Release
but never touches this file — nothing currently updates this table automatically on
release (tracked as a salpa TODO; see the `salpa` repo). The container format is at
`v4` (version 3 is still read).

## Versioning rules

- **MAJOR** - a breaking change. For a port, a change to its public SDK/CLI surface that
  a consumer must adapt to. For the Container format, any change to the on-disk bytes
  (always a `format::VERSION` bump, coordinated across all ports).
- **MINOR** - backward-compatible additions (a new SDK capability, a new CLI flag, a new
  optional feature).
- **PATCH** - fixes and doc-only changes that do not alter behavior or the format.

A port's version moves independently, but the **Container format** is the shared
contract: a file written by any port at format `v4` must decrypt in every other port at
`v4`. That cross-compatibility is tested, and it is the one thing no port may break on
its own.
