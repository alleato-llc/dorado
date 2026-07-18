# Releasing dorado (Rust)

Releases are **automatic**, driven by [salpa](https://github.com/alleato-llc/salpa)
(our house release tool, pulled from ghcr as a private OCI artifact) via
`.github/workflows/release.yml`. Work happens on branches and PRs (`ci.yml` runs
tests); a push/merge to `main` touching `rust/**` runs the release track. It can
also be triggered by hand from the Actions tab (**Run workflow** → `workflow_dispatch`).

## What ships

Everything lands on the same `rust-v<version>` GitHub Release:

- **The two CLIs** (`dorado`, `gyotaku`): bare, unsigned per-platform binaries —
  `dorado-<os>-<arch>[.exe]` / `gyotaku-<os>-<arch>[.exe]` — for Linux, macOS
  (arm64 + x86_64, built separately), and Windows.
- **The two GUI apps** (`dorado-gui`, `gyotaku-gui`):
  - **macOS**: a **signed + notarized universal** `Dorado-<version>.dmg` /
    `Gyotaku-<version>.dmg` (one dmg runs on both Apple Silicon and Intel).
    Unlike the CLI, this is a single universal build, not two separate per-arch
    ones — that's inherent to how macOS app signing/notarization works, not an
    inconsistency.
  - **Linux/Windows**: bare, unsigned binaries, same convention as the CLI
    (`dorado-gui-<os>-<arch>[.exe]`, `gyotaku-gui-<os>-<arch>[.exe]`).

Why the GUIs are signed on macOS but the CLIs aren't: Gatekeeper is far more
aggressive about a double-clicked, unsigned GUI app than a terminal-launched CLI
binary (which a developer audience tolerates a `chmod +x`/`xattr` workaround for).
An unsigned `.app` a regular user downloads and double-clicks just says "cannot be
opened" with no obvious way past it; a signed + notarized one opens cleanly.

`salpa version` computes the next semver from `rust-v*` tags plus `#minor`/`#major`
in the head commit message (patch by default). The `version` job creates the empty
release once so the parallel build legs upload into it deterministically.

## Pipeline shape

```
test  →  version  →  build (CLI: linux/macos-arm64/macos-x86_64/windows, unsigned)
                   →  build-gui-macos (both GUIs, universal, SIGNED + NOTARIZED)
                   →  build-gui-portable (both GUIs: linux, windows, unsigned)
```

The GUI jobs check out `dorado` and the sibling `alleato-llc/rime` repo side by
side (`dorado-gui`/`dorado-gyotaku-gui` depend on it by path — see
`rust/Cargo.toml`'s workspace-exclude comment), matching `ci.yml`'s `gui` job.
Each GUI app carries its own `salpa.yaml` in its own crate directory
(`rust/crates/dorado-gui/salpa.yaml`, `rust/crates/dorado-gyotaku-gui/salpa.yaml`)
rather than a shared config, since each lives in its own directory with no
naming collision to avoid (unlike the CLIs, which share `rust/` and so need
distinctly-named `salpa-dorado.yaml`/`salpa-gyotaku.yaml`).

## One-time setup: the five secrets (macOS signing)

Needed once, in **this repo's** GitHub settings — **Settings → Secrets and
variables → Actions → New repository secret**. This is a fresh setup even if you
already have these secrets configured for a different repo (e.g. `soroban`):
GitHub secrets are per-repository, so the same underlying Apple Developer ID
certificate still needs to be re-exported and re-added here.

| Secret | Value |
|---|---|
| `BUILD_CERTIFICATE_BASE64` | your Developer ID Application certificate **with its private key**, exported as `.p12`, base64-encoded |
| `P12_PASSWORD` | the password you chose during the `.p12` export |
| `APPLE_TEAM_ID` | the 10-character team id (developer.apple.com → Membership) |
| `APPLE_ID` | the Apple ID email used for notarization |
| `APPLE_APP_SPECIFIC_PASSWORD` | an app-specific password — create at [appleid.apple.com](https://appleid.apple.com) → Sign-In and Security → App-Specific Passwords |

Until these exist, `build-gui-macos` will fail at the signing step — the CLI
binaries and the portable GUI binaries are unaffected (they need no secrets).

### Exporting the certificate

You need a **Developer ID Application** certificate (not "Apple Development" /
"Mac App Distribution"). If you don't have one yet: Xcode → Settings → Accounts →
Manage Certificates → + → Developer ID Application (or developer.apple.com →
Certificates). This requires an active Apple Developer Program membership.

1. Open **Keychain Access** → My Certificates.
2. Find "Developer ID Application: Your Name (TEAMID)" — expand it and confirm
   the private key is underneath (no key = export from the Mac that created the
   certificate).
3. Right-click the certificate → **Export…** → format `.p12`, choose a password
   (that's `P12_PASSWORD`).
4. Base64 it onto the clipboard and paste into the secret:

   ```sh
   base64 -i Certificates.p12 | pbcopy
   ```

### Pulling salpa

The workflow pulls the `salpa` binary from ghcr (`ghcr.io/alleato-llc/salpa`) via
`oras`, authenticated with the workflow's own `GITHUB_TOKEN` (`packages: read`).
salpa is a **private** package; this repo is granted read access under the
package's *Manage Actions access* settings — no separate PAT needed.

## Day-to-day

```sh
git checkout -b feature/thing     # ci.yml runs tests on every push
…                                 # open a PR, merge to main
                                  # rust/** → release.yml (rust-v0.1.X: CLIs + both GUIs)
```

- Bigger bumps: include `#minor` or `#major` in the merge commit message.
- A failed release (e.g. before the secrets existed, or a notarization hiccup):
  fix the cause and **re-run the workflow run** — the head is already tagged, so
  it rebuilds the same version instead of bumping again.
- Verify a downloaded dmg locally (on a Mac):

  ```sh
  spctl -a -t open --context context:primary-signature -v Dorado-0.1.0.dmg
  xcrun stapler validate Dorado-0.1.0.dmg
  ```

## Icons

Each GUI app embeds its own icon: `rust/crates/dorado-gui/packaging/AppIcon.icns`
and `rust/crates/dorado-gyotaku-gui/packaging/AppIcon.icns` (used by salpa's macOS
`.app` bundling), plus a 256×256 PNG at `src/assets/icon.png` in each crate (used
as the iced window/taskbar icon on Linux and Windows — macOS takes its Dock icon
from the `.app` bundle instead). Both are generated from a source SVG at
`packaging/icon.svg` in each crate.
