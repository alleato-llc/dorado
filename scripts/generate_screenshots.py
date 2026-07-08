#!/usr/bin/env python3
"""Generate dorado's landing-page screenshot set: an "encrypt" scene for
dorado-gui and a "hash" scene for gyotaku-gui, each in the site's two themes
(Dracula dark, Solarized Light). Output lands in web/public/screenshots/ as
<app>-<scene>-<theme>.png.

Driven entirely by each GUI's permanent env-gated shot harness
(rust/crates/dorado-gui/src/shot.rs, rust/crates/dorado-gyotaku-gui/src/shot.rs)
-- this script only seeds content and loops scenes x themes. Each GUI crate is
excluded from the main Cargo workspace (see rust/Cargo.toml) because it depends
on the sibling `rime` repo by path, so this script invokes `cargo run`
separately inside each crate's own directory (each resolves its own Cargo.lock)
rather than from a single shared workspace root.

Needs a GPU: locally (a real GPU), or headless Linux via
.github/workflows/screenshots.yml (software Vulkan/lavapipe + xvfb). Needs a
sibling checkout of alleato-llc/rime next to this repo (../rime relative to
the dorado repo root) -- that's how both GUI crates resolve their `rime` path
dependency (see each crate's Cargo.toml).

    scripts/generate_screenshots.py [output_dir]

Env:
  SHOT_PROFILE=debug   build/run the debug binary instead of --release
                       (faster to iterate locally; pixels are identical)
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Seeds are inline so the script is self-contained and reproducible.

# A short, readable pangram -- real content so the shots show genuinely
# computed ciphertext / digest output rather than placeholder text.
MESSAGE = "The quick brown fox jumps over the lazy dog."
PASSWORD = "correct-horse-battery-staple"

# Themes: rime's built-in "Dracula" (dark) and "Solarized Light" (light) --
# see rime/rime/src/theme/palettes.rs's builtin_themes(). One dark, one light.
THEMES = [
    ("Dracula", "dracula"),
    ("Solarized Light", "solarized-light"),
]


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "web" / "public" / "screenshots"
    dorado_gui = ROOT / "rust" / "crates" / "dorado-gui"
    gyotaku_gui = ROOT / "rust" / "crates" / "dorado-gyotaku-gui"
    out.mkdir(parents=True, exist_ok=True)

    profile = os.environ.get("SHOT_PROFILE", "release")
    cargo_flags = ["--release"] if profile == "release" else []

    def shot(name: str, cwd: Path, shot_var: str, **extra_env: str) -> None:
        """One capture: run the crate's binary under the given shot env, which
        saves a PNG to out/<name>.png and exits (see each crate's shot.rs)."""
        env = {
            **os.environ,
            shot_var: str(out / f"{name}.png"),
            **extra_env,
        }
        subprocess.run(["cargo", "run", "-q", *cargo_flags], cwd=cwd, check=True, env=env)
        print(f"  -> {name}.png")

    print(f"Generating dorado screenshots into {out} (profile: {profile})...")

    for theme_name, theme_slug in THEMES:
        # dorado-gui: encrypt, a real computed ciphertext.
        shot(
            f"dorado-encrypt-{theme_slug}",
            dorado_gui,
            "DORADO_SHOT",
            DORADO_SHOT_DIRECTION="encrypt",
            DORADO_SHOT_SOURCE="text",
            DORADO_SHOT_THEME=theme_name,
            DORADO_SHOT_PASSWORD=PASSWORD,
            DORADO_SHOT_TEXT=MESSAGE,
        )
        # gyotaku-gui: hash, a real computed digest.
        shot(
            f"gyotaku-hash-{theme_slug}",
            gyotaku_gui,
            "GYOTAKU_SHOT",
            GYOTAKU_SHOT_SOURCE="text",
            GYOTAKU_SHOT_THEME=theme_name,
            GYOTAKU_SHOT_TEXT=MESSAGE,
        )

    print(f"Done -- {2 * len(THEMES)} screenshots in {out}.")


if __name__ == "__main__":
    main()
