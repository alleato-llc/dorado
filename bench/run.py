#!/usr/bin/env python3
"""Dorado throughput orchestrator.

This is the dorado-specific configuration on top of the generic framework in
harness.py: it declares one RunnerSpec per language (how to build it and how to
invoke it), the row/column labels, and the honest framing text, then runs them all
and writes results.json + RESULTS.md.

Parameters come from the environment (with defaults): BENCH_BUF (bytes),
BENCH_WARMUP (seconds), BENCH_MEASURE (seconds). A runner whose toolchain is missing
is skipped. Run from anywhere:  python3 bench/run.py
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import harness
from harness import RunnerSpec, which

BENCH = Path(__file__).resolve().parent
os.chdir(BENCH)

# Canonical parameters. A 64 KiB buffer keeps the slow ports (Python ~0.6 MB/s) above
# a handful of batches while staying compute-bound (no cache-size skew) for the fast
# ones; cipher setup is negligible against the per-byte work at this size.
BUF = int(os.environ.get("BENCH_BUF", 65536))
WARMUP = float(os.environ.get("BENCH_WARMUP", 0.5))
MEASURE = float(os.environ.get("BENCH_MEASURE", 2.0))


def _build(cmd: list[str], cwd: str | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


# --- per-runner prepare functions (build + return the run argv, or None to skip) ---

def prep_rust():
    if not which("cargo"):
        return None
    harness.log("  rust: building (release)")
    _build(["cargo", "build", "-q", "--release"], cwd="rust")
    return ["rust/target/release/dorado-bench"]


def prep_c():
    if not which("cc"):
        return None
    harness.log("  c: building (-O2)")
    _build([
        "cc", "-std=c17", "-O2", "-I../c/include", "c/main.c",
        "../c/src/threefish.c", "../c/src/skein.c", "../c/src/blake3.c",
        "-o", "c/dorado-bench",
    ])
    return ["c/dorado-bench"]


def prep_cpp():
    if not which("c++"):
        return None
    harness.log("  cpp: building (-O2)")
    _build([
        "c++", "-std=c++23", "-O2", "-I../cpp/include", "cpp/main.cpp",
        "../cpp/src/threefish.cpp", "../cpp/src/skein.cpp", "../cpp/src/blake3.cpp",
        "-o", "cpp/dorado-bench",
    ])
    return ["cpp/dorado-bench"]


def prep_zig():
    if not which("zig"):
        return None
    harness.log("  zig: building (ReleaseFast)")
    _build(["zig", "build"], cwd="zig")
    return ["zig/zig-out/bin/dorado-bench"]


def prep_go():
    if not which("go"):
        return None
    harness.log("  go: building")
    _build(["go", "build", "-o", "dorado-bench", "."], cwd="go")
    return ["go/dorado-bench"]


def prep_java():
    if not (which("java") and which("javac")):
        return None
    cp = "../java/build/classes/java/main"
    harness.log("  java: building (gradle classes + javac)")
    # Build the port's classes, preferring the wrapper.
    java_dir = BENCH.parent / "java"
    if (java_dir / "gradlew").exists():
        _build(["./gradlew", "-q", "classes"], cwd=str(java_dir))
    elif which("gradle"):
        _build(["gradle", "-q", "classes"], cwd=str(java_dir))
    else:
        return None
    _build(["javac", "-cp", cp, "-d", "java", "java/Bench.java"])
    return ["java", "-cp", f"{cp}:java", "Bench"]


def prep_python():
    venv = BENCH.parent / "python" / ".venv" / "bin" / "python"
    if venv.exists():
        return [str(venv), "python/runner.py"]
    if which("python3") and subprocess.run(
        ["python3", "-c", "import dorado"], capture_output=True
    ).returncode == 0:
        return ["python3", "python/runner.py"]
    return None


def prep_haskell():
    if not which("ghc"):
        return None
    harness.log("  haskell: building (-O2)")
    # Compiled straight against the port's library sources; the primitives need only
    # GHC boot packages, so no cabal build (and no crypton) is required.
    _build(["ghc", "-O2", "-i../../haskell/src", "Main.hs", "-o", "dorado-bench"],
           cwd="haskell")
    return ["haskell/dorado-bench"]


def prep_ts():
    tsx = BENCH.parent / "ts" / "node_modules" / ".bin" / "tsx"
    if tsx.exists():
        return [str(tsx), "ts/runner.ts"]
    return None


SPECS = [
    RunnerSpec("rust", prep_rust),
    RunnerSpec("c", prep_c),
    RunnerSpec("cpp", prep_cpp),
    RunnerSpec("zig", prep_zig),
    RunnerSpec("go", prep_go),
    RunnerSpec("java", prep_java),
    RunnerSpec("python", prep_python),
    RunnerSpec("haskell", prep_haskell),
    RunnerSpec("ts", prep_ts),
]

# Row order and labels, column order and labels, all dorado-specific.
# Version probes for the toolchains this run uses, recorded into the results'
# provenance (absent tools are skipped). A number is only reproducible alongside the
# compiler that produced it -- without this, a 4x jump between snapshots cannot be
# attributed to a toolchain change or anything else.
TOOLCHAINS = {
    "rust": ["rustc", "--version"],
    "c": ["cc", "--version"],
    "cpp": ["c++", "--version"],
    "zig": ["zig", "version"],
    "go": ["go", "version"],
    "java": ["java", "-version"],
    "haskell": ["ghc", "--numeric-version"],
    "python": ["python3", "--version"],
    "ts": ["node", "--version"],
}

IMPL_ORDER = ["rust", "c", "cpp", "zig", "go", "java", "haskell", "python", "ts", "wasm"]
IMPL_LABELS = {
    "rust": "Rust", "c": "C", "cpp": "C++", "zig": "Zig", "go": "Go", "java": "Java",
    "haskell": "Haskell", "python": "Python", "ts": "TypeScript (pure)",
    "wasm": "WASM (Rust)",
}
BENCH_ORDER = ["threefish-256-ctr", "threefish-512-ctr", "threefish-1024-ctr", "skein-512", "blake3"]
BENCH_LABELS = {
    "threefish-256-ctr": "Threefish-256 CTR",
    "threefish-512-ctr": "Threefish-512 CTR",
    "threefish-1024-ctr": "Threefish-1024 CTR",
    "skein-512": "Skein-512",
    "blake3": "BLAKE3",
}


def intro(meta: dict) -> str:
    return (
        f"Throughput in MB/s (decimal). Measured on **{meta['machine']}** "
        f"({meta['os']}), {meta['date']}, commit `{meta['git_commit']}`. Buffer "
        f"{BUF} bytes; {WARMUP}s warmup, {MEASURE}s measured.\n\n"
        "These are naive, from-scratch, **unoptimized** implementations. The numbers "
        "show language/runtime overhead on identical ARX code, not how fast "
        "cryptography can go (a tuned library with SIMD is far faster). Not a language "
        "speed contest. Each value is the **peak throughput** over many batches (the "
        "fastest batch is the reproducible rate, since scheduling jitter and frequency "
        "scaling only ever slow a batch). Regenerate with `python3 run.py`."
    )


def main() -> None:
    rows = harness.run_all(SPECS, BUF, WARMUP, MEASURE)
    meta = harness.gather_metadata(toolchains=TOOLCHAINS)
    harness.write_results(
        rows,
        "results.json",
        "RESULTS.md",
        params={"buffer_bytes": BUF, "warmup_seconds": WARMUP, "measure_seconds": MEASURE},
        meta=meta,
        units="MB/s (decimal, 1e6 bytes)",
        impl_order=IMPL_ORDER,
        impl_labels=IMPL_LABELS,
        bench_order=BENCH_ORDER,
        bench_labels=BENCH_LABELS,
        intro=intro(meta),
    )


if __name__ == "__main__":
    main()
