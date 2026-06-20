#!/usr/bin/env bash
# Build and run every throughput runner with identical parameters, collect the JSON,
# and generate results.json + RESULTS.md. See README.md for the protocol and framing.
#
# Each runner is invoked as: runner <buffer_bytes> <warmup_s> <measure_s>. A runner
# whose toolchain is missing is skipped with a warning, so a partial run still works.
# Each runner writes to its own file; the files are concatenated in a fixed order at
# the end (no shared append, so the output is deterministic).
set -uo pipefail
cd "$(dirname "$0")"

# Canonical parameters. A 64 KiB buffer keeps the slow ports (Python ~0.6 MB/s) above
# a handful of iterations while staying compute-bound (no cache-size skew) for the
# fast ones; cipher setup is negligible against the per-byte work at this size.
BUF=${BENCH_BUF:-65536}
WARMUP=${BENCH_WARMUP:-0.5}
MEASURE=${BENCH_MEASURE:-2.0}

OUTDIR=$(mktemp -d)
trap 'rm -rf "$OUTDIR"' EXIT

note() { printf '  %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- Rust ---
if have cargo; then
  note "rust: building (release)"
  if ( cd rust && cargo build -q --release ); then
    rust/target/release/dorado-bench "$BUF" "$WARMUP" "$MEASURE" >"$OUTDIR/rust"
  fi
else note "rust: cargo not found, skipping"; fi

# --- C ---
if have cc; then
  note "c: building (-O2)"
  if cc -std=c17 -O2 -I../c/include c/main.c ../c/src/threefish.c ../c/src/skein.c ../c/src/blake3.c -o c/dorado-bench; then
    c/dorado-bench "$BUF" "$WARMUP" "$MEASURE" >"$OUTDIR/c"
  fi
else note "c: cc not found, skipping"; fi

# --- Zig ---
if have zig; then
  note "zig: building (ReleaseFast)"
  if ( cd zig && zig build ); then
    zig/zig-out/bin/dorado-bench "$BUF" "$WARMUP" "$MEASURE" >"$OUTDIR/zig"
  fi
else note "zig: zig not found, skipping"; fi

# --- Go ---
if have go; then
  note "go: building"
  if ( cd go && go build -o dorado-bench . ); then
    go/dorado-bench "$BUF" "$WARMUP" "$MEASURE" >"$OUTDIR/go"
  fi
else note "go: go not found, skipping"; fi

# --- Java ---
if have java && have javac; then
  note "java: building (gradle classes + javac)"
  CP=../java/build/classes/java/main
  if ( cd ../java && ./gradlew -q classes 2>/dev/null || gradle -q classes 2>/dev/null ); then
    if javac -cp "$CP" -d java java/Bench.java; then
      java -cp "$CP:java" Bench "$BUF" "$WARMUP" "$MEASURE" >"$OUTDIR/java"
    fi
  else note "java: could not build the port classes, skipping"; fi
else note "java: java/javac not found, skipping"; fi

# --- Python ---
PYBIN=""
if [ -x ../python/.venv/bin/python ]; then PYBIN=../python/.venv/bin/python
elif have python3 && python3 -c "import dorado" 2>/dev/null; then PYBIN=python3; fi
if [ -n "$PYBIN" ]; then
  note "python: running ($PYBIN)"
  "$PYBIN" python/runner.py "$BUF" "$WARMUP" "$MEASURE" >"$OUTDIR/python"
else note "python: dorado not importable (make a venv: pip install -e ../python), skipping"; fi

# --- TypeScript (pure) ---
TSX=../ts/node_modules/.bin/tsx
if [ -x "$TSX" ]; then
  note "ts: running (pure-TS via tsx)"
  "$TSX" ts/runner.ts "$BUF" "$WARMUP" "$MEASURE" >"$OUTDIR/ts"
else note "ts: tsx not found (npm install in ../ts), skipping"; fi

# Concatenate per-runner outputs in a fixed order.
RAW="$OUTDIR/all.jsonl"
: >"$RAW"
for impl in rust c zig go java python ts; do
  [ -s "$OUTDIR/$impl" ] && cat "$OUTDIR/$impl" >>"$RAW"
done

# --- metadata + report ---
if [ "$(uname -s)" = "Darwin" ]; then
  export BENCH_MACHINE=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown")
else
  export BENCH_MACHINE=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' || echo "unknown")
fi
export BENCH_OS="$(uname -sm)"
export BENCH_DATE="$(date +%Y-%m-%d)"
export BENCH_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
export BENCH_BUF="$BUF" BENCH_WARMUP="$WARMUP" BENCH_MEASURE="$MEASURE"

REPORT_PY=${PYBIN:-python3}
"$REPORT_PY" report.py "$RAW" results.json RESULTS.md
