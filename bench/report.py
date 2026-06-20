#!/usr/bin/env python3
"""Assemble runner output into results.json and RESULTS.md.

Usage: report.py <raw_jsonl> <out_json> <out_md>
Reads metadata from environment: BENCH_MACHINE, BENCH_OS, BENCH_DATE,
BENCH_COMMIT, BENCH_BUF, BENCH_WARMUP, BENCH_MEASURE.
"""

from __future__ import annotations

import json
import os
import sys

# Display order for the rows and columns.
IMPLS = ["rust", "c", "zig", "go", "java", "python", "ts", "wasm"]
IMPL_LABELS = {
    "rust": "Rust",
    "c": "C",
    "zig": "Zig",
    "go": "Go",
    "java": "Java",
    "python": "Python",
    "ts": "TypeScript (pure)",
    "wasm": "WASM (Rust)",
}
BENCHES = ["threefish-256-ctr", "threefish-512-ctr", "threefish-1024-ctr", "skein-512", "blake3"]
BENCH_LABELS = {
    "threefish-256-ctr": "Threefish-256 CTR",
    "threefish-512-ctr": "Threefish-512 CTR",
    "threefish-1024-ctr": "Threefish-1024 CTR",
    "skein-512": "Skein-512",
    "blake3": "BLAKE3",
}


def main() -> None:
    raw_path, out_json, out_md = sys.argv[1], sys.argv[2], sys.argv[3]

    rows = []
    with open(raw_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                rows.append(json.loads(line))

    doc = {
        "machine": os.environ.get("BENCH_MACHINE", "unknown"),
        "os": os.environ.get("BENCH_OS", "unknown"),
        "date": os.environ.get("BENCH_DATE", "unknown"),
        "git_commit": os.environ.get("BENCH_COMMIT", "unknown"),
        "params": {
            "buffer_bytes": int(os.environ.get("BENCH_BUF", "0")),
            "warmup_seconds": float(os.environ.get("BENCH_WARMUP", "0")),
            "measure_seconds": float(os.environ.get("BENCH_MEASURE", "0")),
        },
        "units": "MB/s (decimal, 1e6 bytes)",
        "results": rows,
    }
    with open(out_json, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")

    # Lookup table: (impl, bench) -> mbps
    by = {(r["impl"], r["bench"]): r["mbps"] for r in rows}
    present = [i for i in IMPLS if any(r["impl"] == i for r in rows)]

    lines = []
    lines.append("# Benchmark results")
    lines.append("")
    lines.append(
        f"Throughput in MB/s (decimal). Measured on **{doc['machine']}** "
        f"({doc['os']}), {doc['date']}, commit `{doc['git_commit']}`. Buffer "
        f"{doc['params']['buffer_bytes']} bytes; {doc['params']['warmup_seconds']}s warmup, "
        f"{doc['params']['measure_seconds']}s measured."
    )
    lines.append("")
    lines.append(
        "These are naive, from-scratch, **unoptimized** implementations. The numbers "
        "show language/runtime overhead on identical ARX code, not how fast "
        "cryptography can go (a tuned library with SIMD is far faster). Not a language "
        "speed contest. Each value is the **peak throughput** over many batches (the "
        "fastest batch is the reproducible rate, since scheduling jitter and frequency "
        "scaling only ever slow a batch). Regenerate with `./run.sh`."
    )
    lines.append("")
    header = "| Implementation | " + " | ".join(BENCH_LABELS[b] for b in BENCHES) + " |"
    sep = "| --- | " + " | ".join("---:" for _ in BENCHES) + " |"
    lines.append(header)
    lines.append(sep)
    for impl in present:
        cells = []
        for b in BENCHES:
            v = by.get((impl, b))
            cells.append(f"{v:.1f}" if v is not None else "-")
        lines.append(f"| {IMPL_LABELS[impl]} | " + " | ".join(cells) + " |")
    lines.append("")

    with open(out_md, "w") as f:
        f.write("\n".join(lines))

    print(f"wrote {out_json} and {out_md} ({len(rows)} measurements, {len(present)} implementations)")


if __name__ == "__main__":
    main()
