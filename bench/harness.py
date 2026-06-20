"""Generic micro-benchmark orchestration framework.

This file is a copy of `harness.py` from Gota (https://github.com/alleato-llc/gota),
the standalone cross-language micro-benchmark reference; only this docstring is
adapted. Do not edit the code here: change it in Gota and re-copy, so the two stay in
sync. Nothing in it is dorado-specific. It runs a list of `RunnerSpec`s (each builds
itself and emits JSON lines of {"impl","bench","mbps","iters"}), collects the rows,
and writes a results.json plus a Markdown table. The dorado-specific configuration
(which runners, the row/column labels, the framing text) lives in run.py, which
imports these functions. See README.md for the protocol and provenance.
"""

from __future__ import annotations

import dataclasses
import json
import platform
import shutil
import subprocess
import sys
from typing import Callable, Optional


def which(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


@dataclasses.dataclass
class RunnerSpec:
    """One benchmark runner.

    `prepare` builds/sets up the runner and returns the argv to invoke it (the three
    protocol parameters are appended by the harness), or None if the runner is
    unavailable (a missing toolchain) and should be skipped. It may raise on a build
    failure; the harness logs and skips.
    """

    name: str
    prepare: Callable[[], Optional[list[str]]]


def run_all(specs: list[RunnerSpec], buf: int, warmup: float, measure: float) -> list[dict]:
    """Build and run each available runner with identical parameters; collect the
    JSON-line results. Each runner's stdout is captured separately, so there is no
    shared-output ordering or interleaving."""
    rows: list[dict] = []
    for spec in specs:
        try:
            argv = spec.prepare()
        except Exception as e:  # build failure, etc.
            log(f"  {spec.name}: prepare failed ({e}), skipping")
            continue
        if argv is None:
            log(f"  {spec.name}: unavailable, skipping")
            continue
        log(f"  {spec.name}: running")
        proc = subprocess.run(
            [*argv, str(buf), str(warmup), str(measure)],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            log(f"  {spec.name}: runner exited {proc.returncode}; stderr:\n{proc.stderr.strip()}")
            continue
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                rows.append(json.loads(line))
    return rows


def gather_metadata() -> dict:
    """Machine, OS, date, and git commit, for provenance in the results."""
    machine = "unknown"
    try:
        if platform.system() == "Darwin":
            machine = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"], text=True
            ).strip()
        else:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("model name"):
                        machine = line.split(":", 1)[1].strip()
                        break
    except Exception:
        pass
    commit = "unknown"
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        pass
    return {
        "machine": machine,
        "os": f"{platform.system()} {platform.machine()}",
        "date": subprocess.check_output(["date", "+%Y-%m-%d"], text=True).strip(),
        "git_commit": commit,
    }


def build_results_doc(rows: list[dict], *, params: dict, meta: dict, units: str) -> dict:
    """The results.json document: provenance + params + the raw measurement rows.
    This is the canonical, tooling-friendly shape; feed it to your own pipeline (a
    dashboard, a database, the HTML viewer) instead of the Markdown if you prefer."""
    return {**meta, "params": params, "units": units, "results": rows}


def render_markdown(
    rows: list[dict],
    *,
    intro: str,
    impl_order: list[str],
    impl_labels: dict[str, str],
    bench_order: list[str],
    bench_labels: dict[str, str],
) -> str:
    """Render the results as a Markdown table and return it as a string (so callers can
    route it anywhere: a file, a PR comment, a docs page). Orderings and labels are
    supplied by the caller, so this stays generic."""
    by = {(r["impl"], r["bench"]): r["mbps"] for r in rows}
    present = [i for i in impl_order if any(r["impl"] == i for r in rows)]

    lines = ["# Benchmark results", "", intro.strip(), ""]
    lines.append("| Implementation | " + " | ".join(bench_labels[b] for b in bench_order) + " |")
    lines.append("| --- | " + " | ".join("---:" for _ in bench_order) + " |")
    for impl in present:
        cells = []
        for b in bench_order:
            v = by.get((impl, b))
            cells.append(f"{v:.1f}" if v is not None else "-")
        lines.append(f"| {impl_labels[impl]} | " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)


def _write(target, text: str) -> str:
    """Write `text` to a path (str/Path) or an already-open writable stream (anything
    with a `.write`, e.g. sys.stdout, an io.StringIO, an HTTP response body). Returns a
    display name for logging."""
    if hasattr(target, "write"):
        target.write(text)
        return getattr(target, "name", "<stream>")
    with open(target, "w") as f:
        f.write(text)
    return str(target)


def write_results(
    rows: list[dict],
    out_json,
    out_md,
    *,
    params: dict,
    meta: dict,
    units: str,
    impl_order: list[str],
    impl_labels: dict[str, str],
    bench_order: list[str],
    bench_labels: dict[str, str],
    intro: str,
) -> None:
    """Convenience: write results.json (raw + provenance) and a Markdown table.

    `out_json` and `out_md` may each be a path or an open writable stream, so the
    output can go to files or straight into your own tooling. To integrate more
    deeply, skip this and use `build_results_doc` / `render_markdown` directly, or just
    consume the list of row dicts that `run_all` returns."""
    json_name = _write(out_json, json.dumps(build_results_doc(rows, params=params, meta=meta, units=units), indent=2) + "\n")
    md_name = _write(
        out_md,
        render_markdown(
            rows,
            intro=intro,
            impl_order=impl_order,
            impl_labels=impl_labels,
            bench_order=bench_order,
            bench_labels=bench_labels,
        ),
    )
    present = len([i for i in impl_order if any(r["impl"] == i for r in rows)])
    log(f"wrote {json_name} and {md_name} ({len(rows)} measurements, {present} implementations)")
