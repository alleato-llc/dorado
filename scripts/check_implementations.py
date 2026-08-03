#!/usr/bin/env python3
"""Assert every list of dorado's implementations agrees with implementations.json.

The same list lives in a lot of places: the port directories, the landing page, the
docs' counts, the benchmark orchestrator, and the CI workflow. `implementations.json`
is canonical -- the page *derives* its comparison table and CLI-language lists from it,
so the page cannot drift -- and this script checks everything that cannot be derived,
because a GitHub Actions job must be static YAML and prose is prose.

It exists because the benchmark silently measured 7 of 9 implementations for six weeks:
`bench/` predated the Haskell and C++ ports and nothing noticed. A missing entry here is
not cosmetic -- it means a published table quietly under-reports the project.

Run it directly (`python3 scripts/check_implementations.py`); it prints every problem it
finds, not just the first, and exits non-zero if there are any. Stdlib only.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NUMBER_WORDS = {
    1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
    7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve",
}

# Docs that state the count in prose. CLAUDE.md is included because it said "ten"
# while listing nine directories in the sentence above it, which is exactly the kind of
# quiet drift this script exists to catch.
COUNTED_DOCS = ("README.md", "docs/implementations.md", "CLAUDE.md")

problems: list[str] = []


def problem(where: str, msg: str) -> None:
    problems.append(f"{where}: {msg}")


def check_directories(impls: list[dict]) -> None:
    for impl in impls:
        port = ROOT / impl["dir"]
        if not port.is_dir():
            problem("repo", f"{impl['id']}: no {impl['dir']}/ directory")


def check_bench(impls: list[dict]) -> None:
    """Every implementation marked `benched` must actually be wired into bench/run.py.

    This is the check that would have caught the C++/Haskell gap the day it opened.
    """
    text = (ROOT / "bench" / "run.py").read_text()
    order = re.search(r"^IMPL_ORDER = \[(.*?)\]", text, re.MULTILINE | re.DOTALL)
    listed = set(re.findall(r'"([^"]+)"', order.group(1))) if order else set()

    for impl in impls:
        if not impl.get("benched"):
            continue
        ident = impl["id"]
        if f'RunnerSpec("{ident}"' not in text:
            problem("bench/run.py", f"{ident}: no RunnerSpec (its numbers are missing)")
        if ident not in listed:
            problem("bench/run.py", f"{ident}: not in IMPL_ORDER (no table row)")
        if not (ROOT / "bench" / ident).is_dir():
            problem("bench/", f"{ident}: no bench/{ident}/ runner")


def check_workflow(impls: list[dict]) -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    for impl in impls:
        ident = impl["id"]
        # Most jobs are named for the port; Rust's is "core" (fmt/clippy/test), so the
        # manifest may name the job explicitly.
        job = impl.get("ci_job", ident)
        if not re.search(rf"^  {re.escape(job)}:$", text, re.MULTILINE):
            problem("ci.yml", f"{ident}: no job (expected `{job}:`)")
        # The paths filter is always keyed by the port id, whatever the job is called.
        if not re.search(rf"^\s+{re.escape(ident)}:$", text, re.MULTILINE):
            problem("ci.yml", f"{ident}: no paths-filter entry")


def check_docs(impls: list[dict]) -> None:
    """The prose counts ("nine implementations") must match the manifest."""
    word = NUMBER_WORDS.get(len(impls), str(len(impls)))
    for rel in COUNTED_DOCS:
        text = (ROOT / rel).read_text()
        if f"{word} implementations" not in text:
            problem(rel, f'says neither "{word} implementations" nor an updated count')

    stale = [w for n, w in NUMBER_WORDS.items() if n != len(impls)]
    for rel in COUNTED_DOCS:
        text = (ROOT / rel).read_text()
        for old in stale:
            if f"{old} implementations" in text:
                problem(rel, f'stale count: "{old} implementations"')


def check_page_is_derived() -> None:
    """Guard against someone re-hardcoding the list the page used to carry."""
    text = (ROOT / "web" / "src" / "pages" / "index.astro").read_text()
    if "implementations.json" not in text:
        problem("web/src/pages/index.astro", "no longer imports implementations.json")
    if re.search(r"^const cmpRows = \[", text, re.MULTILINE):
        problem(
            "web/src/pages/index.astro",
            "cmpRows is a literal again; it must be derived from the manifest",
        )


def main() -> int:
    manifest = json.loads((ROOT / "implementations.json").read_text())
    impls = manifest["implementations"]

    ids = [i["id"] for i in impls]
    if len(ids) != len(set(ids)):
        problem("implementations.json", "duplicate id")

    check_directories(impls)
    check_bench(impls)
    check_workflow(impls)
    check_docs(impls)
    check_page_is_derived()

    if problems:
        print(f"implementations.json lists {len(impls)}; found {len(problems)} disagreement(s):\n")
        for p in problems:
            print(f"  - {p}")
        print("\nAdding an implementation? See the checklist in CLAUDE.md.")
        return 1

    print(f"OK: {len(impls)} implementations agree across the repo, docs, bench, and CI.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
