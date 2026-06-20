#!/usr/bin/env python3
"""Gota HTML report. Fills in report_template.html to produce a finished,
self-contained, format-aware viewer for the results.json that the harness writes.

This file (and report_template.html) is a copy from Gota
(https://github.com/alleato-llc/gota); change it there and re-copy. See README.md.

The presentation lives in `report_template.html` (HTML/CSS/JS); this script only
substitutes three tokens into it (the title, the embedded data, the date) and writes
the result. To restyle the report, edit the template, not this file.

The output is one standalone .html file (no network, no build step) that:
  - has a file picker to load any results.json produced by Gota, and
  - if you pass a results.json on the command line, embeds it so the page renders
    immediately on open (you can still load a different file from the picker).

It is generic over the format, not over your project: the page shows only what the
results.json carries (the impl/bench/mbps rows plus the machine/date/params
provenance). Pass a title if you want one; otherwise it is generic.

    python3 report.py                       # empty viewer, load a file in-browser
    python3 report.py results.json          # embed data, write report.html
    python3 report.py results.json -o out.html --title "My project throughput"
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

TEMPLATE_PATH = Path(__file__).resolve().parent / "report_template.html"


def build_html(doc: dict | None, title: str, template: str | None = None) -> str:
    """Fill the template's three tokens. `template` defaults to report_template.html
    next to this script; pass your own string to use a different template."""
    if template is None:
        template = TEMPLATE_PATH.read_text()
    return (
        template.replace("__DATA__", json.dumps(doc) if doc is not None else "null")
        .replace("__TITLE__", title)
        .replace("__GENERATED__", datetime.date.today().isoformat())
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a standalone HTML viewer for a Gota results.json.")
    ap.add_argument("results", nargs="?", help="results.json to embed (optional; otherwise the viewer starts empty)")
    ap.add_argument("-o", "--out", default="report.html", help="output HTML file (default: report.html)")
    ap.add_argument("--title", default="Gota benchmark report", help="report title")
    ap.add_argument("--template", help="custom HTML template (default: report_template.html beside this script)")
    args = ap.parse_args()

    doc = None
    if args.results:
        doc = json.loads(Path(args.results).read_text())

    template = Path(args.template).read_text() if args.template else None
    Path(args.out).write_text(build_html(doc, args.title, template))
    src = args.results if args.results else "(empty viewer)"
    print(f"wrote {args.out} from {src}", file=sys.stderr)


if __name__ == "__main__":
    main()
