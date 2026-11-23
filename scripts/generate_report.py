"""Génère un rapport périodique daté (Markdown + HTML) depuis la base.

Usage : python -m scripts.generate_report --period weekly|monthly --date AAAA-MM-JJ [--out reports]
"""

from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path

from datarisk.config import DB_PATH, REPORTS_DIR, load_config
from datarisk.reporting.report import build_context, render_html, render_markdown
from datarisk.storage.db import connect, load_frames


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--period", choices=["weekly", "monthly"], default="weekly")
    parser.add_argument("--date", type=date.fromisoformat, required=True, help="dernier jour de la période")
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--out", type=Path, default=REPORTS_DIR)
    args = parser.parse_args()

    cfg = load_config()
    frames = load_frames(connect(args.db))
    ctx = build_context(frames, cfg, args.period, args.date)
    args.out.mkdir(parents=True, exist_ok=True)
    stem = args.out / f"report_{args.period}_{args.date.isoformat()}"
    stem.with_suffix(".md").write_text(render_markdown(ctx), encoding="utf-8")
    stem.with_suffix(".html").write_text(render_html(ctx), encoding="utf-8")
    print(f"Rapport {args.period} {ctx['start']} -> {ctx['end']} : {stem}.md / .html")
    for line in ctx["summary"]:
        print(f"  - {line}")


if __name__ == "__main__":
    main()
