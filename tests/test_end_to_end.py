"""Bout en bout sur la simulation seed 42 : déterminisme, cohérence avec la vérité terrain,
requêtes SQL documentées, snapshots et génération de rapport."""

from __future__ import annotations

import csv
import hashlib
import re
from datetime import date
from pathlib import Path

import pandas as pd

from datarisk.ingestion.normalize import looks_unmasked
from datarisk.reporting.report import build_context, period_window, render_html, render_markdown, trend
from datarisk.simulator.exports import Exporter
from datarisk.simulator.world import World

ROOT = Path(__file__).resolve().parent.parent


def digest(folder: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            h.update(path.name.encode() + path.read_bytes())
    return h.hexdigest()


def test_simulation_is_reproducible(tmp_path, cfg, simulated):
    world = World(cfg, 42)
    world.build()
    Exporter(world).write(tmp_path / "raw")
    assert digest(tmp_path / "raw") == digest(simulated["raw"])


def test_every_row_is_either_normalized_or_quarantined(simulated):
    ing = simulated["result"].ingest
    rejected = pd.Series([r["source"] for r in ing.rejected]).value_counts()
    accepted = pd.Series([a.source for a in ing.alerts]).value_counts()
    for source in ("dspm_vendor_a", "dspm_vendor_b"):   # 1 ligne = 1 alerte pour ces sources
        assert accepted[source] + rejected.get(source, 0) == ing.rows_read[source]
    assert all(r["reason"] for r in ing.rejected)


def test_incidents_match_ground_truth(simulated):
    """Aucun incident 'fantôme' : chaque empreinte consolidée correspond à un vrai problème simulé,
    malgré 3 formats de chemins différents (preuve que la canonisation fonctionne)."""
    with open(simulated["raw"] / "ground_truth.csv", encoding="utf-8") as fh:
        truth = {row["fingerprint"]: row for row in csv.DictReader(fh)}
    incidents = simulated["result"].incidents
    assert {i.fingerprint for i in incidents} <= set(truth)
    multi = [i for i in incidents if len(i.source_names) > 1]
    assert len(multi) > 50                                  # doublons inter-sources effectivement fusionnés


def test_no_unmasked_sample_reaches_the_database(simulated):
    samples = simulated["frames"]["raw_alerts"]["masked_sample"]
    assert not any(looks_unmasked(s) for s in samples)
    assert simulated["frames"]["rejected_alerts"]["raw_record"].str.contains("6000011234567890189").sum() == 0


def test_documented_sql_queries_all_run(simulated):
    sql = (ROOT / "docs" / "queries.sql").read_text(encoding="utf-8")
    blocks = re.split(r"\n(?=-- Q\d+\.)", sql)[1:]
    assert len(blocks) == 10
    for block in blocks:
        rows = simulated["conn"].execute(block.strip().rstrip(";")).fetchall()
        assert rows, block.splitlines()[0]


def test_weekly_snapshots_show_campaign_effect(simulated, cfg):
    snaps = simulated["frames"]["metric_snapshots"]
    glob = snaps[snaps["scope_type"] == "global"].pivot(index="snapshot_date", columns="metric", values="value")
    assert len(glob) == cfg["simulation"]["weeks"]
    campaign_week = cfg["simulation"]["campaign_weeks"][0] - 1
    assert glob["remediated"].iloc[campaign_week] == glob["remediated"].max()
    assert glob["risk_index"].iloc[-1] < glob["risk_index"].max()


def test_period_window_and_trend():
    start, end, prev = period_window("weekly", date(2026, 11, 22))
    assert (start, end, prev) == (pd.Timestamp("2026-11-16"), pd.Timestamp("2026-11-23"), pd.Timestamp("2026-11-09"))
    start, end, prev = period_window("monthly", date(2026, 10, 31))
    assert (start, end, prev) == (pd.Timestamp("2026-10-01"), pd.Timestamp("2026-11-01"), pd.Timestamp("2026-09-01"))
    assert trend(5, 8, "lower_is_better") == {"arrow": "↓", "delta": -3, "judgement": "amélioration"}
    assert trend(70, 80, "higher_is_better")["judgement"] == "dégradation"
    assert trend(None, 3, None)["arrow"] == "–"


def test_report_generation(simulated, cfg):
    ctx = build_context(simulated["frames"], cfg, "weekly", date(2026, 11, 22))
    assert len(ctx["summary"]) == 5 and ctx["recommendations"]
    md, html = render_markdown(ctx), render_html(ctx)
    for section in ("Synthèse direction", "KPI / KRI vs période précédente", "Top incidents P1 / P2",
                    "Dépassements de SLA", "Règles les plus bruyantes", "Recommandations", "Méthodologie"):
        assert section in md and section in html
    assert "FICTIVES" in md and "<table>" in html
