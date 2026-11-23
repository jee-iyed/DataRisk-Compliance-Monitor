"""Calcule les snapshots hebdomadaires KPI/KRI et affiche les chiffres clés de la période.

Usage : python -m scripts.build_metrics [--db data/datarisk.db]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from datarisk.config import DB_PATH, load_config
from datarisk.metrics import kpi
from datarisk.metrics.kri import rag
from datarisk.metrics.snapshots import KPI_KEYS, KRI_KEYS, snapshot_frame, weekly_snapshots
from datarisk.metrics.state import remediation_cycles, state_as_of
from datarisk.storage.db import connect, load_frames, write_snapshots


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DB_PATH)
    args = parser.parse_args()

    cfg = load_config()
    conn = connect(args.db)
    frames = load_frames(conn)
    rows = weekly_snapshots(frames, cfg)
    write_snapshots(conn, rows)
    frames = load_frames(conn)
    wide = snapshot_frame(frames["metric_snapshots"])
    first, last = wide.iloc[0], wide.iloc[-1]

    print(f"Snapshots écrits : {len(rows)} lignes, {len(wide)} semaines ({wide.index[0]} -> {wide.index[-1]})\n")
    print(f"{'Indicateur':<30}{'S1':>12}{'S' + str(len(wide)):>12}   statut")
    for key in KPI_KEYS + KRI_KEYS:
        status = rag(last[key], cfg["thresholds"][key]) if key in cfg["thresholds"] else ""
        print(f"{key:<30}{first[key]:>12}{last[key]:>12}   {status}")
    peak = wide["backlog"].idxmax()
    print(f"\nPic de backlog : {int(wide['backlog'].max())} le {peak} ; "
          f"pic de l'indice de risque : {wide['risk_index'].max()} le {wide['risk_index'].idxmax()}")

    # Chiffres de période complète (12 semaines)
    inc, raw, isrc = frames["incidents"], frames["raw_alerts"], frames["incident_sources"]
    end = frames["status_history"]["changed_at"].max()
    st = state_as_of(inc, frames["status_history"], end)
    cycles = remediation_cycles(frames["status_history"])
    noise = kpi.noise_reduction(raw)
    print(f"\nPériode complète : {noise['raw_alerts']} alertes brutes -> {noise['incidents']} incidents "
          f"(réduction du bruit {noise['noise_reduction_pct']} %), corroboration multi-sources "
          f"{kpi.corroboration_rate(isrc)} %")
    print(f"Quarantaine : {len(frames['rejected_alerts'])} lignes ; taux de FP global {kpi.fp_rate(st)} %")
    print("\nMTTR par priorité (jours) :")
    print(kpi.mttr(cycles).to_string(index=False))
    print("\nTaux de FP par source :")
    print(kpi.fp_rate_by(st, isrc, "source_id").to_string(index=False))
    print("\nRègles les plus bruyantes :")
    print(kpi.fp_rate_by(st, isrc, "rule_id").head(5).to_string(index=False))


if __name__ == "__main__":
    main()
