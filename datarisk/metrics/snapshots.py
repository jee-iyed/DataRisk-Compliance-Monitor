"""Indicateurs à une date + photo hebdomadaire (metric_snapshots) pour les tendances.

Conventions :
- indicateurs de FLUX (alertes reçues, nouveaux incidents, remédiations, réduction du bruit,
  couverture) : calculés sur la fenêtre [window_start, as_of[ ;
- indicateurs de STOCK (backlog, KRI) : état à `as_of` ;
- indicateurs de QUALITÉ (taux de FP, MTTR, respect SLA, réouvertures) : cumulés depuis le début.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pandas as pd

from datarisk.constants import REMEDIATED
from datarisk.metrics import kpi, kri
from datarisk.metrics.state import remediation_cycles, state_as_of

KPI_KEYS = ["coverage_pct", "raw_alerts", "noise_reduction_pct", "new_incidents", "remediated",
            "fp_rate_pct", "mttr_mean_days", "mttr_median_days", "sla_compliance_pct", "backlog",
            "backlog_mean_age_days", "open_sla_breaches", "reopen_rate_pct"]
KRI_KEYS = ["c3_exposed_public_external", "unencrypted_personal_records", "open_exposed_secrets",
            "retention_exceeded", "p1_over_sla", "risk_index", "accepted_risks"]


def indicators(frames: dict[str, pd.DataFrame], cfg: dict, as_of: pd.Timestamp,
               window_start: pd.Timestamp) -> dict:
    history = frames["status_history"]
    st = state_as_of(frames["incidents"], history, as_of)
    cycles = remediation_cycles(history, as_of)
    window = history[(history["changed_at"] >= window_start) & (history["changed_at"] < as_of)]
    noise = kpi.noise_reduction(frames["raw_alerts"], window_start, as_of)
    overall = kpi.mttr(cycles, by=None)
    bl = kpi.backlog(st, as_of)
    return {
        "coverage_pct": kpi.coverage(frames["scan_coverage"], cfg["scope"], window_start, as_of)["coverage_pct"],
        "raw_alerts": noise["raw_alerts"],
        "noise_reduction_pct": noise["noise_reduction_pct"],
        "new_incidents": int(window["from_status"].isna().sum()),
        "remediated": int((window["to_status"] == REMEDIATED).sum()),
        "fp_rate_pct": kpi.fp_rate(st),
        "mttr_mean_days": float(overall["mean_days"].iloc[0]) if len(overall) else None,
        "mttr_median_days": float(overall["median_days"].iloc[0]) if len(overall) else None,
        "sla_compliance_pct": kpi.sla_compliance(cycles),
        "backlog": bl["backlog"],
        "backlog_mean_age_days": bl["mean_age_days"],
        "open_sla_breaches": kpi.open_sla_breaches(st, as_of),
        "reopen_rate_pct": kpi.reopen_rate(history, as_of),
        "c3_exposed_public_external": kri.c3_exposed_public_external(st),
        "unencrypted_personal_records": kri.unencrypted_personal_records(st),
        "open_exposed_secrets": kri.open_exposed_secrets(st),
        "retention_exceeded": kri.retention_exceeded(st),
        "p1_over_sla": kri.p1_over_sla(st, as_of),
        "risk_index": kri.risk_index(st),
        "accepted_risks": kri.accepted_risks(st),
    }


def period_bounds(cfg: dict) -> tuple[pd.Timestamp, int]:
    return pd.Timestamp(cfg["simulation"]["start_date"]), int(cfg["simulation"]["weeks"])


def weekly_snapshots(frames: dict[str, pd.DataFrame], cfg: dict) -> list[dict]:
    """1 photo par fin de semaine : indicateurs globaux + indice de risque / backlog par entité et périmètre."""
    start, weeks = period_bounds(cfg)
    rows: list[dict] = []
    for k in range(weeks):
        as_of = start + timedelta(weeks=k + 1)
        day = (as_of - timedelta(days=1)).date().isoformat()   # dimanche
        values = indicators(frames, cfg, as_of, as_of - timedelta(weeks=1))
        rows += [{"snapshot_date": day, "scope_type": "global", "scope_value": "ALL", "metric": m, "value": v}
                 for m, v in values.items()]
        st = state_as_of(frames["incidents"], frames["status_history"], as_of)
        act = kri.active(st)
        for scope_type, column, keys in (("entity", "entity_id", cfg["entities"]),
                                         ("perimeter", "perimeter_id", cfg["scope"]["BQA"])):
            risk = kri.risk_index(st, by=column)
            counts = act[column].value_counts()
            p1 = act[act["priority"] == "P1"][column].value_counts()
            for key in keys:
                for metric, series in (("risk_index", risk), ("backlog", counts), ("p1_open", p1)):
                    rows.append({"snapshot_date": day, "scope_type": scope_type, "scope_value": key,
                                 "metric": metric, "value": float(series.get(key, 0))})
    return rows


def snapshot_frame(snapshots: pd.DataFrame, scope_type: str = "global", scope_value: str = "ALL") -> pd.DataFrame:
    """Snapshots en format large : 1 ligne par date, 1 colonne par indicateur."""
    df = snapshots[(snapshots["scope_type"] == scope_type) & (snapshots["scope_value"] == scope_value)]
    return df.pivot(index="snapshot_date", columns="metric", values="value").sort_index()


def as_timestamp(value: str | datetime) -> pd.Timestamp:
    return pd.Timestamp(value)
