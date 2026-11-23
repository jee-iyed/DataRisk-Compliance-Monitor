"""KPI : performance du DISPOSITIF (outils + processus). Ils répondent à "travaille-t-on bien ?".

Toutes les fonctions sont pures : DataFrames en entrée, nombres / DataFrames en sortie.
Les pourcentages sont exprimés de 0 à 100 ; une division par zéro renvoie None (pas de faux 0 %).
"""

from __future__ import annotations

import pandas as pd

from datarisk.constants import ACTIVE_STATUSES, CLOSED_STATUSES, FALSE_POSITIVE, OPEN, REMEDIATED


def pct(num: float, den: float) -> float | None:
    return round(100.0 * num / den, 1) if den else None


def coverage(scan_coverage: pd.DataFrame, scope: dict[str, list[str]], start: pd.Timestamp,
             end: pd.Timestamp) -> dict:
    """Couverture = périmètres (entité x périmètre) scannés au moins une fois sur [start, end[
    / périmètres attendus dans `scope`."""
    expected = {(e, p) for e, perims in scope.items() for p in perims}
    window = scan_coverage[(scan_coverage["scan_date"] >= start) & (scan_coverage["scan_date"] < end)]
    scanned = set(zip(window["entity_id"], window["perimeter_id"], strict=True)) & expected
    return {"scanned": len(scanned), "expected": len(expected), "coverage_pct": pct(len(scanned), len(expected)),
            "missing": sorted(f"{e}/{p}" for e, p in expected - scanned)}


def noise_reduction(raw_alerts: pd.DataFrame, start: pd.Timestamp | None = None,
                    end: pd.Timestamp | None = None) -> dict:
    """Alertes brutes reçues sur la fenêtre -> nb d'incidents distincts auxquels elles se rattachent."""
    df = raw_alerts
    if start is not None:
        df = df[df["last_seen"] >= start]
    if end is not None:
        df = df[df["last_seen"] < end]
    n_raw, n_inc = len(df), df["incident_id"].nunique()
    return {"raw_alerts": n_raw, "incidents": n_inc,
            "noise_reduction_pct": pct(n_raw - n_inc, n_raw)}


def corroboration_rate(incident_sources: pd.DataFrame) -> float | None:
    """% d'incidents vus par au moins 2 sources distinctes (doublons inter-sources)."""
    n_sources = incident_sources.groupby("incident_id")["source_id"].nunique()
    return pct((n_sources >= 2).sum(), len(n_sources))


def fp_rate(state: pd.DataFrame) -> float | None:
    """Taux de FP = incidents qualifiés faux positifs / incidents qualifiés (remédiés, FP, exceptions)."""
    qualified = state[state["status"].isin(CLOSED_STATUSES)]
    return pct((qualified["status"] == FALSE_POSITIVE).sum(), len(qualified))


def fp_rate_by(state: pd.DataFrame, incident_sources: pd.DataFrame, key: str) -> pd.DataFrame:
    """Taux de FP par source (`source_id`), par règle (`rule_id`) ou par type (`alert_type`).
    Un incident vu par 2 sources compte pour chacune : c'est la règle qui a "tiré" qu'on évalue."""
    qualified = state[state["status"].isin(CLOSED_STATUSES)][["incident_id", "status", "alert_type"]]
    if key in qualified.columns:
        df = qualified
    else:
        df = qualified.merge(incident_sources[["incident_id", "source_id", "rule_id"]].drop_duplicates(),
                             on="incident_id")
    out = (df.assign(is_fp=df["status"] == FALSE_POSITIVE)
             .groupby(key).agg(qualified=("incident_id", "nunique"), false_positives=("is_fp", "sum")))
    out["fp_rate_pct"] = (100 * out["false_positives"] / out["qualified"]).round(1)
    return out.reset_index().sort_values(["false_positives", "fp_rate_pct"], ascending=False)


def mttr(cycles: pd.DataFrame, by: str | None = "priority") -> pd.DataFrame:
    """MTTR (jours) moyen et médian des cycles REMÉDIÉS, global ou par priorité de clôture."""
    done = cycles[cycles["outcome"] == REMEDIATED].copy()
    done["days"] = (done["closed_at"] - done["opened_at"]).dt.total_seconds() / 86400
    grouped = done.groupby(by) if by else done.assign(_all="ALL").groupby("_all")
    out = grouped["days"].agg(n="count", mean_days="mean", median_days="median").round(1)
    return out.reset_index().rename(columns={"_all": "scope"})


def sla_compliance(cycles: pd.DataFrame) -> float | None:
    """% de cycles remédiés avant l'échéance SLA (échéance fixée à l'ouverture, resserrée si la
    priorité monte)."""
    done = cycles[cycles["outcome"] == REMEDIATED]
    return pct((done["closed_at"] <= done["sla_due"]).sum(), len(done))


def backlog(state: pd.DataFrame, as_of: pd.Timestamp) -> dict:
    """Incidents à traiter (Ouverte / Assignée / En cours) et âge du cycle en cours, en jours."""
    active = state[state["status"].isin(ACTIVE_STATUSES)]
    age = (as_of - active["opened_at"]).dt.total_seconds() / 86400
    return {"backlog": len(active),
            "mean_age_days": round(float(age.mean()), 1) if len(age) else None,
            "max_age_days": round(float(age.max()), 1) if len(age) else None,
            "by_priority": active["priority"].value_counts().sort_index().to_dict()}


def open_sla_breaches(state: pd.DataFrame, as_of: pd.Timestamp) -> int:
    active = state[state["status"].isin(ACTIVE_STATUSES)]
    return int((active["sla_due"] < as_of).sum())


def reopen_rate(history: pd.DataFrame, as_of: pd.Timestamp | None = None) -> float | None:
    """Réouvertures (Remédiée -> Ouverte) / remédiations. Mesure la qualité des corrections."""
    h = history if as_of is None else history[history["changed_at"] <= as_of]
    reopens = ((h["from_status"] == REMEDIATED) & (h["to_status"] == OPEN)).sum()
    remediations = (h["to_status"] == REMEDIATED).sum()
    return pct(reopens, remediations)
