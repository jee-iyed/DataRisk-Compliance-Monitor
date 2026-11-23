"""Reconstitution de l'état à une date donnée à partir de la table d'audit (status_history).

Chaque ligne d'historique porte statut, priorité, score et échéance SLA au moment du changement :
on peut donc "remonter le temps" et calculer les indicateurs tels qu'ils étaient à n'importe quelle
date (c'est ce qui alimente les snapshots hebdomadaires et les comparaisons de période).
"""

from __future__ import annotations

import pandas as pd

from datarisk.constants import CLOSED_STATUSES, OPEN

STATE_COLUMNS = ["status", "priority", "risk_score", "sla_due", "opened_at"]


def state_as_of(incidents: pd.DataFrame, history: pd.DataFrame, as_of: pd.Timestamp) -> pd.DataFrame:
    """Incidents connus à `as_of`, avec statut / priorité / score / SLA / début de cycle à cette date."""
    h = history[history["changed_at"] <= as_of].sort_values(["incident_id", "changed_at", "id"])
    last = (h.groupby("incident_id").tail(1).set_index("incident_id")
            [["to_status", "priority", "risk_score", "sla_due"]].rename(columns={"to_status": "status"}))
    openings = h[(h["to_status"] == OPEN) & (h["from_status"].fillna("") != OPEN)]
    last["opened_at"] = openings.groupby("incident_id")["changed_at"].max()
    base = incidents.drop(columns=[c for c in STATE_COLUMNS if c in incidents.columns]).set_index("incident_id")
    return base.join(last, how="inner").reset_index()


def remediation_cycles(history: pd.DataFrame, as_of: pd.Timestamp | None = None) -> pd.DataFrame:
    """Un cycle = de l'ouverture (création, réouverture, fin d'exception) à la clôture suivante.

    Colonnes : incident_id, opened_at, closed_at (NaT si en cours), outcome (statut de clôture),
    priority et sla_due au moment de la clôture (ou de la dernière ligne connue).
    """
    h = history if as_of is None else history[history["changed_at"] <= as_of]
    h = h.sort_values(["incident_id", "changed_at", "id"])
    cycles: list[dict] = []
    current: dict | None = None
    current_id = None
    for row in h.itertuples(index=False):
        if row.incident_id != current_id:
            if current is not None:
                cycles.append(current)
            current, current_id = None, row.incident_id
        if row.to_status == OPEN and row.from_status != OPEN:
            if current is not None:
                cycles.append(current)
            current = {"incident_id": row.incident_id, "opened_at": row.changed_at, "closed_at": pd.NaT,
                       "outcome": None, "priority": row.priority, "sla_due": row.sla_due}
        elif current is not None:
            current["priority"], current["sla_due"] = row.priority, row.sla_due
            if row.to_status in CLOSED_STATUSES:
                current["closed_at"], current["outcome"] = row.changed_at, row.to_status
                cycles.append(current)
                current = None
    if current is not None:
        cycles.append(current)
    columns = ["incident_id", "opened_at", "closed_at", "outcome", "priority", "sla_due"]
    return pd.DataFrame(cycles, columns=columns)
