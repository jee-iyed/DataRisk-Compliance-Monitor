"""KRI : niveau de RISQUE résiduel. Ils répondent à "à quel point sommes-nous exposés ?".

Ne comptent que les incidents À TRAITER (Ouverte / Assignée / En cours). Les exceptions acceptées
sont un risque ACCEPTÉ : suivies à part (accepted_risks), pas mélangées au risque subi.
"""

from __future__ import annotations

import pandas as pd

from datarisk.constants import ACTIVE_STATUSES, EXCEPTION, PERSONAL_CATEGORIES


def active(state: pd.DataFrame) -> pd.DataFrame:
    return state[state["status"].isin(ACTIVE_STATUSES)]


def c3_exposed_public_external(state: pd.DataFrame) -> int:
    """Actifs C3 exposés publiquement ou à des externes (actifs distincts)."""
    a = active(state)
    hit = a[(a["classification"] == "C3") & a["alert_type"].isin(["PUBLIC_EXPOSURE", "EXTERNAL_SHARING"])]
    return int(hit["asset_id"].nunique())


def unencrypted_personal_records(state: pd.DataFrame) -> int:
    """Volume d'enregistrements personnels (personnelle, bancaire, art. 9) stockés non chiffrés.
    Dédupliqué par actif pour ne pas compter deux fois le même fichier."""
    a = active(state)
    hit = a[(a["alert_type"] == "UNENCRYPTED") & a["rgpd_category"].isin(PERSONAL_CATEGORIES)]
    return int(hit.drop_duplicates("asset_id")["record_count"].sum())


def open_exposed_secrets(state: pd.DataFrame) -> int:
    """Secrets exposés non révoqués (incident EXPOSED_SECRET non remédié)."""
    return int((active(state)["alert_type"] == "EXPOSED_SECRET").sum())


def retention_exceeded(state: pd.DataFrame) -> int:
    """Données conservées au-delà de la durée prévue (RGPD art. 5.1.e)."""
    return int((active(state)["alert_type"] == "RETENTION_EXCEEDED").sum())


def p1_over_sla(state: pd.DataFrame, as_of: pd.Timestamp) -> int:
    a = active(state)
    return int(((a["priority"] == "P1") & (a["sla_due"] < as_of)).sum())


def risk_index(state: pd.DataFrame, by: str | None = None) -> float | pd.Series:
    """Indice de risque = somme des scores des incidents à traiter / 100
    (1 point ~ 1 incident de score 100). Agrégeable par entité ou par périmètre."""
    a = active(state)
    if by is None:
        return round(float(a["risk_score"].sum()) / 100, 1)
    return (a.groupby(by)["risk_score"].sum() / 100).round(1)


def accepted_risks(state: pd.DataFrame) -> int:
    return int((state["status"] == EXCEPTION).sum())


def rag(value: float | None, threshold: dict) -> str:
    """Statut vert / orange / rouge selon les seuils de config.yaml."""
    if value is None:
        return "n/a"
    if threshold["direction"] == "lower_is_better":
        return "vert" if value <= threshold["green"] else "orange" if value <= threshold["amber"] else "rouge"
    return "vert" if value >= threshold["green"] else "orange" if value >= threshold["amber"] else "rouge"
