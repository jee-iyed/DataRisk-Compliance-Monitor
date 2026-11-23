"""Score de priorité 0-100 explicable et SLA de remédiation.

    score = base_points × sensibilité × exposition × volume  +  bonus      (borné à 100)

- sensibilité = poids de la classification (C0..C3) + bonus de catégorie RGPD, plafonné à 1
- exposition  = public 1.0 > externe 0.8 > groupe large 0.55 > restreint 0.3
- volume      = de min_factor (1 enregistrement) à 1.0 (>= reference_records), en échelle log
- bonus       = non chiffré (si >= C2), prod en dev, hors UE, secret, corroboré par >= 2 sources,
                persistance (1 pt / semaine, plafonné)

Déterministe : mêmes entrées -> même score, et chaque point est justifié dans `contributions`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class ScoreResult:
    score: float
    priority: str
    contributions: list[dict]    # [{"factor": ..., "points": ..., "detail": ...}]


def volume_factor(records: int, cfg: dict) -> float:
    vol = cfg["scoring"]["volume"]
    ratio = min(1.0, math.log10(1 + max(0, records)) / math.log10(1 + vol["reference_records"]))
    return round(vol["min_factor"] + (1 - vol["min_factor"]) * ratio, 3)


def priority_for(score: float, cfg: dict) -> str:
    for level, threshold in sorted(cfg["scoring"]["priorities"].items(), key=lambda kv: -kv[1]):
        if score >= threshold:
            return level
    return "P4"


def compute_score(*, alert_type: str, classification: str, rgpd_category: str, exposure: str,
                  record_count: int, encrypted: bool, environment: str, in_eu: bool,
                  source_count: int, age_weeks: int, cfg: dict) -> ScoreResult:
    sc = cfg["scoring"]
    sens = min(1.0, sc["classification"][classification] + sc["rgpd_bonus"][rgpd_category])
    expo = sc["exposure"][exposure]
    vol = volume_factor(record_count, cfg)
    base = round(sc["base_points"] * sens * expo * vol, 1)
    contributions = [{
        "factor": "base",
        "points": base,
        "detail": (f"{sc['base_points']} × sensibilité {sens:.2f} ({classification}, {rgpd_category}) "
                   f"× exposition {expo:.2f} ({exposure}) × volume {vol:.2f} ({record_count} enr.)"),
    }]
    b = sc["bonus"]

    def add(factor: str, points: float, detail: str) -> None:
        if points:
            contributions.append({"factor": factor, "points": points, "detail": detail})

    if not encrypted and classification in ("C2", "C3"):
        add("unencrypted", b["unencrypted"], "donnée >= C2 non chiffrée")
    if environment == "dev" and classification in ("C2", "C3"):
        add("prod_in_dev", b["prod_in_dev"], "donnée sensible en environnement de dev")
    if not in_eu and rgpd_category != "aucune":
        add("non_eu", b["non_eu"], "hébergement hors UE (transfert RGPD chap. V)")
    if alert_type == "EXPOSED_SECRET" or rgpd_category == "secret":
        add("secret", b["secret"], "secret / identifiant d'authentification")
    if source_count >= 2:
        add("corroborated", b["corroborated"], f"corroboré par {source_count} sources indépendantes")
    add("age", min(b["age_max"], b["age_per_week"] * max(0, age_weeks)),
        f"détecté de façon persistante depuis {age_weeks} semaine(s)")

    score = round(min(100.0, sum(c["points"] for c in contributions)), 1)
    return ScoreResult(score, priority_for(score, cfg), contributions)


def sla_due(opened_at: datetime, priority: str, cfg: dict) -> datetime:
    return opened_at + timedelta(days=cfg["sla_days"][priority])


def is_sla_breached(due: datetime, as_of: datetime, resolved_at: datetime | None = None) -> bool:
    """Dépassement : résolu après l'échéance, ou toujours ouvert après l'échéance."""
    return (resolved_at or as_of) > due
