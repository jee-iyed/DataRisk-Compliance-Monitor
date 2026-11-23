"""Consolidation : N détections (sources x semaines) -> 1 "incident de données".

Empreinte = sha256(chemin canonique de l'actif | type d'alerte). Elle est :
- indépendante de la source (les chemins sont canonisés à la normalisation) -> doublons inter-sources ;
- stable dans le temps -> les re-détections hebdomadaires retombent sur le même incident ;
- déterministe -> un outil tiers (ticketing, journal d'analystes) peut référencer l'incident par elle.

Attributs consolidés selon un principe de PRÉCAUTION : si deux sources divergent, on retient la
valeur la plus défavorable (classification la plus haute, exposition la plus large, etc.).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from datarisk.constants import (
    ACTIVE_STATUSES,
    CLASSIFICATIONS,
    CLOSED_STATUSES,
    EXCEPTION,
    EXPOSURES,
    FALSE_POSITIVE,
    REMEDIATED,
)
from datarisk.ingestion.normalize import RGPD_RANK, NormalizedAlert
from datarisk.prioritization.scoring import compute_score

if TYPE_CHECKING:
    from datarisk.governance.workflow import Workflow

EXPOSURE_RANK = {e: len(EXPOSURES) - i for i, e in enumerate(EXPOSURES)}   # public = le plus exposé


def fingerprint(asset_id: str, alert_type: str) -> str:
    return hashlib.sha256(f"{asset_id}|{alert_type}".encode()).hexdigest()[:16]


@dataclass
class Incident:
    incident_id: int
    fingerprint: str
    alert_type: str
    entity: str
    perimeter: str
    asset_id: str
    asset_path: str
    data_owner: str
    data_types: set[str]
    classification: str
    rgpd_category: str
    exposure: str
    encrypted: bool
    environment: str
    location: str
    in_eu: bool
    record_count: int
    max_severity: int
    first_seen: datetime
    last_seen: datetime
    status: str | None = None
    opened_at: datetime | None = None
    resolved_at: datetime | None = None
    assignee: str | None = None
    reopen_count: int = 0
    detection_count: int = 0
    suppressed_count: int = 0
    # (source, source_alert_id) -> {rule_id, first_seen, last_seen, detections}
    sources: dict[tuple[str, str], dict] = field(default_factory=dict)
    risk_score: float = 0.0
    priority: str = "P4"
    explanation: list[dict] = field(default_factory=list)
    sla_due: datetime | None = None

    @property
    def source_names(self) -> list[str]:
        return sorted({s for s, _ in self.sources})

    @property
    def lifecycle(self) -> str:
        """nouvelle / récurrente / réouverte / résolue (vue "cycle de vie" de la consolidation)."""
        if self.status in CLOSED_STATUSES:
            return "resolue"
        if self.reopen_count:
            return "reouverte"
        weeks_seen = (self.last_seen - self.first_seen).days // 7
        return "recurrente" if weeks_seen >= 1 else "nouvelle"


def merge_attributes(inc: Incident, a: NormalizedAlert) -> None:
    """Principe de précaution : on garde la valeur la plus défavorable."""
    if CLASSIFICATIONS.index(a.classification) > CLASSIFICATIONS.index(inc.classification):
        inc.classification = a.classification
    if RGPD_RANK[a.rgpd_category] > RGPD_RANK[inc.rgpd_category]:
        inc.rgpd_category = a.rgpd_category
    if EXPOSURE_RANK[a.exposure] > EXPOSURE_RANK[inc.exposure]:
        inc.exposure = a.exposure
    inc.encrypted = inc.encrypted and a.encrypted
    if a.environment == "dev":
        inc.environment = "dev"
    if not a.in_eu and inc.in_eu:
        inc.in_eu, inc.location = False, a.location
    inc.record_count = max(inc.record_count, a.record_count)
    inc.max_severity = max(inc.max_severity, a.normalized_severity)
    inc.data_types |= set(a.data_types)
    if inc.data_owner == "inconnu":
        inc.data_owner = a.data_owner


class Consolidator:
    def __init__(self, cfg: dict, workflow: Workflow) -> None:
        self.cfg = cfg
        self.workflow = workflow
        self.incidents: dict[str, Incident] = {}
        self.by_id: dict[int, Incident] = {}

    def rescore(self, inc: Incident, at: datetime) -> None:
        result = compute_score(
            alert_type=inc.alert_type, classification=inc.classification, rgpd_category=inc.rgpd_category,
            exposure=inc.exposure, record_count=inc.record_count, encrypted=inc.encrypted,
            environment=inc.environment, in_eu=inc.in_eu, source_count=len(inc.source_names),
            age_weeks=(at - inc.first_seen).days // 7, cfg=self.cfg)
        old = inc.priority
        inc.risk_score, inc.priority, inc.explanation = result.score, result.priority, result.contributions
        if inc.status is not None and old != inc.priority:
            self.workflow.on_priority_change(inc, at, old)

    def ingest(self, a: NormalizedAlert) -> tuple[Incident, str]:
        """Rattache une alerte normalisée à son incident. Renvoie (incident, issue) avec issue parmi :
        created, updated, reopened, suppressed_fp (faux positif déjà qualifié), under_exception."""
        fp = fingerprint(a.asset_id, a.alert_type)
        inc = self.incidents.get(fp)
        created = inc is None
        if inc is None:
            inc = Incident(
                incident_id=len(self.incidents) + 1, fingerprint=fp, alert_type=a.alert_type, entity=a.entity,
                perimeter=a.perimeter, asset_id=a.asset_id, asset_path=a.asset_path, data_owner=a.data_owner,
                data_types=set(a.data_types), classification=a.classification, rgpd_category=a.rgpd_category,
                exposure=a.exposure, encrypted=a.encrypted, environment=a.environment, location=a.location,
                in_eu=a.in_eu, record_count=a.record_count, max_severity=a.normalized_severity,
                first_seen=a.first_seen, last_seen=a.last_seen)
            self.incidents[fp] = inc
            self.by_id[inc.incident_id] = inc
        else:
            merge_attributes(inc, a)
            inc.first_seen = min(inc.first_seen, a.first_seen)
            inc.last_seen = max(inc.last_seen, a.last_seen)

        src = inc.sources.setdefault((a.source, a.source_alert_id), {
            "rule_id": a.rule_id, "first_seen": a.first_seen, "last_seen": a.last_seen, "detections": 0})
        src["last_seen"] = max(src["last_seen"], a.last_seen)
        src["detections"] += 1
        inc.detection_count += 1
        self.rescore(inc, a.last_seen)

        if created:
            self.workflow.open(inc, a.last_seen, f"détection initiale ({a.source})")
            return inc, "created"
        if inc.status == REMEDIATED and inc.resolved_at is not None and a.last_seen > inc.resolved_at:
            self.workflow.open(inc, a.last_seen, f"re-détection après remédiation ({a.source})")
            return inc, "reopened"
        if inc.status == FALSE_POSITIVE:
            inc.suppressed_count += 1
            return inc, "suppressed_fp"
        if inc.status == EXCEPTION:
            return inc, "under_exception"
        assert inc.status in ACTIVE_STATUSES or inc.status == REMEDIATED
        return inc, "updated"
