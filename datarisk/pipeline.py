"""Orchestration : rejoue chronologiquement alertes et actions analystes, comme en production.

    exports bruts --(connecteurs + normalisation)--> alertes normalisées  ┐
    journal d'actions analystes (workflow_events.csv) ───────────────────┤ tri chronologique
                                                                          ▼
         consolidation (empreinte) -> score/SLA -> workflow -> expiration des exceptions

Rejouer dans l'ordre du temps garantit que chaque décision (réouverture, suppression d'un faux
positif, expiration d'exception) est prise avec l'information disponible à cet instant.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from datarisk.consolidation.dedup import Consolidator, Incident
from datarisk.governance.workflow import InvalidTransition, Workflow
from datarisk.ingestion.connectors import IngestResult, load_sources
from datarisk.ingestion.normalize import NormalizedAlert


@dataclass
class PipelineResult:
    ingest: IngestResult
    incidents: list[Incident]
    workflow: Workflow
    raw_links: list[tuple[NormalizedAlert, int, str]]      # (alerte, incident_id, issue)
    workflow_rejects: list[dict] = field(default_factory=list)
    period_end: datetime | None = None


def period_end(cfg: dict) -> datetime:
    sim = cfg["simulation"]
    return datetime.fromisoformat(sim["start_date"]) + timedelta(weeks=int(sim["weeks"]))


def load_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    events = []
    with open(path, encoding="utf-8", newline="") as fh:
        for line_no, row in enumerate(csv.DictReader(fh), start=2):
            row["line_no"] = line_no
            row["event_time"] = datetime.fromisoformat(row["event_time"])
            row["expires_at"] = datetime.fromisoformat(row["expires_at"]) if row.get("expires_at") else None
            events.append(row)
    return events


def run_pipeline(cfg: dict, raw_dir: Path, datashield_db: Path | None = None,
                 as_of: datetime | None = None) -> PipelineResult:
    ingest = load_sources(raw_dir, cfg, datashield_db)
    events = load_events(raw_dir / "workflow_events.csv")
    end = as_of or period_end(cfg)

    # 0 = alerte, 1 = action analyste : à instant égal, l'alerte d'abord (l'incident doit exister)
    timeline: list[tuple[datetime, int, int, object]] = []
    timeline += [(a.last_seen, 0, i, a) for i, a in enumerate(ingest.alerts)]
    timeline += [(e["event_time"], 1, i, e) for i, e in enumerate(events)]
    timeline.sort(key=lambda x: x[:3])

    workflow = Workflow(cfg)
    cons = Consolidator(cfg, workflow)
    links: list[tuple[NormalizedAlert, int, str]] = []
    rejects: list[dict] = []

    for t, kind, _, item in timeline:
        if t > end and datashield_db is None:
            break
        workflow.expire_exceptions(cons.by_id, t)
        if kind == 0:
            assert isinstance(item, NormalizedAlert)
            inc, outcome = cons.ingest(item)
            links.append((item, inc.incident_id, outcome))
            continue
        assert isinstance(item, dict)
        target = cons.incidents.get(item["fingerprint"])
        try:
            if target is None:
                raise InvalidTransition("incident inconnu (empreinte jamais détectée)")
            workflow.apply(target, item["action"], t, item["actor"], assignee=item.get("assignee") or None,
                           justification=item.get("justification") or None,
                           approver=item.get("approver") or None, expires_at=item["expires_at"],
                           comment=item.get("comment") or None)
        except InvalidTransition as exc:
            rejects.append({"source": "workflow", "file": "workflow_events.csv", "line_no": item["line_no"],
                            "reason": str(exc), "raw_record": {k: str(v) for k, v in item.items()}})

    last = max([end] + [t for t, *_ in timeline]) if datashield_db is not None else end
    workflow.expire_exceptions(cons.by_id, last)
    return PipelineResult(ingest, list(cons.incidents.values()), workflow, links, rejects, last)
