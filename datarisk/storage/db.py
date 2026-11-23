"""Accès SQLite : création du schéma, écriture du résultat du pipeline, lecture en DataFrames."""

from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from datarisk.pipeline import PipelineResult

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
DATE_COLUMNS = {
    "incidents": ["first_seen", "last_seen", "opened_at", "resolved_at", "sla_due"],
    "raw_alerts": ["first_seen", "last_seen"],
    "status_history": ["changed_at", "sla_due"],
    "exceptions": ["granted_at", "expires_at"],
    "incident_sources": ["first_seen", "last_seen"],
    "scan_coverage": ["scan_date"],
    "metric_snapshots": ["snapshot_date"],
}


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") if dt else None


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str | Path, fresh: bool = True) -> sqlite3.Connection:
    path = Path(db_path)
    if fresh and path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def _read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def write_pipeline(conn: sqlite3.Connection, cfg: dict, result: PipelineResult, raw_dir: Path) -> None:
    now = iso(datetime.now())
    with conn:
        conn.executemany("INSERT INTO sources VALUES (?, ?)", cfg["sources"].items())
        conn.executemany("INSERT INTO entities VALUES (?, ?)", cfg["entities"].items())
        conn.executemany("INSERT INTO perimeters VALUES (?, ?)", cfg["perimeters"].items())
        owners = {r["owner_id"]: r for r in _read_csv(raw_dir / "owners.csv")}
        for inc in result.incidents:   # propriétaires remontés par les sources mais absents du référentiel
            owners.setdefault(inc.data_owner, {"owner_id": inc.data_owner, "entity": inc.entity,
                                               "display_name": None})
        conn.executemany("INSERT INTO owners VALUES (:owner_id, :entity, :display_name)", owners.values())
        conn.executemany(
            "INSERT INTO scan_coverage VALUES (:scan_date, :source, :entity, :perimeter, :assets_scanned)",
            _read_csv(raw_dir / "scan_coverage.csv"))

        conn.executemany(
            "INSERT INTO incidents VALUES (" + ",".join("?" * 33) + ")",
            [(i.incident_id, i.fingerprint, i.alert_type, i.entity, i.perimeter, i.asset_id, i.asset_path,
              i.data_owner, json.dumps(sorted(i.data_types)), i.classification, i.rgpd_category, i.exposure,
              int(i.encrypted), i.environment, i.location, int(i.in_eu), i.record_count, i.max_severity,
              iso(i.first_seen), iso(i.last_seen), i.status, i.lifecycle, iso(i.opened_at), iso(i.resolved_at),
              i.assignee, i.reopen_count, i.detection_count, i.suppressed_count, len(i.source_names),
              i.risk_score, i.priority, json.dumps(i.explanation, ensure_ascii=False), iso(i.sla_due),
              ) for i in result.incidents])
        conn.executemany(
            "INSERT INTO incident_sources VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(i.incident_id, s, sid, v["rule_id"], iso(v["first_seen"]), iso(v["last_seen"]), v["detections"])
             for i in result.incidents for (s, sid), v in i.sources.items()])
        conn.executemany(
            "INSERT INTO raw_alerts VALUES (" + ",".join("?" * 27) + ")",
            [(a.alert_id, a.source, a.source_alert_id, a.rule_id, a.alert_type, a.entity, a.perimeter,
              a.asset_path, a.asset_id, a.data_owner, json.dumps(a.data_types), a.classification,
              a.rgpd_category, a.exposure, int(a.encrypted), a.environment, a.location, int(a.in_eu),
              a.record_count, a.masked_sample, iso(a.first_seen), iso(a.last_seen), a.status, a.raw_severity,
              a.normalized_severity, incident_id, outcome) for a, incident_id, outcome in result.raw_links])
        rejected = result.ingest.rejected + result.workflow_rejects
        conn.executemany(
            "INSERT INTO rejected_alerts (source_id, file, line_no, reason, raw_record, rejected_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(r["source"], r["file"], r["line_no"], r["reason"],
              r["raw_record"] if isinstance(r["raw_record"], str) else json.dumps(r["raw_record"],
                                                                                  ensure_ascii=False),
              now) for r in rejected])
        conn.executemany(
            "INSERT INTO status_history (incident_id, changed_at, from_status, to_status, actor, reason, "
            "priority, risk_score, sla_due) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(h["incident_id"], iso(h["changed_at"]), h["from_status"], h["to_status"], h["actor"],
              h["reason"], h["priority"], h["risk_score"], iso(h["sla_due"])) for h in result.workflow.history])
        conn.executemany(
            "INSERT INTO exceptions VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(e.exception_id, e.incident_id, e.justification, e.approver, iso(e.granted_at),
              iso(e.expires_at), e.status) for e in result.workflow.exceptions])


def purge_raw_alerts(conn: sqlite3.Connection, as_of: datetime, retention_days: int) -> int:
    """Politique de rétention : supprime les observations brutes trop anciennes (les incidents restent)."""
    cutoff = iso(as_of - timedelta(days=retention_days))
    with conn:
        return conn.execute("DELETE FROM raw_alerts WHERE last_seen < ?", (cutoff,)).rowcount


def write_snapshots(conn: sqlite3.Connection, rows: list[dict]) -> None:
    with conn:
        conn.execute("DELETE FROM metric_snapshots")
        conn.executemany(
            "INSERT INTO metric_snapshots VALUES (:snapshot_date, :scope_type, :scope_value, :metric, :value)",
            rows)


def load_frames(conn: sqlite3.Connection) -> dict[str, pd.DataFrame]:
    """Toutes les tables utiles en DataFrames, dates converties."""
    frames = {}
    for table in ("incidents", "incident_sources", "raw_alerts", "rejected_alerts", "status_history",
                  "exceptions", "scan_coverage", "metric_snapshots", "owners", "entities", "perimeters"):
        df = pd.read_sql_query(f"SELECT * FROM {table}", conn)  # noqa: S608 (noms de tables fixes)
        for col in DATE_COLUMNS.get(table, []):
            df[col] = pd.to_datetime(df[col])
        frames[table] = df
    return frames
