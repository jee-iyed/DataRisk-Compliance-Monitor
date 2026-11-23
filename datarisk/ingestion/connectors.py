"""Connecteurs : lecture des exports bruts de chaque source + quarantaine des lignes invalides.

- dspm_vendor_a : data/raw/dspm_vendor_a/*.json   ({"export_date": ..., "alerts": [...]})
- dspm_vendor_b : data/raw/dspm_vendor_b/*.csv    (séparateur ';', UTF-8 avec BOM, en-têtes FR)
- datashield    : data/raw/datashield/*.json      (format simulé)
                  OU la vraie base SQLite de DataShield DSPM Lab (option --datashield-db)
"""

from __future__ import annotations

import copy
import csv
import json
import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from datarisk.ingestion.normalize import (
    NormalizedAlert,
    RejectedRow,
    normalize_datashield,
    normalize_vendor_a,
    normalize_vendor_b,
)

SAMPLE_KEYS = ("sample", "Échantillon masqué", "masked_sample")


@dataclass
class IngestResult:
    alerts: list[NormalizedAlert] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    rows_read: dict[str, int] = field(default_factory=dict)
    no_actionable_type: int = 0     # alertes DataShield sans type actionnable (ignorées, comptées)


def redact(record: dict) -> dict:
    """Copie de la ligne rejetée SANS l'échantillon (il a pu être rejeté justement car non masqué)."""
    out = copy.deepcopy(record)
    for key in SAMPLE_KEYS:
        if key in out:
            out[key] = "[MASQUÉ PAR L'INGESTION]"
    for f in out.get("findings") or []:
        if isinstance(f, dict) and "masked_sample" in f:
            f["masked_sample"] = "[MASQUÉ PAR L'INGESTION]"
    return out


def read_vendor_a(path: Path) -> Iterator[tuple[int, dict]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    yield from enumerate(data["alerts"], start=1)


def read_vendor_b(path: Path) -> Iterator[tuple[int, dict]]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        yield from enumerate(csv.DictReader(fh, delimiter=";"), start=2)   # ligne 1 = en-têtes


def read_datashield_json(path: Path) -> Iterator[tuple[int, dict]]:
    yield from enumerate(json.loads(path.read_text(encoding="utf-8")), start=1)


DATASHIELD_SQL = """
SELECT a.id AS alert_id, a.file_key, a.status, a.created_at, a.updated_at, a.risk_score, a.priority,
       f.id AS file_id, f.path, f.owner, f.encrypted, f.classification_level, f.classification,
       f.exposure_level, f.exposure_label, f.aggravating_json,
       r.id AS repo_id, r.kind, r.uri, r.environment, r.location, r.in_eu
FROM alerts a
JOIN files f        ON f.id = a.file_id
JOIN repositories r ON r.id = f.repository_id
ORDER BY a.id
"""


def read_datashield_sqlite(db_path: Path, entity: str | None = None) -> list[dict]:
    """Lit la base de DataShield DSPM Lab (lecture seule) et produit le même format que l'export JSON."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        records = []
        for r in conn.execute(DATASHIELD_SQL):
            findings = [dict(f) for f in conn.execute(
                "SELECT rule_id, data_type, gdpr_category, count, masked_sample FROM findings "
                "WHERE file_id = ?", (r["file_id"],))]
            records.append({
                "alert_id": r["alert_id"], "file_key": r["file_key"], "status": r["status"],
                "created_at": r["created_at"], "updated_at": r["updated_at"],
                "risk_score": r["risk_score"], "priority": r["priority"], "entity": entity,
                "path": r["path"], "owner": r["owner"], "encrypted": r["encrypted"],
                "classification_level": r["classification_level"], "classification": r["classification"],
                "exposure_level": r["exposure_level"], "exposure_label": r["exposure_label"],
                "aggravating": json.loads(r["aggravating_json"] or "[]"),
                "repository": {"id": r["repo_id"], "kind": r["kind"], "uri": r["uri"],
                               "environment": r["environment"], "location": r["location"],
                               "in_eu": r["in_eu"]},
                "findings": findings,
            })
        return records
    finally:
        conn.close()


def _ingest(result: IngestResult, source: str, file_label: str, rows: Iterator[tuple[int, dict]],
            normalizer: Callable[[dict, dict], Any], cfg: dict) -> None:
    for line_no, rec in rows:
        result.rows_read[source] = result.rows_read.get(source, 0) + 1
        try:
            out = normalizer(rec, cfg)
        except RejectedRow as exc:
            result.rejected.append({"source": source, "file": file_label, "line_no": line_no,
                                    "reason": str(exc), "raw_record": json.dumps(redact(rec), ensure_ascii=False,
                                                                                 default=str)})
            continue
        if isinstance(out, list):
            if not out:
                result.no_actionable_type += 1
            result.alerts.extend(out)
        else:
            result.alerts.append(out)


def load_sources(raw_dir: Path, cfg: dict, datashield_db: Path | None = None) -> IngestResult:
    result = IngestResult()
    for path in sorted((raw_dir / "dspm_vendor_a").glob("*.json")):
        _ingest(result, "dspm_vendor_a", path.name, read_vendor_a(path), normalize_vendor_a, cfg)
    for path in sorted((raw_dir / "dspm_vendor_b").glob("*.csv")):
        _ingest(result, "dspm_vendor_b", path.name, read_vendor_b(path), normalize_vendor_b, cfg)
    if datashield_db is not None:
        records = read_datashield_sqlite(datashield_db)
        _ingest(result, "datashield", datashield_db.name, enumerate(records, start=1), normalize_datashield, cfg)
    else:
        for path in sorted((raw_dir / "datashield").glob("*.json")):
            _ingest(result, "datashield", path.name, read_datashield_json(path), normalize_datashield, cfg)
    return result
