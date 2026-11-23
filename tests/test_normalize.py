"""Normalisation des 3 formats sources, garde-fous et quarantaine."""

from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime

import pytest

from datarisk.ingestion.connectors import load_sources, read_datashield_sqlite
from datarisk.ingestion.normalize import (
    RejectedRow,
    canonical_asset,
    looks_unmasked,
    normalize_datashield,
    normalize_vendor_a,
    normalize_vendor_b,
)
from datarisk.simulator.exports import VB_COLUMNS

VA = {
    "id": "VA-000001", "detector": "VA-PUB-01", "type": "PUBLIC_EXPOSURE", "severity": "critical",
    "tenant": "banque-a", "service": "smb", "resource": "smb://SRV-BQA-FIC01/RH/paie_001.xlsx",
    "owner": "A.Moreau@bqa.test", "data_category": "financial", "data_types": ["IBAN"],
    "classification": "restricted", "exposure": "public_link", "encrypted": False, "environment": "production",
    "region": "eu-west-3", "records": 1200, "sample": "FR76 **** **** **** **** ***1 189",
    "first_seen": "2026-09-01T02:00:00Z", "last_seen": "2026-09-08T02:00:00Z", "state": "open",
}
VB = {
    "Référence": "B0000001", "Règle": "VB-100", "Type d'alerte": "Exposition publique", "Criticité": "5",
    "Entité": "Banque A", "Périmètre": "Partage SMB", "Chemin": r"\\srv-bqa-fic01\RH\paie_001.xlsx",
    "Propriétaire": "A.MOREAU@BQA.TEST", "Catégorie RGPD": "Bancaire", "Types de données": "IBAN|EMAIL",
    "Confidentialité": "Secret", "Exposition": "Publique", "Chiffré": "Non", "Environnement": "PROD",
    "Localisation": "France", "Nb enregistrements": "1200", "Échantillon masqué": "FR76 **** ***1 189",
    "Première détection": "02/09/2026 02:00", "Dernière détection": "09/09/2026 02:00", "Statut": "Ouverte",
}
DS = {
    "alert_id": 7, "file_key": "smb_rh/paie_001.xlsx", "status": "open", "created_at": "2026-09-04T02:00:00+00:00",
    "updated_at": "2026-09-11T02:00:00+00:00", "risk_score": 88, "priority": "Critique", "entity": "BQA",
    "path": "paie_001.xlsx", "owner": "a.moreau@bqa.test", "encrypted": 0, "classification_level": 4,
    "classification": "C3 Secret", "exposure_level": 4, "exposure_label": "lien public anonyme",
    "aggravating": [{"code": "unencrypted", "label": "non chiffré", "points": 10},
                    {"code": "stale_data", "label": "ancien", "points": 10}],
    "repository": {"id": "smb_rh", "kind": "smb", "uri": r"\\SRV-BQA-FIC01\RH", "environment": "prod",
                   "location": "UE (Paris)", "in_eu": 1},
    "findings": [{"rule_id": "DS-FIN-001", "data_type": "IBAN_FR", "gdpr_category": "Données financières",
                  "count": 40, "masked_sample": "FR76 **** 189"},
                 {"rule_id": "DS-SEC-001", "data_type": "AWS_ACCESS_KEY", "gdpr_category": "Secret / authentification",
                  "count": 1, "masked_sample": "AKIA************ABCD"}],
}


def test_canonical_asset_is_source_independent():
    expected = "srv-bqa-fic01/rh/paie_001.xlsx"
    assert canonical_asset("smb://SRV-BQA-FIC01/RH/paie_001.xlsx") == expected
    assert canonical_asset(r"\\srv-bqa-fic01\RH\paie_001.xlsx") == expected
    assert canonical_asset(r"\\SRV-BQA-FIC01\RH" + "/paie_001.xlsx") == expected
    assert canonical_asset("https://bqa.sharepoint.test//sites/RH/") == "bqa.sharepoint.test/sites/rh"


def test_vendor_a_mapping(cfg):
    a = normalize_vendor_a(VA, cfg)
    assert (a.entity, a.perimeter, a.classification, a.exposure, a.rgpd_category) == \
           ("BQA", "SMB", "C3", "public", "bancaire")
    assert a.normalized_severity == 4 and a.raw_severity == "critical"
    assert a.data_owner == "a.moreau@bqa.test" and a.in_eu and a.location == "FR"
    assert a.last_seen == datetime(2026, 9, 8, 2) and a.first_seen == datetime(2026, 9, 1, 2)


def test_vendor_b_mapping_and_same_asset_as_vendor_a(cfg):
    b = normalize_vendor_b(VB, cfg)
    assert (b.entity, b.perimeter, b.classification, b.exposure, b.encrypted) == ("BQA", "SMB", "C3", "public", False)
    assert b.normalized_severity == 4            # échelle 1-5 -> 1-4
    assert b.last_seen == datetime(2026, 9, 9, 2)  # date au format français
    assert b.data_types == ["IBAN", "EMAIL"]
    assert b.asset_id == normalize_vendor_a(VA, cfg).asset_id   # base de la déduplication inter-sources


def test_datashield_alert_is_unfolded_into_one_alert_per_type(cfg):
    alerts = normalize_datashield(DS, cfg)
    types = {a.alert_type: a for a in alerts}
    assert set(types) == {"PUBLIC_EXPOSURE", "UNENCRYPTED", "RETENTION_EXCEEDED", "EXPOSED_SECRET"}
    pub = types["PUBLIC_EXPOSURE"]
    assert (pub.classification, pub.exposure, pub.rgpd_category) == ("C3", "public", "secret")
    assert pub.normalized_severity == 4
    assert pub.asset_id == "srv-bqa-fic01/rh/paie_001.xlsx"
    assert pub.record_count == 41 and set(pub.data_types) == {"IBAN", "CLE_API"}
    assert types["EXPOSED_SECRET"].rule_id == "DS-SEC-001"


def test_datashield_alert_without_actionable_type_returns_nothing(cfg):
    rec = {**DS, "exposure_level": 1, "aggravating": [], "findings": DS["findings"][:1]}
    assert normalize_datashield(rec, cfg) == []


@pytest.mark.parametrize(("source", "record", "expected"), [
    ("a", {**VA, "severity": "urgent"}, "sévérité"),
    ("a", {**VA, "resource": ""}, "chemin d'actif manquant"),
    ("a", {**VA, "records": -5}, "négatif"),
    ("a", {**VA, "last_seen": "2026-13-45T00:00:00Z"}, "date invalide"),
    ("a", {**VA, "sample": "FR7630006000011234567890189"}, "NON masqué"),
    ("a", {k: v for k, v in VA.items() if k != "owner"}, "champ obligatoire manquant"),
    ("a", {**VA, "first_seen": "2026-09-30T00:00:00Z"}, "first_seen postérieur"),
    ("b", {**VB, "Dernière détection": "31/02/2026 02:00"}, "date invalide"),
    ("b", {**VB, "Criticité": "9"}, "sévérité"),
    ("b", {**VB, "Entité": "Banque Z"}, "entité inconnue"),
    ("b", {**VB, "Échantillon masqué": "jean.dupont@mail-client.test"}, "NON masqué"),
    ("ds", {**DS, "exposure_level": 7}, "niveau d'exposition"),
    ("ds", {**DS, "repository": {**DS["repository"], "kind": "ftp"}}, "type de dépôt"),
])
def test_invalid_rows_are_rejected_with_a_reason(cfg, source, record, expected):
    normalizer = {"a": normalize_vendor_a, "b": normalize_vendor_b, "ds": normalize_datashield}[source]
    with pytest.raises(RejectedRow, match=expected):
        normalizer(record, cfg)


def test_masking_guard():
    assert looks_unmasked("4970123412341234")
    assert looks_unmasked("contact: jean.dupont@mail.test")
    assert looks_unmasked("AKIAABCDEFGHIJKLMNOP")
    assert not looks_unmasked("j***@mail-client.test")
    assert not looks_unmasked("FR76 **** **** **** **** ***1 189")
    assert not looks_unmasked("AKIA************WXYZ")


def test_load_sources_quarantines_without_losing_or_leaking(tmp_path, cfg):
    (tmp_path / "dspm_vendor_a").mkdir()
    (tmp_path / "dspm_vendor_b").mkdir()
    (tmp_path / "datashield").mkdir()
    bad = {**VA, "id": "VA-2", "sample": "FR7630006000011234567890189"}
    (tmp_path / "dspm_vendor_a" / "a.json").write_text(json.dumps({"alerts": [VA, bad]}), encoding="utf-8")
    with open(tmp_path / "dspm_vendor_b" / "b.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=VB_COLUMNS, delimiter=";")
        writer.writeheader()
        writer.writerow(VB)
        writer.writerow({**VB, "Criticité": "9"})
    (tmp_path / "datashield" / "d.json").write_text(json.dumps([DS]), encoding="utf-8")

    result = load_sources(tmp_path, cfg)
    assert result.rows_read == {"dspm_vendor_a": 2, "dspm_vendor_b": 2, "datashield": 1}
    assert len(result.alerts) == 1 + 1 + 4
    assert [(r["source"], r["line_no"]) for r in result.rejected] == [("dspm_vendor_a", 2), ("dspm_vendor_b", 3)]
    leaked = result.rejected[0]["raw_record"]
    assert "6000011234567890189" not in leaked and "MASQUÉ PAR L'INGESTION" in leaked


def test_datashield_sqlite_connector(tmp_path, cfg):
    """Base au schéma de DataShield DSPM Lab (sous-ensemble utile) -> même format que l'export JSON."""
    db = tmp_path / "datashield.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE repositories (id TEXT, name TEXT, kind TEXT, uri TEXT, environment TEXT, location TEXT, in_eu INT);
        CREATE TABLE files (id INT, file_key TEXT, repository_id TEXT, path TEXT, owner TEXT, encrypted INT,
            classification_level INT, classification TEXT, exposure_level INT, exposure_label TEXT,
            aggravating_json TEXT);
        CREATE TABLE findings (id INT, file_id INT, rule_id TEXT, data_type TEXT, gdpr_category TEXT, count INT,
            masked_sample TEXT);
        CREATE TABLE alerts (id INT, file_key TEXT, file_id INT, risk_score INT, priority TEXT, status TEXT,
            created_at TEXT, updated_at TEXT);
        INSERT INTO repositories VALUES ('smb_rh', 'SMB RH', 'smb', '\\\\fs-paris-01\\RH', 'prod', 'UE (Paris)', 1);
        INSERT INTO files VALUES (1, 'smb_rh/a.csv', 'smb_rh', 'a.csv', 'j.michel@corp.test', 0, 4, 'C3 Secret',
            3, 'invités externes', '[{"code": "unencrypted", "label": "x", "points": 10}]');
        INSERT INTO findings VALUES (1, 1, 'DS-PII-001', 'NIR', 'Identifiant national (NIR, art. 87 RGPD)', 37,
            '1**************');
        INSERT INTO alerts VALUES (1, 'smb_rh/a.csv', 1, 61, 'Élevé', 'open', '2026-11-23T23:13:00+00:00',
            '2026-11-23T23:13:00+00:00');
    """)
    conn.commit()
    conn.close()
    records = read_datashield_sqlite(db, entity="BQB")
    alerts = normalize_datashield(records[0], cfg)
    assert {a.alert_type for a in alerts} == {"EXTERNAL_SHARING", "UNENCRYPTED"}
    assert all(a.entity == "BQB" and a.asset_id == "fs-paris-01/rh/a.csv" for a in alerts)
    assert alerts[0].rgpd_category == "personnelle" and alerts[0].normalized_severity == 3
