"""Écriture des exports bruts à partir du monde simulé : un fichier par source et par scan.

Chaque source a son propre format (c'est ce qui justifie la couche de normalisation) :
- dspm_vendor_a : JSON, anglais, sévérité texte, dates ISO UTC, chemins avec schéma (smb://, https://)
- dspm_vendor_b : CSV ';', français, sévérité 1-5, dates JJ/MM/AAAA, chemins UNC (\\\\serveur\\partage)
- datashield    : JSON au format de DataShield DSPM Lab (1 alerte par fichier, facteurs aggravants)
Une petite fraction de lignes est volontairement corrompue pour exercer la quarantaine.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from datarisk.ingestion import normalize as nz
from datarisk.simulator.world import World

SHORT = {"PUBLIC_EXPOSURE": "PUB", "EXTERNAL_SHARING": "EXT", "OVERLY_BROAD_GROUP": "GRP",
         "UNENCRYPTED": "ENC", "PROD_DATA_IN_DEV": "DEV", "RETENTION_EXCEEDED": "RET",
         "EXPOSED_SECRET": "SEC", "INACTIVE_ACCOUNT_ACCESS": "INA", "NON_EU_LOCATION": "GEO"}
VB_RULE = {t: f"VB-{100 + i}" for i, t in enumerate(SHORT)}
SCHEME = {"M365": "https://", "ONEDRIVE": "https://", "SMB": "smb://", "CLOUD": "s3://", "SQLDB": "mssql://"}
COUNTRY_TO_REGION = {"FR": "eu-west-3", "IE": "eu-west-1", "US": "us-east-1"}
COUNTRY_TO_FR = {"FR": "France", "IE": "Irlande", "US": "États-Unis"}
DS_LOCATION = {"FR": "UE (Paris)", "IE": "UE (Dublin)", "US": "Hors UE (us-east-1)"}
DS_KIND = {"M365": "sharepoint", "ONEDRIVE": "onedrive", "SMB": "smb", "CLOUD": "s3"}
DS_CLASSIF = {"C0": "C0 Public", "C1": "C1 Interne", "C2": "C2 Confidentiel", "C3": "C3 Secret"}
DS_EXPO_LEVEL = {"PUBLIC_EXPOSURE": 4, "EXTERNAL_SHARING": 3, "OVERLY_BROAD_GROUP": 2}
DS_FACTOR = {v: k for k, v in nz.DS_FACTOR_TYPE.items() if k != "excessive_rights"}
DS_FINDING = {  # type commun -> (type DataShield, catégorie DataShield)
    "IBAN": ("IBAN_FR", "Données financières"),
    "CARTE_BANCAIRE": ("CREDIT_CARD", "Données de paiement (PCI DSS)"),
    "EMAIL": ("EMAIL", "Données d'identification / contact"),
    "TELEPHONE": ("PHONE_FR", "Données d'identification / contact"),
    "NIR": ("NIR", "Identifiant national (NIR, art. 87 RGPD)"),
    "SALAIRE": ("PAYSLIP", "Données RH / rémunération"),
    "DONNEE_SANTE": ("HEALTH_DATA", "Donnée de santé (art. 9 RGPD)"),
    "CLE_API": ("AWS_ACCESS_KEY", "Secret / authentification"),
    "MOT_DE_PASSE": ("PASSWORD", "Secret / authentification"),
    "DOC_INTERNE": ("CONFIDENTIAL_PROJECT", "Secret des affaires"),
}
SECRET_TYPES = {"CLE_API", "MOT_DE_PASSE"}
TIER_LABEL = {1: "Faible", 2: "Moyen", 3: "Élevé", 4: "Critique"}
VB_COLUMNS = ["Référence", "Règle", "Type d'alerte", "Criticité", "Entité", "Périmètre", "Chemin",
              "Propriétaire", "Catégorie RGPD", "Types de données", "Confidentialité", "Exposition", "Chiffré",
              "Environnement", "Localisation", "Nb enregistrements", "Échantillon masqué",
              "Première détection", "Dernière détection", "Statut"]


def inverse(table: dict) -> dict:
    return {v: k for k, v in table.items()}


INV = {name: inverse(getattr(nz, name)) for name in (
    "VA_CLASSIFICATION", "VA_EXPOSURE", "VA_CATEGORY", "VA_SERVICE", "VA_ENVIRONMENT", "VB_TYPE",
    "VB_CLASSIFICATION", "VB_EXPOSURE", "VB_RGPD", "VB_PERIMETER", "VB_ENVIRONMENT")}

# Corruptions volontaires (une par ligne corrompue) -> motifs de rejet attendus
CORRUPT_A = [("severity", "urgent"), ("resource", ""), ("records", -5),
             ("last_seen", "2026-13-45T00:00:00Z"), ("sample", "FR7630006000011234567890189")]
CORRUPT_B = [("Dernière détection", "31/02/2026 02:00"), ("Criticité", "9"), ("Entité", "Banque Z"),
             ("Échantillon masqué", "jean.dupont@mail-client.test")]
CORRUPT_DS = [("updated_at", "hier"), ("exposure_level", 7), ("entity", "Filiale Z")]


def iso_z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class Exporter:
    def __init__(self, world: World) -> None:
        self.w = world
        self.rng = world.rng
        self.ids: dict[tuple, str] = {}
        self.first_seen: dict[tuple, datetime] = {}
        self.ds_alert_ids: dict[str, int] = {}
        self.ds_created: dict[str, datetime] = {}

    # ---------------------------------------------------------------- détections
    def detections(self):
        """(source, semaine, date de scan, problème, n° d'intervalle) pour chaque remontée d'outil."""
        out = []
        w = self.w
        for issue in w.issues:
            for k, (start, end) in enumerate(issue.intervals):
                for s in issue.sources:
                    for week in range(w.weeks):
                        t = w.scan_time(s, week)
                        if t < start or (end is not None and t >= end) or (s, week) in issue.missed:
                            continue
                        if w.onboarded(issue.asset.entity, issue.asset.perimeter, week):
                            out.append((s, week, t, issue, k))
        out.sort(key=lambda d: (d[2], d[3].asset.path, d[3].alert_type))
        return out

    def source_id(self, source: str, issue, k: int, t: datetime) -> tuple[str, datetime]:
        key = (source, issue.fingerprint, k)
        if key not in self.ids:
            n = len(self.ids) + 1
            self.ids[key] = f"VA-{n:06d}" if source == "dspm_vendor_a" else f"B{n:07d}"
            self.first_seen[key] = t
        return self.ids[key], self.first_seen[key]

    def severity_a(self, tier: int) -> str:
        idx = min(3, max(0, tier - 1 + self.rng.choices([-1, 0, 1], weights=[1, 8, 1])[0]))
        label = ["low", "medium", "high", "critical"][idx]
        return "info" if label == "low" and self.rng.random() < 0.3 else label

    def severity_b(self, tier: int) -> int:
        base = {1: self.rng.choice([1, 2]), 2: 3, 3: 4, 4: 5}[tier]
        return min(5, max(1, base + self.rng.choices([-1, 0, 1], weights=[1, 8, 1])[0]))

    # ---------------------------------------------------------------- formats
    def record_a(self, issue, k: int, t: datetime) -> dict:
        a = issue.asset
        sid, first = self.source_id("dspm_vendor_a", issue, k, t)
        return {
            "id": sid, "detector": f"VA-{SHORT[issue.alert_type]}-01", "type": issue.alert_type,
            "severity": self.severity_a(issue.tier), "tenant": nz.slug(self.w.cfg["entities"][a.entity]),
            "service": INV["VA_SERVICE"][a.perimeter], "resource": SCHEME[a.perimeter] + a.path,
            "owner": a.owner, "data_category": INV["VA_CATEGORY"][issue.attr("rgpd")],
            "data_types": issue.attr("data_types"),
            "classification": INV["VA_CLASSIFICATION"][issue.attr("classification")],
            "exposure": INV["VA_EXPOSURE"][issue.attr("exposure")], "encrypted": a.encrypted,
            "environment": INV["VA_ENVIRONMENT"][a.environment], "region": COUNTRY_TO_REGION[a.location],
            "records": a.records, "sample": issue.attr("sample"),
            "first_seen": iso_z(first), "last_seen": iso_z(t), "state": "open",
        }

    def record_b(self, issue, k: int, t: datetime) -> dict:
        a = issue.asset
        sid, first = self.source_id("dspm_vendor_b", issue, k, t)
        path = "\\\\" + a.path.replace("/", "\\") if a.perimeter == "SMB" else a.path
        return {
            "Référence": sid, "Règle": VB_RULE[issue.alert_type],
            "Type d'alerte": INV["VB_TYPE"][issue.alert_type], "Criticité": self.severity_b(issue.tier),
            "Entité": self.w.cfg["entities"][a.entity], "Périmètre": INV["VB_PERIMETER"][a.perimeter],
            "Chemin": path, "Propriétaire": a.owner.upper(),
            "Catégorie RGPD": INV["VB_RGPD"][issue.attr("rgpd")],
            "Types de données": "|".join(issue.attr("data_types")),
            "Confidentialité": INV["VB_CLASSIFICATION"][issue.attr("classification")],
            "Exposition": INV["VB_EXPOSURE"][issue.attr("exposure")],
            "Chiffré": "Oui" if a.encrypted else "Non", "Environnement": INV["VB_ENVIRONMENT"][a.environment],
            "Localisation": COUNTRY_TO_FR[a.location], "Nb enregistrements": a.records,
            "Échantillon masqué": issue.attr("sample"),
            "Première détection": first.strftime(nz.VB_DATE_FORMAT),
            "Dernière détection": t.strftime(nz.VB_DATE_FORMAT), "Statut": "Ouverte",
        }

    def record_ds(self, issues: list, t: datetime) -> dict:
        """1 enregistrement DataShield par fichier et par scan, regroupant les problèmes détectés."""
        a = issues[0].asset
        types = {i.alert_type for i in issues}
        self.ds_alert_ids.setdefault(a.path, len(self.ds_alert_ids) + 1)
        created = self.ds_created.setdefault(a.path, t)
        level = max([DS_EXPO_LEVEL.get(x, 1) for x in types])
        samples: dict[str, str] = {}     # type de donnée -> échantillon masqué (tel que vu par l'outil)
        for i in issues:
            for d in i.attr("data_types"):
                samples.setdefault(d, i.attr("sample"))
        data_types = [d for d in samples if d not in SECRET_TYPES or "EXPOSED_SECRET" in types]
        data_types = data_types or ["DOC_INTERNE"]
        findings = []
        for d in data_types:
            ds_type, label = DS_FINDING[d]
            sample = samples.get(d, "[aucune donnée personnelle]")
            findings.append({"rule_id": f"DS-{ds_type}", "data_type": ds_type, "gdpr_category": label,
                             "count": max(1, a.records // len(data_types)), "masked_sample": sample})
        segs = a.path.split("/")
        uri = ("\\\\" + "\\".join(segs[:-1])) if a.perimeter == "SMB" else SCHEME[a.perimeter] + "/".join(segs[:-1])
        tier = max(i.tier for i in issues)
        return {
            "alert_id": self.ds_alert_ids[a.path], "file_key": f"{a.entity.lower()}/{a.path}",
            "status": "open", "created_at": created.isoformat() + "+00:00", "updated_at": t.isoformat() + "+00:00",
            "risk_score": 20 * tier + self.rng.randint(0, 15), "priority": TIER_LABEL[tier], "entity": a.entity,
            "path": segs[-1], "owner": a.owner, "encrypted": int(a.encrypted),
            "classification_level": int(a.classification[1]) + 1, "classification": DS_CLASSIF[a.classification],
            "exposure_level": level, "exposure_label": "",
            "aggravating": [{"code": DS_FACTOR[x], "label": x.lower(), "points": 10}
                            for x in sorted(types) if x in DS_FACTOR],
            "repository": {"id": f"{a.entity.lower()}_{DS_KIND[a.perimeter]}_{segs[0]}",
                           "kind": DS_KIND[a.perimeter], "uri": uri, "environment": a.environment,
                           "location": DS_LOCATION[a.location], "in_eu": int(a.location != "US")},
            "findings": findings,
        }

    def maybe_corrupt(self, rec: dict, corruptions: list) -> dict:
        if self.rng.random() >= self.w.cfg["simulation"]["invalid_row_rate"]:
            return rec
        key, value = self.rng.choice(corruptions)
        return {**rec, key: value}

    # ---------------------------------------------------------------- écriture
    def write(self, out_dir: Path) -> dict[str, int]:
        for sub in ("dspm_vendor_a", "dspm_vendor_b", "datashield"):
            (out_dir / sub).mkdir(parents=True, exist_ok=True)
            for old in (out_dir / sub).iterdir():
                old.unlink()
        per_scan: dict[tuple[str, datetime], list] = defaultdict(list)
        for s, _week, t, issue, k in self.detections():
            per_scan[(s, t)].append((issue, k))

        counts = {"dspm_vendor_a": 0, "dspm_vendor_b": 0, "datashield": 0}
        for (s, t), items in sorted(per_scan.items(), key=lambda x: (x[0][1], x[0][0])):
            day = t.date().isoformat()
            if s == "dspm_vendor_a":
                alerts = [self.maybe_corrupt(self.record_a(i, k, t), CORRUPT_A) for i, k in items]
                payload = {"vendor": "DSPM Vendor A", "export_date": iso_z(t), "alerts": alerts}
                (out_dir / s / f"alerts_{day}.json").write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                                                                encoding="utf-8")
                counts[s] += len(alerts)
            elif s == "dspm_vendor_b":
                with open(out_dir / s / f"alertes_{day}.csv", "w", encoding="utf-8-sig", newline="") as fh:
                    writer = csv.DictWriter(fh, fieldnames=VB_COLUMNS, delimiter=";")
                    writer.writeheader()
                    for i, k in items:
                        writer.writerow(self.maybe_corrupt(self.record_b(i, k, t), CORRUPT_B))
                        counts[s] += 1
            else:
                by_asset: dict[str, list] = defaultdict(list)
                for i, _k in items:
                    by_asset[i.asset.path].append(i)
                records = [self.maybe_corrupt(self.record_ds(v, t), CORRUPT_DS) for v in by_asset.values()]
                (out_dir / s / f"datashield_export_{day}.json").write_text(
                    json.dumps(records, ensure_ascii=False, indent=1), encoding="utf-8")
                counts[s] += len(records)

        self._write_events(out_dir / "workflow_events.csv")
        self._write_coverage(out_dir / "scan_coverage.csv")
        self._write_owners(out_dir / "owners.csv")
        self._write_ground_truth(out_dir / "ground_truth.csv")
        return counts

    def _write_events(self, path: Path) -> None:
        cols = ["event_time", "fingerprint", "action", "actor", "assignee", "justification", "approver",
                "expires_at", "comment"]
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols)
            writer.writeheader()
            for e in self.w.events:
                row = {c: e.get(c, "") for c in cols}
                row["event_time"] = e["event_time"].isoformat(timespec="seconds")
                if e.get("expires_at"):
                    row["expires_at"] = e["expires_at"].isoformat(timespec="seconds")
                writer.writerow(row)

    def _write_coverage(self, path: Path) -> None:
        from datarisk.simulator.world import SOURCE_PERIMETERS, SOURCES
        w = self.w
        assets_per = defaultdict(int)
        for a in w.assets:
            assets_per[(a.entity, a.perimeter)] += 1
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["scan_date", "source", "entity", "perimeter", "assets_scanned"])
            for week in range(w.weeks):
                for s in SOURCES:
                    for (entity, perimeter), n in sorted(assets_per.items()):
                        if perimeter in SOURCE_PERIMETERS[s] and w.onboarded(entity, perimeter, week):
                            writer.writerow([w.scan_time(s, week).date().isoformat(), s, entity, perimeter, n])

    def _write_owners(self, path: Path) -> None:
        owners = sorted({(a.owner, a.entity) for a in self.w.assets})
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["owner_id", "entity", "display_name"])
            for owner, entity in owners:
                local = owner.split("@")[0]
                first, last = local.split(".")
                writer.writerow([owner, entity, f"{first.upper()}. {last.capitalize()}"])

    def _write_ground_truth(self, path: Path) -> None:
        """Vérité terrain (pour les tests de bout en bout uniquement : le pipeline ne la lit pas)."""
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["fingerprint", "asset_id", "alert_type", "is_false_positive", "sources", "tier"])
            for i in self.w.issues:
                writer.writerow([i.fingerprint, i.asset.canonical, i.alert_type, int(i.is_fp),
                                 "|".join(i.sources), i.tier])
