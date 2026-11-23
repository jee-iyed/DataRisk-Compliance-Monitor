"""Normalisation des 3 formats sources vers le schéma commun `NormalizedAlert`.

Chaque source a son vocabulaire (anglais / français / DataShield), ses formats de date et son échelle
de sévérité. Les tables de correspondance ci-dessous sont la documentation du mapping : elles sont
aussi utilisées (inversées) par le simulateur pour produire les exports.

Toute ligne qui ne peut pas être normalisée lève `RejectedRow(motif)` : l'appelant la range en
quarantaine (table rejected_alerts), elle n'est jamais perdue silencieusement.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from datarisk.constants import ALERT_TYPES, CLASSIFICATIONS, ENVIRONMENTS, EXPOSURES, RGPD_CATEGORIES


class RejectedRow(Exception):
    """Ligne invalide : le message est le motif de rejet."""


@dataclass
class NormalizedAlert:
    alert_id: str               # identifiant de l'observation (hash source + id source + date)
    source: str
    source_alert_id: str
    rule_id: str
    alert_type: str
    entity: str
    perimeter: str
    asset_path: str             # chemin tel que remonté par la source
    asset_id: str               # chemin canonique (clé de déduplication)
    data_owner: str
    data_types: list[str]
    classification: str         # C0..C3
    rgpd_category: str          # aucune / personnelle / bancaire / secret / sensible_art9
    exposure: str               # public / externe / groupe_large / restreint
    encrypted: bool
    environment: str            # prod / dev
    location: str
    in_eu: bool
    record_count: int
    masked_sample: str
    first_seen: datetime
    last_seen: datetime
    status: str                 # statut côté source (informatif)
    raw_severity: str
    normalized_severity: int    # 1 Faible .. 4 Critique
    extra: dict[str, Any] = field(default_factory=dict)


# ============================================================================== tables de mapping
# --- dspm_vendor_a (JSON, anglais)
VA_CLASSIFICATION = {"public": "C0", "internal": "C1", "confidential": "C2", "restricted": "C3"}
VA_EXPOSURE = {"public_link": "public", "external": "externe", "org_wide": "groupe_large", "private": "restreint"}
VA_CATEGORY = {"none": "aucune", "personal": "personnelle", "financial": "bancaire",
               "credential": "secret", "special_category": "sensible_art9"}
VA_SERVICE = {"sharepoint": "M365", "onedrive": "ONEDRIVE", "s3": "CLOUD", "smb": "SMB", "sql": "SQLDB"}
VA_ENVIRONMENT = {"production": "prod", "development": "dev"}
VA_REGION = {"eu-west-3": ("FR", True), "eu-west-1": ("IE", True), "eu-central-1": ("DE", True),
             "us-east-1": ("US", False)}

# --- dspm_vendor_b (CSV, français)
VB_TYPE = {
    "Exposition publique": "PUBLIC_EXPOSURE", "Partage externe": "EXTERNAL_SHARING",
    "Groupe trop large": "OVERLY_BROAD_GROUP", "Absence de chiffrement": "UNENCRYPTED",
    "Données de production hors prod": "PROD_DATA_IN_DEV",
    "Durée de conservation dépassée": "RETENTION_EXCEEDED", "Secret en clair": "EXPOSED_SECRET",
    "Compte inactif": "INACTIVE_ACCOUNT_ACCESS", "Hébergement hors UE": "NON_EU_LOCATION",
}
VB_CLASSIFICATION = {"Public": "C0", "Interne": "C1", "Confidentiel": "C2", "Secret": "C3"}
VB_EXPOSURE = {"Publique": "public", "Externe": "externe", "Groupe large": "groupe_large",
               "Restreinte": "restreint"}
VB_RGPD = {"Aucune": "aucune", "Personnelle": "personnelle", "Bancaire": "bancaire", "Secret": "secret",
           "Sensible (art. 9)": "sensible_art9"}
VB_PERIMETER = {"SharePoint": "M365", "OneDrive": "ONEDRIVE", "Partage SMB": "SMB",
                "Bucket cloud": "CLOUD", "Base SQL": "SQLDB"}
VB_YES_NO = {"Oui": True, "Non": False}
VB_ENVIRONMENT = {"PROD": "prod", "DEV": "dev"}
VB_COUNTRY = {"France": ("FR", True), "Irlande": ("IE", True), "Allemagne": ("DE", True),
              "États-Unis": ("US", False)}
VB_DATE_FORMAT = "%d/%m/%Y %H:%M"

# --- datashield (export de DataShield DSPM Lab : 1 alerte par fichier, n facteurs)
DS_EXPOSURE_LEVEL = {4: "public", 3: "externe", 2: "groupe_large", 1: "restreint"}
DS_EXPOSURE_TYPE = {4: "PUBLIC_EXPOSURE", 3: "EXTERNAL_SHARING", 2: "OVERLY_BROAD_GROUP"}
DS_FACTOR_TYPE = {
    "unencrypted": "UNENCRYPTED", "sensitive_data_in_dev": "PROD_DATA_IN_DEV",
    "outside_eu": "NON_EU_LOCATION", "inactive_accounts": "INACTIVE_ACCOUNT_ACCESS",
    "stale_data": "RETENTION_EXCEEDED", "excessive_rights": "OVERLY_BROAD_GROUP",
}
DS_DATA_TYPE = {"IBAN_FR": "IBAN", "CREDIT_CARD": "CARTE_BANCAIRE", "PHONE_FR": "TELEPHONE",
                "HEALTH_DATA": "DONNEE_SANTE", "AWS_ACCESS_KEY": "CLE_API", "GITHUB_TOKEN": "CLE_API",
                "PRIVATE_KEY": "CLE_API", "PASSWORD": "MOT_DE_PASSE", "PAYSLIP": "SALAIRE",
                "CONFIDENTIAL_PROJECT": "DOC_INTERNE"}
# catégorie DataShield (préfixe) -> catégorie RGPD commune
DS_GDPR_PREFIX = [("Donnée de santé", "sensible_art9"), ("Secret / authentification", "secret"),
                  ("Données financières", "bancaire"), ("Données de paiement", "bancaire"),
                  ("Identifiant national", "personnelle"), ("Données d'identification", "personnelle"),
                  ("Données RH", "personnelle")]
RGPD_RANK = {c: i for i, c in enumerate(RGPD_CATEGORIES)}   # aucune < personnelle < ... < sensible_art9

# ============================================================================== helpers
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def canonical_asset(path: str) -> str:
    r"""Chemin canonique, identique quelle que soit la source.

    'smb://SRV-BQA-FIC01/RH/x.xlsx', '\\srv-bqa-fic01\RH\x.xlsx' -> 'srv-bqa-fic01/rh/x.xlsx'
    """
    p = _SCHEME.sub("", path.strip()).replace("\\", "/")
    return re.sub(r"/+", "/", p).strip("/").lower()


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def resolve_entity(value: str, entities: dict[str, str]) -> str:
    """Accepte le code ('BQA'), le nom ('Banque A') ou le slug ('banque-a')."""
    v = (value or "").strip()
    for code, name in entities.items():
        if v.upper() == code or v.lower() == name.lower() or slug(v) == slug(name):
            return code
    raise RejectedRow(f"entité inconnue : {value!r}")


def lookup(table: dict, value: Any, what: str) -> Any:
    try:
        return table[value]
    except (KeyError, TypeError):
        raise RejectedRow(f"{what} inconnu(e) : {value!r}") from None


def parse_iso(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(str(value).strip())
    except ValueError:
        raise RejectedRow(f"date invalide : {value!r}") from None
    return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt


def parse_fr(value: str) -> datetime:
    try:
        return datetime.strptime(str(value).strip(), VB_DATE_FORMAT)
    except ValueError:
        raise RejectedRow(f"date invalide : {value!r}") from None


def parse_count(value: Any) -> int:
    try:
        n = int(str(value).replace(" ", ""))
    except ValueError:
        raise RejectedRow(f"nombre d'enregistrements invalide : {value!r}") from None
    if n < 0:
        raise RejectedRow(f"nombre d'enregistrements négatif : {n}")
    return n


_LONG_DIGITS = re.compile(r"\d{8,}")
_EMAIL = re.compile(r"([^\s@]+)@[\w.-]+\.[a-z]{2,}", re.IGNORECASE)
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")


def looks_unmasked(sample: str) -> bool:
    """Garde-fou : un échantillon doit être masqué. Rejette les suites de >= 8 chiffres (IBAN, carte,
    NIR en clair), les e-mails sans '*' dans la partie locale et les clés AWS complètes."""
    compact = sample.replace(" ", "")
    if _LONG_DIGITS.search(compact) or _AWS_KEY.search(compact):
        return True
    return any("*" not in m.group(1) for m in _EMAIL.finditer(sample))


def make_alert_id(source: str, source_alert_id: str, last_seen: datetime) -> str:
    raw = f"{source}|{source_alert_id}|{last_seen.isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def validate(alert: NormalizedAlert, cfg: dict) -> NormalizedAlert:
    """Contrôles communs, quelle que soit la source."""
    if not alert.asset_id:
        raise RejectedRow("chemin d'actif manquant")
    if not alert.source_alert_id:
        raise RejectedRow("identifiant source manquant")
    if alert.alert_type not in ALERT_TYPES:
        raise RejectedRow(f"type d'alerte inconnu : {alert.alert_type!r}")
    if alert.perimeter not in cfg["perimeters"]:
        raise RejectedRow(f"périmètre inconnu : {alert.perimeter!r}")
    if alert.classification not in CLASSIFICATIONS:
        raise RejectedRow(f"classification invalide : {alert.classification!r}")
    if alert.rgpd_category not in RGPD_CATEGORIES:
        raise RejectedRow(f"catégorie RGPD invalide : {alert.rgpd_category!r}")
    if alert.exposure not in EXPOSURES:
        raise RejectedRow(f"exposition invalide : {alert.exposure!r}")
    if alert.environment not in ENVIRONMENTS:
        raise RejectedRow(f"environnement invalide : {alert.environment!r}")
    if alert.first_seen > alert.last_seen:
        raise RejectedRow("first_seen postérieur à last_seen")
    if looks_unmasked(alert.masked_sample):
        raise RejectedRow("échantillon NON masqué (donnée potentiellement en clair)")
    return alert


def _severity(cfg: dict, source: str, raw: Any) -> int:
    return lookup(cfg["severity_mapping"][source], str(raw), f"sévérité {source}")


# ============================================================================== normaliseurs
def normalize_vendor_a(rec: dict, cfg: dict) -> NormalizedAlert:
    """Éditeur A : JSON, champs en anglais, sévérité texte, dates ISO 8601 UTC."""
    try:
        resource = rec["resource"] or ""
        location, in_eu = lookup(VA_REGION, rec["region"], "région")
        last_seen = parse_iso(rec["last_seen"])
        alert = NormalizedAlert(
            alert_id=make_alert_id("dspm_vendor_a", rec["id"], last_seen),
            source="dspm_vendor_a", source_alert_id=rec["id"], rule_id=rec["detector"],
            alert_type=rec["type"], entity=resolve_entity(rec["tenant"], cfg["entities"]),
            perimeter=lookup(VA_SERVICE, rec["service"], "service"),
            asset_path=resource, asset_id=canonical_asset(resource),
            data_owner=str(rec["owner"]).lower(), data_types=list(rec["data_types"]),
            classification=lookup(VA_CLASSIFICATION, rec["classification"], "classification"),
            rgpd_category=lookup(VA_CATEGORY, rec["data_category"], "catégorie de données"),
            exposure=lookup(VA_EXPOSURE, rec["exposure"], "exposition"),
            encrypted=bool(rec["encrypted"]),
            environment=lookup(VA_ENVIRONMENT, rec["environment"], "environnement"),
            location=location, in_eu=in_eu, record_count=parse_count(rec["records"]),
            masked_sample=str(rec["sample"]), first_seen=parse_iso(rec["first_seen"]), last_seen=last_seen,
            status=rec["state"], raw_severity=str(rec["severity"]),
            normalized_severity=_severity(cfg, "dspm_vendor_a", rec["severity"]),
        )
    except KeyError as exc:
        raise RejectedRow(f"champ obligatoire manquant : {exc.args[0]}") from None
    return validate(alert, cfg)


def normalize_vendor_b(row: dict, cfg: dict) -> NormalizedAlert:
    """Éditeur B : CSV ';', champs en français, sévérité numérique 1-5, dates JJ/MM/AAAA HH:MM."""
    try:
        path = row["Chemin"] or ""
        location, in_eu = lookup(VB_COUNTRY, row["Localisation"], "localisation")
        last_seen = parse_fr(row["Dernière détection"])
        types = [t for t in (row["Types de données"] or "").split("|") if t]
        alert = NormalizedAlert(
            alert_id=make_alert_id("dspm_vendor_b", row["Référence"], last_seen),
            source="dspm_vendor_b", source_alert_id=row["Référence"], rule_id=row["Règle"],
            alert_type=lookup(VB_TYPE, row["Type d'alerte"], "type d'alerte"),
            entity=resolve_entity(row["Entité"], cfg["entities"]),
            perimeter=lookup(VB_PERIMETER, row["Périmètre"], "périmètre"),
            asset_path=path, asset_id=canonical_asset(path),
            data_owner=row["Propriétaire"].lower(), data_types=types,
            classification=lookup(VB_CLASSIFICATION, row["Confidentialité"], "confidentialité"),
            rgpd_category=lookup(VB_RGPD, row["Catégorie RGPD"], "catégorie RGPD"),
            exposure=lookup(VB_EXPOSURE, row["Exposition"], "exposition"),
            encrypted=lookup(VB_YES_NO, row["Chiffré"], "valeur Chiffré"),
            environment=lookup(VB_ENVIRONMENT, row["Environnement"], "environnement"),
            location=location, in_eu=in_eu, record_count=parse_count(row["Nb enregistrements"]),
            masked_sample=row["Échantillon masqué"], first_seen=parse_fr(row["Première détection"]),
            last_seen=last_seen, status=row["Statut"], raw_severity=str(row["Criticité"]),
            normalized_severity=_severity(cfg, "dspm_vendor_b", row["Criticité"]),
        )
    except KeyError as exc:
        raise RejectedRow(f"colonne obligatoire manquante : {exc.args[0]}") from None
    return validate(alert, cfg)


def _ds_category(gdpr_label: str) -> str:
    for prefix, category in DS_GDPR_PREFIX:
        if gdpr_label.startswith(prefix):
            return category
    return "aucune"


def normalize_datashield(rec: dict, cfg: dict) -> list[NormalizedAlert]:
    """DataShield : 1 alerte par fichier portant un niveau d'exposition et des facteurs aggravants.
    On la "déplie" en 1 alerte par type (exposition, chaque facteur, secret détecté).
    Une alerte DataShield sans type actionnable (accès restreint, aucun facteur) renvoie [].
    """
    try:
        repo = rec["repository"]
        kind_map = cfg["datashield"]["kind_to_perimeter"]
        perimeter = lookup(kind_map, repo["kind"], "type de dépôt DataShield")
        asset_path = f"{repo['uri']}/{rec['path']}" if rec.get("path") else ""
        findings = rec.get("findings") or []
        categories = [_ds_category(f["gdpr_category"]) for f in findings]
        rgpd = max(categories, key=RGPD_RANK.__getitem__, default="aucune")
        top = next((f for f, c in zip(findings, categories, strict=True) if c == rgpd), None)
        level = int(rec["exposure_level"])
        last_seen = parse_iso(rec["updated_at"])
        common = dict(
            source="datashield", entity=resolve_entity(rec.get("entity") or cfg["datashield"]["default_entity"],
                                                       cfg["entities"]),
            perimeter=perimeter, asset_path=asset_path, asset_id=canonical_asset(asset_path),
            data_owner=str(rec.get("owner") or "inconnu").lower(),
            data_types=sorted({DS_DATA_TYPE.get(f["data_type"], f["data_type"]) for f in findings}),
            classification=f"C{int(rec['classification_level']) - 1}", rgpd_category=rgpd,
            exposure=lookup(DS_EXPOSURE_LEVEL, level, "niveau d'exposition"),
            encrypted=bool(rec["encrypted"]), environment=repo["environment"],
            location=repo["location"], in_eu=bool(repo["in_eu"]),
            record_count=sum(parse_count(f["count"]) for f in findings),
            masked_sample=top["masked_sample"] if top else "", first_seen=parse_iso(rec["created_at"]),
            last_seen=last_seen, status=rec["status"], raw_severity=rec["priority"],
            normalized_severity=_severity(cfg, "datashield", rec["priority"]),
        )
        # (type d'alerte, règle) dérivés de l'alerte DataShield
        derived: dict[str, str] = {}
        if level in DS_EXPOSURE_TYPE:
            derived[DS_EXPOSURE_TYPE[level]] = f"DS-EXPOSURE-{level}"
        for factor in rec.get("aggravating") or []:
            if factor["code"] in DS_FACTOR_TYPE:
                derived.setdefault(DS_FACTOR_TYPE[factor["code"]], f"DS-{factor['code']}")
        for f, c in zip(findings, categories, strict=True):
            if c == "secret":
                derived.setdefault("EXPOSED_SECRET", f.get("rule_id") or "DS-SECRET")
    except KeyError as exc:
        raise RejectedRow(f"champ obligatoire manquant : {exc.args[0]}") from None

    alerts = []
    for alert_type, rule_id in sorted(derived.items()):
        sid = f"{rec['alert_id']}/{alert_type}"
        alerts.append(validate(NormalizedAlert(
            alert_id=make_alert_id("datashield", sid, last_seen), source_alert_id=sid, rule_id=rule_id,
            alert_type=alert_type, **common), cfg))
    return alerts
