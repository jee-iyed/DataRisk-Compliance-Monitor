"""Le "monde" simulé : entités, actifs de données, problèmes réels et comportement des analystes.

Principe : on simule d'abord la VÉRITÉ (quels actifs ont quel problème, quand il apparaît, quand il
est corrigé), puis on en dérive ce que chaque outil DSPM en voit (export par source) et ce que les
analystes font (journal d'actions). Le pipeline, lui, ne voit que les exports et le journal.

Réalisme modélisé :
- doublons inter-sources (un même problème vu par 2-3 outils) et re-détections hebdomadaires ;
- scans manqués (un outil ne remonte pas tout chaque semaine) ;
- faux positifs portés par des règles "bruyantes" d'un outil précis ;
- remédiations plus rapides pour les problèmes graves, campagne de remédiation à mi-période ;
- régressions (problème corrigé qui réapparaît), exceptions avec date d'expiration ;
- périmètres raccordés en cours de route (couverture qui progresse).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from datarisk.consolidation.dedup import fingerprint
from datarisk.ingestion.normalize import canonical_asset

SOURCES = ("dspm_vendor_a", "dspm_vendor_b", "datashield")
SCAN_WEEKDAY = {"dspm_vendor_a": 0, "dspm_vendor_b": 2, "datashield": 4}  # lundi, mercredi, vendredi
SCAN_HOUR = 2
SOURCE_PERIMETERS = {
    "dspm_vendor_a": {"M365", "ONEDRIVE", "CLOUD"},          # orienté cloud / SaaS
    "dspm_vendor_b": {"SMB", "SQLDB", "M365"},                # orienté on-premise
    "datashield": {"SMB", "M365", "ONEDRIVE", "CLOUD"},       # scanner de fichiers
}
TYPE_PERIMETERS = {
    "PUBLIC_EXPOSURE": {"M365", "ONEDRIVE", "CLOUD"},
    "EXTERNAL_SHARING": {"M365", "ONEDRIVE"},
    "OVERLY_BROAD_GROUP": {"M365", "SMB", "SQLDB"},
    "UNENCRYPTED": {"SMB", "CLOUD", "SQLDB"},
    "PROD_DATA_IN_DEV": {"SQLDB", "CLOUD", "SMB"},
    "RETENTION_EXCEEDED": {"M365", "ONEDRIVE", "SMB", "CLOUD", "SQLDB"},
    "EXPOSED_SECRET": {"SMB", "CLOUD", "M365", "ONEDRIVE"},
    "INACTIVE_ACCOUNT_ACCESS": {"SMB", "SQLDB", "M365"},
    "NON_EU_LOCATION": {"CLOUD"},
}
# Raccordement progressif : (entité, périmètre) -> 1re semaine scannée (None = jamais : angle mort)
ONBOARDING_WEEK: dict[tuple[str, str], int | None] = {
    ("BQB", "CLOUD"): 3, ("ASS", "SQLDB"): 5, ("ASS", "CLOUD"): None,
}
DETECTION_RATE = 0.90        # proba qu'un outil remonte un problème actif lors d'un scan donné
SOURCE_RECALL = 0.80         # proba qu'un outil couvrant le périmètre sache détecter ce problème
ASSETS_PER_PERIMETER = 34

TEAMS = ["RH", "Finance", "Marketing", "Juridique", "IT", "Conformite", "Commercial"]
OWNER_NAMES = [
    "a.moreau", "b.lefevre", "c.girard", "d.roux", "e.fournier", "f.mercier",
    "g.bonnet", "h.lambert", "i.fontaine", "j.chevalier", "k.robin", "l.masson",
    "m.henry", "n.garnier", "o.faure", "p.andre", "q.blanc", "r.guerin",
]
ANALYSTS = ["analyste.1", "analyste.2", "analyste.3", "analyste.4"]

# (catégorie RGPD, types de données, échantillon MASQUÉ, nom de fichier, table SQL, classifications)
PROFILES = [
    ("bancaire", ["IBAN", "EMAIL"], "FR76 **** **** **** **** ***{d3}", "virements_clients.xlsx",
     "comptes", ["C2", "C3"]),
    ("bancaire", ["CARTE_BANCAIRE"], "4970 **** **** {d4}", "export_cartes.csv", "cartes", ["C3"]),
    ("personnelle", ["EMAIL", "TELEPHONE"], "{l}***@mail-client.test", "annuaire_clients.xlsx",
     "clients", ["C1", "C2"]),
    ("personnelle", ["NIR", "SALAIRE"], "{d1} ** ** ** *** *** **", "dossiers_salaries.xlsx",
     "salaries", ["C2", "C3"]),
    ("sensible_art9", ["DONNEE_SANTE", "NIR"], "diagnostic: ******** (patient {l}.)", "arrets_maladie.pdf",
     "sinistres_sante", ["C3"]),
    ("secret", ["CLE_API"], "AKIA************{A4}", "config_deploiement.yaml", "app_credentials", ["C3"]),
    ("secret", ["MOT_DE_PASSE"], "password=********", "acces_applicatifs.txt", "app_users", ["C3"]),
    ("aucune", ["DOC_INTERNE"], "[aucune donnée personnelle]", "note_interne.docx", "referentiel",
     ["C0", "C1"]),
]
PROFILE_WEIGHTS = [14, 6, 18, 10, 6, 5, 4, 14]

EXPOSURE_DIST = {
    "M365": {"public": 0.08, "externe": 0.20, "groupe_large": 0.30, "restreint": 0.42},
    "ONEDRIVE": {"public": 0.10, "externe": 0.30, "groupe_large": 0.05, "restreint": 0.55},
    "SMB": {"public": 0.0, "externe": 0.0, "groupe_large": 0.45, "restreint": 0.55},
    "CLOUD": {"public": 0.15, "externe": 0.10, "groupe_large": 0.0, "restreint": 0.75},
    "SQLDB": {"public": 0.0, "externe": 0.0, "groupe_large": 0.35, "restreint": 0.65},
}
ENCRYPTED_RATE = {"M365": 0.7, "ONEDRIVE": 0.8, "SMB": 0.3, "CLOUD": 0.5, "SQLDB": 0.6}
DEV_RATE = {"M365": 0.0, "ONEDRIVE": 0.0, "SMB": 0.10, "CLOUD": 0.30, "SQLDB": 0.25}

# Règles bruyantes : (source fautive, type, poids, attributs erronés remontés par l'outil)
NOISY_RULES = [
    ("dspm_vendor_b", "OVERLY_BROAD_GROUP", 0.35, {"exposure": "groupe_large"}),
    ("dspm_vendor_a", "EXPOSED_SECRET", 0.25,
     {"rgpd": "secret", "data_types": ["CLE_API"], "sample": "sk_test_************", "classification": "C3"}),
    ("dspm_vendor_b", "RETENTION_EXCEEDED", 0.15, {}),
    ("datashield", "INACTIVE_ACCOUNT_ACCESS", 0.10, {}),
    ("dspm_vendor_a", "EXTERNAL_SHARING", 0.15, {"exposure": "externe"}),
]
FP_RATIO = 0.25                 # nb de problèmes "faux" / nb de problèmes réels
EXCEPTION_TYPES = {"RETENTION_EXCEEDED", "NON_EU_LOCATION", "OVERLY_BROAD_GROUP", "UNENCRYPTED"}
EXCEPTION_JUSTIFICATIONS = [
    "Migration vers le stockage chiffré planifiée au prochain trimestre",
    "Obligation légale de conservation en cours de vérification par le juridique",
    "Prestataire hors UE couvert par des clauses contractuelles types (CCT)",
    "Groupe large requis par le processus métier, revue des droits planifiée",
]


@dataclass
class Asset:
    entity: str
    perimeter: str
    path: str                 # chemin "affichable" sans schéma, casse d'origine
    owner: str
    team: str
    classification: str
    rgpd: str
    data_types: list[str]
    sample: str
    records: int
    encrypted: bool
    environment: str
    location: str             # code pays : FR, IE, US
    exposure: str

    @property
    def canonical(self) -> str:
        return canonical_asset(self.path)


@dataclass
class Issue:
    asset: Asset
    alert_type: str
    is_fp: bool
    sources: list[str]
    overrides: dict
    start: datetime
    tier: int                                  # urgence perçue par les analystes (1..4)
    missed: set[tuple[str, int]] = field(default_factory=set)
    intervals: list[list] = field(default_factory=list)  # [[début, fin|None], ...] périodes actives

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.asset.canonical, self.alert_type)

    def attr(self, name: str):
        """Attribut tel que remonté par l'outil (les faux positifs portent des attributs erronés)."""
        return self.overrides.get(name, getattr(self.asset, name))


class World:
    def __init__(self, cfg: dict, seed: int) -> None:
        self.cfg = cfg
        self.rng = random.Random(seed)
        sim = cfg["simulation"]
        self.start = datetime.fromisoformat(sim["start_date"])
        self.weeks = int(sim["weeks"])
        self.end = self.start + timedelta(weeks=self.weeks)
        w1, w2 = sim["campaign_weeks"][0], sim["campaign_weeks"][-1]
        self.campaign_start = self.start + timedelta(weeks=w1 - 1)
        self.campaign_end = self.start + timedelta(weeks=w2)
        self.assets: list[Asset] = []
        self.issues: list[Issue] = []
        self.events: list[dict] = []

    # ------------------------------------------------------------------ helpers temporels
    def scan_time(self, source: str, week: int) -> datetime:
        return self.start + timedelta(weeks=week, days=SCAN_WEEKDAY[source], hours=SCAN_HOUR)

    def onboarded(self, entity: str, perimeter: str, week: int) -> bool:
        first = ONBOARDING_WEEK.get((entity, perimeter), 1)
        return first is not None and week + 1 >= first

    def days(self, lo: float, hi: float) -> timedelta:
        return timedelta(hours=self.rng.uniform(lo, hi) * 24)

    # ------------------------------------------------------------------ génération
    def build(self) -> None:
        self._build_assets()
        self._build_issues()
        for issue in self.issues:
            if issue.is_fp:
                self._plan_false_positive(issue)
            else:
                self._plan_true_positive(issue, issue.start, allow_branching=True)
        self.events.sort(key=lambda e: e["event_time"])

    def _pick(self, dist: dict[str, float]) -> str:
        keys = [k for k, v in dist.items() if v > 0]
        return self.rng.choices(keys, weights=[dist[k] for k in keys])[0]

    def _build_assets(self) -> None:
        owners = {e: OWNER_NAMES[i * 6:(i + 1) * 6] for i, e in enumerate(self.cfg["entities"])}
        for entity in self.cfg["entities"]:
            ent = entity.lower()
            for perimeter in ("M365", "ONEDRIVE", "SMB", "CLOUD", "SQLDB"):
                for i in range(ASSETS_PER_PERIMETER):
                    rgpd, types, sample, fname, table, classes = self.rng.choices(
                        PROFILES, weights=PROFILE_WEIGHTS)[0]
                    team = self.rng.choice(TEAMS)
                    owner_local = self.rng.choice(owners[entity])
                    env = "dev" if self.rng.random() < DEV_RATE[perimeter] else "prod"
                    stem, ext = fname.rsplit(".", 1)
                    fname_i = f"{stem}_{i:03d}.{ext}"
                    path = {
                        "M365": f"{ent}.sharepoint.test/sites/{team}/{fname_i}",
                        "ONEDRIVE": f"{ent}-my.sharepoint.test/personal/{owner_local.replace('.', '_')}"
                                    f"/Documents/{fname_i}",
                        "SMB": f"srv-{ent}-fic0{self.rng.randint(1, 3)}/{team}/{fname_i}",
                        "CLOUD": f"{ent}-{env}-exports/{team}/{fname_i}",
                        "SQLDB": f"sql-{ent}-0{self.rng.randint(1, 3)}/{team.upper()}_DB/dbo.{table}_{i:03d}",
                    }[perimeter]
                    location = "FR"
                    if perimeter == "CLOUD":
                        location = self.rng.choices(["FR", "IE", "US"], weights=[60, 15, 25])[0]
                    lo, hi = {"secret": (0, 1.3), "aucune": (0, 3), "sensible_art9": (1, 4.5)}.get(rgpd, (1, 5.7))
                    self.assets.append(Asset(
                        entity=entity, perimeter=perimeter, path=path,
                        owner=f"{owner_local}@{ent}.test", team=team,
                        classification=self.rng.choice(classes), rgpd=rgpd, data_types=list(types),
                        sample=self._fill_sample(sample), records=max(1, int(10 ** self.rng.uniform(lo, hi))),
                        encrypted=self.rng.random() < ENCRYPTED_RATE[perimeter], environment=env,
                        location=location, exposure=self._pick(EXPOSURE_DIST[perimeter]),
                    ))

    def _fill_sample(self, template: str) -> str:
        r = self.rng
        return template.format(d1=r.randint(1, 2), d3=f"{r.randint(0, 999):03d}", d4=f"{r.randint(0, 9999):04d}",
                               l=r.choice("abcdefghjklmnprstv"),
                               A4="".join(r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(4)))

    @staticmethod
    def candidate_types(a: Asset) -> list[str]:
        """Problèmes COHÉRENTS avec les attributs de l'actif (pas de 'non chiffré' sur un actif chiffré)."""
        out = []
        expo_type = {"public": "PUBLIC_EXPOSURE", "externe": "EXTERNAL_SHARING",
                     "groupe_large": "OVERLY_BROAD_GROUP"}.get(a.exposure)
        if expo_type and a.classification != "C0":
            out.append(expo_type)
        if not a.encrypted and a.classification in ("C2", "C3"):
            out.append("UNENCRYPTED")
        if a.environment == "dev" and a.classification in ("C2", "C3"):
            out.append("PROD_DATA_IN_DEV")
        if a.location == "US" and a.rgpd in ("personnelle", "bancaire", "sensible_art9"):
            out.append("NON_EU_LOCATION")
        if a.rgpd == "secret":
            out.append("EXPOSED_SECRET")
        return [t for t in out if a.perimeter in TYPE_PERIMETERS[t]]

    def _tier(self, issue_type: str, classification: str, rgpd: str, exposure: str) -> int:
        s = {"C0": 0, "C1": 1, "C2": 2, "C3": 3}[classification]
        s += 1 if rgpd in ("sensible_art9", "secret", "bancaire") else 0
        s += {"public": 3, "externe": 2, "groupe_large": 1, "restreint": 0}[exposure]
        s += {"EXPOSED_SECRET": 2, "PUBLIC_EXPOSURE": 1}.get(issue_type, 0)
        return 4 if s >= 7 else 3 if s >= 5 else 2 if s >= 3 else 1

    def _start_time(self) -> datetime:
        weights = [6.0] + [1.0] * 5 + [0.6] * (self.weeks - 6)
        week = self.rng.choices(range(self.weeks), weights=weights)[0]
        if week == 0:   # stock existant découvert au déploiement des outils
            return self.start - self.days(1, 90)
        return self.start + timedelta(weeks=week) + self.days(0, 7)

    def _new_issue(self, asset: Asset, alert_type: str, is_fp: bool, sources: list[str],
                   overrides: dict) -> Issue:
        tier = self._tier(alert_type, overrides.get("classification", asset.classification),
                          overrides.get("rgpd", asset.rgpd), overrides.get("exposure", asset.exposure))
        issue = Issue(asset, alert_type, is_fp, sources, overrides, self._start_time(), tier)
        issue.missed = {(s, w) for s in sources for w in range(self.weeks) if self.rng.random() > DETECTION_RATE}
        return issue

    def _build_issues(self) -> None:
        used: set[tuple[str, str]] = set()
        for a in self.assets:
            types = self.candidate_types(a)
            if a.rgpd in ("personnelle", "bancaire", "sensible_art9") and self.rng.random() < 0.15:
                types.append("RETENTION_EXCEEDED")
            if a.perimeter in TYPE_PERIMETERS["INACTIVE_ACCOUNT_ACCESS"] and self.rng.random() < 0.12:
                types.append("INACTIVE_ACCOUNT_ACCESS")
            for t in types:
                if self.rng.random() > 0.75:
                    continue
                covering = [s for s in SOURCES if a.perimeter in SOURCE_PERIMETERS[s]]
                sources = [s for s in covering if self.rng.random() < SOURCE_RECALL]
                if not sources:
                    continue       # angle mort : aucun outil ne le voit
                used.add((a.path, t))
                self.issues.append(self._new_issue(a, t, False, sources, {}))

        n_fp = round(len(self.issues) * FP_RATIO)
        for _ in range(n_fp):
            source, t, _, overrides = self.rng.choices(NOISY_RULES, weights=[r[2] for r in NOISY_RULES])[0]
            pool = [a for a in self.assets if a.perimeter in SOURCE_PERIMETERS[source]
                    and a.perimeter in TYPE_PERIMETERS[t] and (a.path, t) not in used]
            a = self.rng.choice(pool)
            used.add((a.path, t))
            sources = [source]
            others = [s for s in SOURCES if s != source and a.perimeter in SOURCE_PERIMETERS[s]]
            if others and self.rng.random() < 0.10:   # parfois un 2e outil se trompe aussi
                sources.append(self.rng.choice(others))
            self.issues.append(self._new_issue(a, t, True, sources, dict(overrides)))

    # ------------------------------------------------------------------ cycle de vie
    def first_detection(self, issue: Issue, after: datetime) -> datetime | None:
        best = None
        for s in issue.sources:
            for w in range(self.weeks):
                t = self.scan_time(s, w)
                if t < after or (s, w) in issue.missed:
                    continue
                if not self.onboarded(issue.asset.entity, issue.asset.perimeter, w):
                    continue
                best = t if best is None else min(best, t)
                break
        return best

    def _emit(self, issue: Issue, when: datetime, action: str, **extra) -> bool:
        """Ajoute une action analyste si elle tombe dans la période simulée."""
        if when >= self.end:
            return False
        self.events.append({"event_time": when, "fingerprint": issue.fingerprint, "action": action,
                            "actor": self.rng.choice(ANALYSTS), **extra})
        return True

    def triage_delay(self, tier: int) -> timedelta:
        lo, hi = {4: (0.1, 0.8), 3: (0.3, 2), 2: (1, 5), 1: (2, 10)}[tier]
        return self.days(lo, hi)

    def fix_delay(self, tier: int) -> timedelta:
        lo, hi = {4: (0.3, 3), 3: (2, 10), 2: (5, 40), 1: (10, 90)}[tier]
        return self.days(lo, hi)

    def _handle_chain(self, issue: Issue, t: datetime) -> datetime | None:
        """assign -> start ; renvoie l'instant de début des travaux (None si hors période)."""
        if not self._emit(issue, t, "assign", assignee=issue.asset.owner):
            return None
        t += self.days(0.1, 1.5)
        return t if self._emit(issue, t, "start") else None

    def _plan_true_positive(self, issue: Issue, start: datetime, allow_branching: bool) -> None:
        interval: list = [start, None]
        issue.intervals.append(interval)
        t0 = self.first_detection(issue, start)
        if t0 is None:
            return
        t = self._handle_chain(issue, t0 + self.triage_delay(issue.tier))
        if t is None:
            return
        t_fix = t + self.fix_delay(issue.tier)
        # Campagne de remédiation : une partie du stock est traitée pendant les semaines de campagne
        if t_fix > self.campaign_start and t < self.campaign_end and self.rng.random() < 0.65:
            t_fix = min(t_fix, max(t, self.campaign_start) + self.days(0.5, 13))

        if allow_branching and issue.alert_type in EXCEPTION_TYPES and issue.tier <= 3 \
                and self.rng.random() < 0.10:
            t_exc = t + self.days(1, 5)
            expires = t_exc + self.days(21, 50)
            if not self._emit(issue, t_exc, "accept_exception",
                              justification=self.rng.choice(EXCEPTION_JUSTIFICATIONS),
                              approver=f"RSSI {issue.asset.entity}", expires_at=expires):
                return
            if expires >= self.end:
                return                                  # exception toujours en cours
            # L'exception expire -> le pipeline rouvre l'incident -> nouvelle prise en charge
            t = self._handle_chain(issue, expires + self.days(0.5, 3))
            if t is None:
                return
            t_fix = t + self.days(3, 20)

        if not self._emit(issue, t_fix, "remediate"):
            return
        interval[1] = t_fix
        # Régression : le problème réapparaît (ex. lien de partage recréé)
        if allow_branching and t_fix < self.end - timedelta(days=14) and self.rng.random() < 0.10:
            self._plan_true_positive(issue, t_fix + self.days(5, 20), allow_branching=False)

    def _plan_false_positive(self, issue: Issue) -> None:
        # Un faux positif n'est jamais "corrigé" : l'outil continue de le remonter (suppression côté pipeline)
        issue.intervals.append([issue.start, None])
        t0 = self.first_detection(issue, issue.start)
        if t0 is None or self.rng.random() > 0.85:   # une partie des FP n'est jamais qualifiée
            return
        t = t0 + self.triage_delay(issue.tier)
        if self.rng.random() < 0.5:
            if not self._emit(issue, t, "assign", assignee=issue.asset.owner):
                return
            t += self.days(0.5, 3)
        self._emit(issue, t, "false_positive",
                   comment=f"Règle {issue.sources[0]}/{issue.alert_type} : faux positif confirmé")
