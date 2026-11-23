"""Catalogue des indicateurs : libellé, nature (KPI/KRI), unité, formule et raison d'être.
Source unique utilisée par le dashboard, les rapports (annexe méthodologique) et la documentation."""

from __future__ import annotations

INDICATORS: dict[str, dict[str, str]] = {
    # ----------------------------------------------------------------------------------- KPI
    "coverage_pct": {
        "label": "Couverture des périmètres", "kind": "KPI", "unit": "%",
        "formula": "(entité × périmètre) scannés sur la période / (entité × périmètre) attendus (config.scope)",
        "why": "Un risque non scanné est invisible : sans couverture, les KRI sont optimistes."},
    "raw_alerts": {
        "label": "Alertes brutes reçues", "kind": "KPI", "unit": "",
        "formula": "nb d'observations normalisées reçues sur la période (toutes sources)",
        "why": "Mesure la charge entrante avant consolidation."},
    "noise_reduction_pct": {
        "label": "Réduction du bruit", "kind": "KPI", "unit": "%",
        "formula": "1 − incidents distincts / alertes brutes (sur la même fenêtre)",
        "why": "Montre ce que la déduplication épargne aux analystes."},
    "new_incidents": {
        "label": "Nouveaux incidents", "kind": "KPI", "unit": "",
        "formula": "incidents créés sur la période", "why": "Flux entrant de risques."},
    "remediated": {
        "label": "Remédiations", "kind": "KPI", "unit": "",
        "formula": "passages au statut Remédiée sur la période", "why": "Flux sortant : capacité de traitement."},
    "fp_rate_pct": {
        "label": "Taux de faux positifs", "kind": "KPI", "unit": "%",
        "formula": "incidents « Faux positif » / incidents qualifiés (Remédiée + Faux positif + Exception)",
        "why": "Coût du bruit pour les équipes ; pilote le réglage des règles DSPM."},
    "mttr_mean_days": {
        "label": "MTTR moyen", "kind": "KPI", "unit": "j",
        "formula": "moyenne (date de remédiation − date d'ouverture du cycle), cycles remédiés",
        "why": "Vitesse de réduction du risque."},
    "mttr_median_days": {
        "label": "MTTR médian", "kind": "KPI", "unit": "j",
        "formula": "médiane du même délai", "why": "Moins sensible aux quelques dossiers très longs."},
    "sla_compliance_pct": {
        "label": "Respect des SLA", "kind": "KPI", "unit": "%",
        "formula": "cycles remédiés avant l'échéance SLA / cycles remédiés",
        "why": "Engagement de délai par priorité (P1 2 j, P2 7 j, P3 30 j, P4 90 j)."},
    "backlog": {
        "label": "Backlog à traiter", "kind": "KPI", "unit": "",
        "formula": "incidents Ouverte + Assignée + En cours à la date", "why": "Stock de travail."},
    "backlog_mean_age_days": {
        "label": "Âge moyen du backlog", "kind": "KPI", "unit": "j",
        "formula": "moyenne (date − ouverture du cycle) des incidents à traiter",
        "why": "Un backlog qui vieillit signale un problème de capacité ou d'appropriation."},
    "open_sla_breaches": {
        "label": "Incidents ouverts hors SLA", "kind": "KPI", "unit": "",
        "formula": "incidents à traiter dont l'échéance SLA est dépassée", "why": "À escalader."},
    "reopen_rate_pct": {
        "label": "Taux de réouverture", "kind": "KPI", "unit": "%",
        "formula": "transitions Remédiée → Ouverte (re-détection) / remédiations",
        "why": "Qualité des corrections (un lien de partage recréé, un fichier recopié…)."},
    # ----------------------------------------------------------------------------------- KRI
    "c3_exposed_public_external": {
        "label": "Actifs C3 exposés public / externe", "kind": "KRI", "unit": "",
        "formula": "actifs distincts C3 avec un incident à traiter « exposition publique » ou « partage externe »",
        "why": "Scénario de fuite le plus direct sur les données les plus sensibles."},
    "unencrypted_personal_records": {
        "label": "Enregistrements personnels non chiffrés", "kind": "KRI", "unit": "",
        "formula": "Σ enregistrements (dédupliqués par actif) des incidents « non chiffré » sur données "
                   "personnelles / bancaires / art. 9",
        "why": "Ordre de grandeur de l'impact d'une fuite (RGPD art. 32, notification art. 33-34)."},
    "open_exposed_secrets": {
        "label": "Secrets exposés non révoqués", "kind": "KRI", "unit": "",
        "formula": "incidents « secret exposé » à traiter",
        "why": "Un secret exposé ouvre un accès direct au SI."},
    "retention_exceeded": {
        "label": "Données hors durée de conservation", "kind": "KRI", "unit": "",
        "formula": "incidents « hors rétention » à traiter",
        "why": "Non-conformité RGPD art. 5.1.e et surface d'attaque inutile."},
    "p1_over_sla": {
        "label": "Incidents P1 hors SLA", "kind": "KRI", "unit": "",
        "formula": "incidents P1 à traiter dont l'échéance est dépassée",
        "why": "Risque critique connu et non traité dans les délais."},
    "risk_index": {
        "label": "Indice de risque", "kind": "KRI", "unit": "",
        "formula": "Σ scores des incidents à traiter / 100 (1 point ≈ 1 incident de score 100)",
        "why": "Agrégat comparable dans le temps et entre entités / périmètres."},
    "accepted_risks": {
        "label": "Risques acceptés (exceptions)", "kind": "KRI", "unit": "",
        "formula": "incidents en « Exception acceptée » à la date",
        "why": "Risque résiduel assumé : à revoir avant expiration."},
}
