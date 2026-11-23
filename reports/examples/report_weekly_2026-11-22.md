# Rapport hebdomadaire de sécurité des données

**Période :** 2026-11-16 → 2026-11-22 · comparée à la période débutant le 2026-11-09  
**Généré le :** 2026-11-24 00:36 · **Données : FICTIVES (simulation)**

## 1. Synthèse direction

1. Indice de risque : 18.8 (↑ 2.7 vs période précédente, orange) ; entité la plus exposée : ASS.
2. 60 incidents à traiter, dont 18 hors SLA (P1 hors SLA : 2).
3. Sur la période : 21 nouveaux incidents, 11 remédiations ; 164 alertes brutes consolidées (réduction du bruit 20.1%).
4. Indicateurs au rouge : Respect des SLA, Enregistrements personnels non chiffrés, Secrets exposés non révoqués.
5. Qualité : taux de faux positifs 19.3%, règle la plus bruyante VA-SEC-01 (53.3 % de FP).

## 2. KPI / KRI vs période précédente

| Type | Indicateur | Période | Précédente | Tendance | Statut |
|---|---|---:|---:|:---:|:---:|
| KPI | Couverture des périmètres | 93.3% | 93.3% | → | 🟠 orange |
| KPI | Alertes brutes reçues | 164 | 160 | ↑ |   |
| KPI | Réduction du bruit | 20.1% | 21.2% | ↓ |   |
| KPI | Nouveaux incidents | 21 | 17 | ↑ |   |
| KPI | Remédiations | 11 | 16 | ↓ |   |
| KPI | Taux de faux positifs | 19.3% | 18.8% | ↑ dégradation | 🟠 orange |
| KPI | MTTR moyen | 14.1 j | 14 j | ↑ |   |
| KPI | MTTR médian | 10.3 j | 10.4 j | ↓ |   |
| KPI | Respect des SLA | 72.6% | 73.3% | ↓ dégradation | 🔴 rouge |
| KPI | Backlog à traiter | 60 | 51 | ↑ |   |
| KPI | Âge moyen du backlog | 30.2 j | 30.6 j | ↓ |   |
| KPI | Incidents ouverts hors SLA | 18 | 20 | ↓ |   |
| KPI | Taux de réouverture | 5.9% | 5.8% | ↑ dégradation | 🟠 orange |
| KRI | Actifs C3 exposés public / externe | 2 | 1 | ↑ dégradation | 🟢 vert |
| KRI | Enregistrements personnels non chiffrés | 757 029 | 629 483 | ↑ dégradation | 🔴 rouge |
| KRI | Secrets exposés non révoqués | 6 | 4 | ↑ dégradation | 🔴 rouge |
| KRI | Données hors durée de conservation | 6 | 3 | ↑ dégradation | 🟠 orange |
| KRI | Incidents P1 hors SLA | 2 | 2 | → | 🟠 orange |
| KRI | Indice de risque | 18.8 | 16.1 | ↑ dégradation | 🟠 orange |
| KRI | Risques acceptés (exceptions) | 4 | 6 | ↓ |   |

## 3. Top incidents P1 / P2 à traiter

| # | Prio | Score | Type | Entité | Actif | Propriétaire | Statut | Échéance |
|---|---|---|---|---|---|---|---|---|
| 395 | P1 | 61.4 | Compte inactif avec droits | BQB | `bqb.sharepoint.test/sites/rh/acces_applicatifs_025.txt` | g.bonnet@bqb.test | En cours | 2026-11-15 |
| 243 | P1 | 60.0 | Secret exposé | BQA | `bqa-my.sharepoint.test/personal/f_mercier/documents/note_interne_031.docx` | f.mercier@bqa.test | Ouverte | 2026-09-30 |
| 399 | P2 | 58.2 | Partage externe | ASS | `ass.sharepoint.test/sites/conformite/dossiers_salaries_002.xlsx` | q.blanc@ass.test | Ouverte | 2026-11-23 |
| 301 | P2 | 52.7 | Données non chiffrées | ASS | `srv-ass-fic02/rh/acces_applicatifs_029.txt` | m.henry@ass.test | En cours | 2026-11-22 |
| 211 | P2 | 49.7 | Partage externe | BQB | `bqb-my.sharepoint.test/personal/h_lambert/documents/config_deploiement_026.yaml` | h.lambert@bqb.test | Ouverte | 2026-09-28 |
| 36 | P2 | 48.2 | Secret exposé | BQA | `bqa.sharepoint.test/sites/finance/dossiers_salaries_027.xlsx` | d.roux@bqa.test | Ouverte | 2026-09-07 |
| 165 | P2 | 48.0 | Partage externe | BQA | `bqa-my.sharepoint.test/personal/d_roux/documents/annuaire_clients_005.xlsx` | d.roux@bqa.test | Ouverte | 2026-09-21 |
| 151 | P2 | 47.3 | Compte inactif avec droits | ASS | `ass.sharepoint.test/sites/conformite/export_cartes_027.csv` | m.henry@ass.test | Ouverte | 2026-09-18 |
| 410 | P2 | 47.1 | Groupe trop large | BQB | `srv-bqb-fic03/rh/dossiers_salaries_019.xlsx` | h.lambert@bqb.test | En cours | 2026-11-25 |
| 344 | P2 | 47.1 | Données non chiffrées | ASS | `srv-ass-fic01/juridique/annuaire_clients_031.xlsx` | o.faure@ass.test | En cours | 2026-10-28 |

## 4. Dépassements de SLA (18 incidents à traiter hors délai)

| # | Prio | Score | Type | Entité | Actif | Propriétaire | Statut | Échéance | Retard (j) |
|---|---|---|---|---|---|---|---|---|---|
| 243 | P1 | 60.0 | Secret exposé | BQA | `bqa-my.sharepoint.test/personal/f_mercier/documents/note_interne_031.docx` | f.mercier@bqa.test | Ouverte | 2026-09-30 | 53.9 |
| 395 | P1 | 61.4 | Compte inactif avec droits | BQB | `bqb.sharepoint.test/sites/rh/acces_applicatifs_025.txt` | g.bonnet@bqb.test | En cours | 2026-11-15 | 7.9 |
| 36 | P2 | 48.2 | Secret exposé | BQA | `bqa.sharepoint.test/sites/finance/dossiers_salaries_027.xlsx` | d.roux@bqa.test | Ouverte | 2026-09-07 | 76.9 |
| 123 | P2 | 45.4 | Groupe trop large | BQB | `srv-bqb-fic03/conformite/arrets_maladie_010.pdf` | k.robin@bqb.test | Ouverte | 2026-09-09 | 74.9 |
| 151 | P2 | 47.3 | Compte inactif avec droits | ASS | `ass.sharepoint.test/sites/conformite/export_cartes_027.csv` | m.henry@ass.test | Ouverte | 2026-09-18 | 65.9 |
| 165 | P2 | 48.0 | Partage externe | BQA | `bqa-my.sharepoint.test/personal/d_roux/documents/annuaire_clients_005.xlsx` | d.roux@bqa.test | Ouverte | 2026-09-21 | 62.9 |
| 211 | P2 | 49.7 | Partage externe | BQB | `bqb-my.sharepoint.test/personal/h_lambert/documents/config_deploiement_026.yaml` | h.lambert@bqb.test | Ouverte | 2026-09-28 | 55.9 |
| 249 | P2 | 45.4 | Groupe trop large | ASS | `sql-ass-01/it_db/dbo.app_users_025` | r.guerin@ass.test | Ouverte | 2026-10-07 | 46.9 |
| 344 | P2 | 47.1 | Données non chiffrées | ASS | `srv-ass-fic01/juridique/annuaire_clients_031.xlsx` | o.faure@ass.test | En cours | 2026-10-28 | 25.9 |
| 301 | P2 | 52.7 | Données non chiffrées | ASS | `srv-ass-fic02/rh/acces_applicatifs_029.txt` | m.henry@ass.test | En cours | 2026-11-22 | 0.5 |
| 19 | P3 | 28.6 | Secret exposé | BQA | `bqa-my.sharepoint.test/personal/a_moreau/documents/note_interne_033.docx` | a.moreau@bqa.test | Ouverte | 2026-09-30 | 53.9 |
| 51 | P3 | 34.3 | Partage externe | BQB | `bqb.sharepoint.test/sites/marketing/annuaire_clients_022.xlsx` | j.chevalier@bqb.test | Ouverte | 2026-09-30 | 53.9 |
| 247 | P3 | 38.6 | Groupe trop large | BQA | `bqa.sharepoint.test/sites/it/arrets_maladie_017.pdf` | e.fournier@bqa.test | Ouverte | 2026-10-30 | 23.9 |
| 304 | P3 | 39.0 | Groupe trop large | BQA | `srv-bqa-fic01/juridique/virements_clients_013.xlsx` | f.mercier@bqa.test | Ouverte | 2026-11-06 | 16.9 |
| 323 | P3 | 28.2 | Données non chiffrées | ASS | `srv-ass-fic02/commercial/virements_clients_017.xlsx` | q.blanc@ass.test | En cours | 2026-11-13 | 9.9 |

## 5. Règles les plus bruyantes (à remonter à l'équipe outillage DSPM)

| Règle | Incidents qualifiés | Faux positifs | Taux FP |
|---|---:|---:|---:|
| VA-SEC-01 | 45 | 24 | 53.3 % |
| VB-102 | 79 | 23 | 29.1 % |
| VB-105 | 24 | 11 | 45.8 % |
| VA-EXT-01 | 29 | 8 | 27.6 % |
| DS-inactive_accounts | 14 | 3 | 21.4 % |

## 6. Recommandations

- Escalader les 2 incident(s) P1 hors SLA auprès des propriétaires et du RSSI.
- Révoquer et faire tourner les 6 secret(s) exposé(s), puis purger les fichiers et l'historique qui les contiennent.
- Prioriser le chiffrement des stockages portant 757 029 enregistrements personnels non chiffrés (RGPD art. 32).
- Supprimer les liens publics / partages externes sur les 2 actif(s) C3 concernés.
- Lancer l'archivage ou la purge des 6 jeu(x) de données hors durée de conservation (RGPD art. 5.1.e).
- Demander à l'équipe outillage DSPM de revoir la règle VA-SEC-01 (53.3 % de faux positifs sur 45 incidents qualifiés).
- Demander à l'équipe outillage DSPM de revoir la règle VB-102 (29.1 % de faux positifs sur 79 incidents qualifiés).
- Demander à l'équipe outillage DSPM de revoir la règle VB-105 (45.8 % de faux positifs sur 24 incidents qualifiés).
- Demander à l'équipe outillage DSPM de revoir la règle VA-EXT-01 (27.6 % de faux positifs sur 29 incidents qualifiés).
- Étendre la couverture (actuellement 93.3%) aux périmètres non scannés.
- Revoir les 4 exception(s) qui expirent dans les 30 jours.

## Annexe — Méthodologie

- Sources : 2 exports d'éditeurs DSPM simulés (JSON, CSV) + export DataShield DSPM Lab ; 33 lignes en quarantaine (rejetées avec motif).
- Consolidation : empreinte sha256(chemin canonique | type d'alerte) ; attributs au plus défavorable.
- Score : 80 × sensibilité × exposition × volume + bonus (non chiffré, prod en dev, hors UE, secret, corroboration, persistance), borné à 100 ; P1 ≥ 60, P2 ≥ 45, P3 ≥ 28.
- SLA : P1 = 2 j, P2 = 7 j, P3 = 30 j, P4 = 90 j.
- Flux sur la période ; stocks à la fin de période ; qualité (FP, MTTR, SLA) cumulée depuis le début.

| Indicateur | Type | Formule |
|---|---|---|
| Couverture des périmètres | KPI | (entité × périmètre) scannés sur la période / (entité × périmètre) attendus (config.scope) |
| Alertes brutes reçues | KPI | nb d'observations normalisées reçues sur la période (toutes sources) |
| Réduction du bruit | KPI | 1 − incidents distincts / alertes brutes (sur la même fenêtre) |
| Nouveaux incidents | KPI | incidents créés sur la période |
| Remédiations | KPI | passages au statut Remédiée sur la période |
| Taux de faux positifs | KPI | incidents « Faux positif » / incidents qualifiés (Remédiée + Faux positif + Exception) |
| MTTR moyen | KPI | moyenne (date de remédiation − date d'ouverture du cycle), cycles remédiés |
| MTTR médian | KPI | médiane du même délai |
| Respect des SLA | KPI | cycles remédiés avant l'échéance SLA / cycles remédiés |
| Backlog à traiter | KPI | incidents Ouverte + Assignée + En cours à la date |
| Âge moyen du backlog | KPI | moyenne (date − ouverture du cycle) des incidents à traiter |
| Incidents ouverts hors SLA | KPI | incidents à traiter dont l'échéance SLA est dépassée |
| Taux de réouverture | KPI | transitions Remédiée → Ouverte (re-détection) / remédiations |
| Actifs C3 exposés public / externe | KRI | actifs distincts C3 avec un incident à traiter « exposition publique » ou « partage externe » |
| Enregistrements personnels non chiffrés | KRI | Σ enregistrements (dédupliqués par actif) des incidents « non chiffré » sur données personnelles / bancaires / art. 9 |
| Secrets exposés non révoqués | KRI | incidents « secret exposé » à traiter |
| Données hors durée de conservation | KRI | incidents « hors rétention » à traiter |
| Incidents P1 hors SLA | KRI | incidents P1 à traiter dont l'échéance est dépassée |
| Indice de risque | KRI | Σ scores des incidents à traiter / 100 (1 point ≈ 1 incident de score 100) |
| Risques acceptés (exceptions) | KRI | incidents en « Exception acceptée » à la date |
