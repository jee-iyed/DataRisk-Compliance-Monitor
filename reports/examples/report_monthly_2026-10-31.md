# Rapport mensuel de sécurité des données

**Période :** 2026-10-01 → 2026-10-31 · comparée à la période débutant le 2026-09-01  
**Généré le :** 2026-11-24 00:36 · **Données : FICTIVES (simulation)**

## 1. Synthèse direction

1. Indice de risque : 17.3 (↓ 18.4 vs période précédente, orange) ; entité la plus exposée : ASS.
2. 57 incidents à traiter, dont 14 hors SLA (P1 hors SLA : 1).
3. Sur la période : 96 nouveaux incidents, 147 remédiations ; 731 alertes brutes consolidées (réduction du bruit 65.8%).
4. Indicateurs au rouge : Respect des SLA, Enregistrements personnels non chiffrés, Secrets exposés non révoqués.
5. Qualité : taux de faux positifs 19%, règle la plus bruyante VB-102 (32.4 % de FP).

## 2. KPI / KRI vs période précédente

| Type | Indicateur | Période | Précédente | Tendance | Statut |
|---|---|---:|---:|:---:|:---:|
| KPI | Couverture des périmètres | 93.3% | 93.3% | → | 🟠 orange |
| KPI | Alertes brutes reçues | 731 | 882 | ↓ |   |
| KPI | Réduction du bruit | 65.8% | 70% | ↓ |   |
| KPI | Nouveaux incidents | 96 | 220 | ↓ |   |
| KPI | Remédiations | 147 | 113 | ↑ |   |
| KPI | Taux de faux positifs | 19% | 28% | ↓ amélioration | 🟠 orange |
| KPI | MTTR moyen | 13.8 j | 10.3 j | ↑ |   |
| KPI | MTTR médian | 10.3 j | 8.9 j | ↑ |   |
| KPI | Respect des SLA | 74.2% | 77.9% | ↓ dégradation | 🔴 rouge |
| KPI | Backlog à traiter | 57 | 111 | ↓ |   |
| KPI | Âge moyen du backlog | 22.5 j | 13.7 j | ↑ |   |
| KPI | Incidents ouverts hors SLA | 14 | 18 | ↓ |   |
| KPI | Taux de réouverture | 5.8% | 3.5% | ↑ dégradation | 🟠 orange |
| KRI | Actifs C3 exposés public / externe | 2 | 3 | ↓ amélioration | 🟢 vert |
| KRI | Enregistrements personnels non chiffrés | 465 849 | 697 120 | ↓ amélioration | 🔴 rouge |
| KRI | Secrets exposés non révoqués | 5 | 10 | ↓ amélioration | 🔴 rouge |
| KRI | Données hors durée de conservation | 6 | 12 | ↓ amélioration | 🟠 orange |
| KRI | Incidents P1 hors SLA | 1 | 4 | ↓ amélioration | 🟠 orange |
| KRI | Indice de risque | 17.3 | 35.7 | ↓ amélioration | 🟠 orange |
| KRI | Risques acceptés (exceptions) | 7 | 7 | → |   |

## 3. Top incidents P1 / P2 à traiter

| # | Prio | Score | Type | Entité | Actif | Propriétaire | Statut | Échéance |
|---|---|---|---|---|---|---|---|---|
| 243 | P1 | 60.0 | Secret exposé | BQA | `bqa-my.sharepoint.test/personal/f_mercier/documents/note_interne_031.docx` | f.mercier@bqa.test | Ouverte | 2026-09-30 |
| 211 | P2 | 49.7 | Partage externe | BQB | `bqb-my.sharepoint.test/personal/h_lambert/documents/config_deploiement_026.yaml` | h.lambert@bqb.test | Ouverte | 2026-09-28 |
| 148 | P2 | 48.6 | Données non chiffrées | BQA | `srv-bqa-fic01/marketing/dossiers_salaries_000.xlsx` | a.moreau@bqa.test | En cours | 2026-10-25 |
| 367 | P2 | 48.3 | Partage externe | BQB | `bqb.sharepoint.test/sites/it/dossiers_salaries_006.xlsx` | l.masson@bqb.test | Assignée | 2026-11-06 |
| 36 | P2 | 48.2 | Secret exposé | BQA | `bqa.sharepoint.test/sites/finance/dossiers_salaries_027.xlsx` | d.roux@bqa.test | Ouverte | 2026-09-07 |
| 165 | P2 | 48.0 | Partage externe | BQA | `bqa-my.sharepoint.test/personal/d_roux/documents/annuaire_clients_005.xlsx` | d.roux@bqa.test | Ouverte | 2026-09-21 |
| 151 | P2 | 47.3 | Compte inactif avec droits | ASS | `ass.sharepoint.test/sites/conformite/export_cartes_027.csv` | m.henry@ass.test | Ouverte | 2026-09-18 |
| 359 | P2 | 45.8 | Données non chiffrées | ASS | `sql-ass-02/juridique_db/dbo.comptes_007` | q.blanc@ass.test | En cours | 2026-11-04 |
| 362 | P2 | 45.6 | Groupe trop large | ASS | `srv-ass-fic03/conformite/dossiers_salaries_016.xlsx` | n.garnier@ass.test | Ouverte | 2026-11-04 |
| 123 | P2 | 45.4 | Groupe trop large | BQB | `srv-bqb-fic03/conformite/arrets_maladie_010.pdf` | k.robin@bqb.test | Ouverte | 2026-09-09 |

## 4. Dépassements de SLA (14 incidents à traiter hors délai)

| # | Prio | Score | Type | Entité | Actif | Propriétaire | Statut | Échéance | Retard (j) |
|---|---|---|---|---|---|---|---|---|---|
| 243 | P1 | 60.0 | Secret exposé | BQA | `bqa-my.sharepoint.test/personal/f_mercier/documents/note_interne_031.docx` | f.mercier@bqa.test | Ouverte | 2026-09-30 | 31.9 |
| 36 | P2 | 48.2 | Secret exposé | BQA | `bqa.sharepoint.test/sites/finance/dossiers_salaries_027.xlsx` | d.roux@bqa.test | Ouverte | 2026-09-07 | 54.9 |
| 123 | P2 | 45.4 | Groupe trop large | BQB | `srv-bqb-fic03/conformite/arrets_maladie_010.pdf` | k.robin@bqb.test | Ouverte | 2026-09-09 | 52.9 |
| 151 | P2 | 47.3 | Compte inactif avec droits | ASS | `ass.sharepoint.test/sites/conformite/export_cartes_027.csv` | m.henry@ass.test | Ouverte | 2026-09-18 | 43.9 |
| 165 | P2 | 48.0 | Partage externe | BQA | `bqa-my.sharepoint.test/personal/d_roux/documents/annuaire_clients_005.xlsx` | d.roux@bqa.test | Ouverte | 2026-09-21 | 40.9 |
| 211 | P2 | 49.7 | Partage externe | BQB | `bqb-my.sharepoint.test/personal/h_lambert/documents/config_deploiement_026.yaml` | h.lambert@bqb.test | Ouverte | 2026-09-28 | 33.9 |
| 249 | P2 | 45.4 | Groupe trop large | ASS | `sql-ass-01/it_db/dbo.app_users_025` | r.guerin@ass.test | Ouverte | 2026-10-07 | 24.9 |
| 148 | P2 | 48.6 | Données non chiffrées | BQA | `srv-bqa-fic01/marketing/dossiers_salaries_000.xlsx` | a.moreau@bqa.test | En cours | 2026-10-25 | 6.3 |
| 19 | P3 | 28.6 | Secret exposé | BQA | `bqa-my.sharepoint.test/personal/a_moreau/documents/note_interne_033.docx` | a.moreau@bqa.test | Ouverte | 2026-09-30 | 31.9 |
| 22 | P3 | 28.6 | Données hors durée de conservation (RGPD art. 5) | BQA | `bqa-my.sharepoint.test/personal/d_roux/documents/annuaire_clients_017.xlsx` | d.roux@bqa.test | En cours | 2026-09-30 | 31.9 |
| 51 | P3 | 34.3 | Partage externe | BQB | `bqb.sharepoint.test/sites/marketing/annuaire_clients_022.xlsx` | j.chevalier@bqb.test | Ouverte | 2026-09-30 | 31.9 |
| 247 | P3 | 38.6 | Groupe trop large | BQA | `bqa.sharepoint.test/sites/it/arrets_maladie_017.pdf` | e.fournier@bqa.test | Ouverte | 2026-10-30 | 1.9 |
| 255 | P3 | 37.4 | Compte inactif avec droits | ASS | `sql-ass-02/marketing_db/dbo.comptes_033` | p.andre@ass.test | En cours | 2026-10-30 | 1.9 |
| 268 | P3 | 38.0 | Données hors durée de conservation (RGPD art. 5) | BQB | `sql-bqb-02/juridique_db/dbo.salaries_002` | g.bonnet@bqb.test | En cours | 2026-10-30 | 1.9 |

## 5. Règles les plus bruyantes (à remonter à l'équipe outillage DSPM)

| Règle | Incidents qualifiés | Faux positifs | Taux FP |
|---|---:|---:|---:|
| VB-102 | 68 | 22 | 32.4 % |
| VA-SEC-01 | 38 | 18 | 47.4 % |
| VB-105 | 22 | 10 | 45.5 % |
| VA-EXT-01 | 23 | 6 | 26.1 % |
| DS-inactive_accounts | 13 | 3 | 23.1 % |

## 6. Recommandations

- Escalader les 1 incident(s) P1 hors SLA auprès des propriétaires et du RSSI.
- Révoquer et faire tourner les 5 secret(s) exposé(s), puis purger les fichiers et l'historique qui les contiennent.
- Prioriser le chiffrement des stockages portant 465 849 enregistrements personnels non chiffrés (RGPD art. 32).
- Supprimer les liens publics / partages externes sur les 2 actif(s) C3 concernés.
- Lancer l'archivage ou la purge des 6 jeu(x) de données hors durée de conservation (RGPD art. 5.1.e).
- Demander à l'équipe outillage DSPM de revoir la règle VB-102 (32.4 % de faux positifs sur 68 incidents qualifiés).
- Demander à l'équipe outillage DSPM de revoir la règle VA-SEC-01 (47.4 % de faux positifs sur 38 incidents qualifiés).
- Demander à l'équipe outillage DSPM de revoir la règle VB-105 (45.5 % de faux positifs sur 22 incidents qualifiés).
- Demander à l'équipe outillage DSPM de revoir la règle VA-EXT-01 (26.1 % de faux positifs sur 23 incidents qualifiés).
- Étendre la couverture (actuellement 93.3%) aux périmètres non scannés.
- Revoir les 1 exception(s) qui expirent dans les 30 jours.

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
