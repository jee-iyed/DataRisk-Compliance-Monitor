# Décisions de conception

Chaque décision : le **choix**, la **raison**, l'**alternative écartée** et ce que ça **coûte**.

## D1. Un outil de pilotage, pas un détecteur
- **Choix** : partir des alertes produites par des outils DSPM (dont DataShield DSPM Lab) au lieu de
  rescanner les données.
- **Raison** : le poste vise l'exploitation d'un outil DSPM (alertes, écarts, faux positifs, dashboards,
  rapports). La valeur ajoutée est en aval : consolider, prioriser, suivre, rendre compte.
- **Écarté** : réimplémenter la détection (doublon avec DataShield).
- **Coût** : la qualité des incidents dépend de celle des sources ; on le mesure (taux de FP par source/règle).

## D2. KPI ≠ KRI
- **Choix** : deux familles séparées, avec des seuils vert/orange/rouge configurables.
- **Raison** : un KPI mesure le **dispositif** (couverture, MTTR, SLA, FP) ; un KRI mesure le **risque**
  (données C3 exposées, volume non chiffré, secrets). Une équipe peut être performante (KPI verts) pendant que
  le risque monte (KRI rouges) — ex. : dans la simulation, l'indice de risque baisse mais le volume non
  chiffré augmente.
- **Écarté** : un « score global » unique, qui masquerait ces divergences.

## D3. Normalisation vers un schéma commun + quarantaine
- **Choix** : chaque source a son normaliseur (tables de mapping explicites) ; une ligne invalide lève
  `RejectedRow(motif)` et part dans `rejected_alerts` avec l'échantillon **retiré**.
- **Raison** : formats hétérogènes (JSON/CSV, anglais/français, sévérité texte/1-5, dates ISO/FR). Ne jamais
  perdre une ligne silencieusement : la quarantaine est elle-même un indicateur de qualité des flux.
- **Écarté** : ignorer les lignes en erreur (perte d'information non tracée) ou les corriger à la volée
  (on inventerait des données).

## D4. Garde-fou de masquage à l'ingestion
- **Choix** : rejeter tout échantillon qui ressemble à une valeur en clair (≥ 8 chiffres consécutifs, e-mail
  sans `*`, clé AWS complète).
- **Raison** : un outil de pilotage ne doit pas devenir un nouveau dépôt de données sensibles (minimisation,
  RGPD art. 5.1.c). Défense en profondeur : on ne fait pas confiance au masquage des sources.
- **Coût** : faux rejets possibles (ex. un identifiant technique de 8 chiffres) — visibles en quarantaine.

## D5. Déduplication par empreinte déterministe
- **Choix** : `sha256(chemin canonique | type d'alerte)[:16]`.
- **Raison** : indépendante de la source (chemins canonisés), stable dans le temps (re-détections), et
  **référençable** par un outil tiers (le journal des analystes cible l'empreinte, pas un id interne).
- **Écarté** : un identifiant auto-incrémenté (non reproductible), une corrélation floue (non explicable).
- **Coût** : un fichier renommé/déplacé = nouvel incident (pas de corrélation par contenu).

## D6. Fusion des attributs au plus défavorable
- **Choix** : si deux sources divergent, on garde la classification la plus haute, l'exposition la plus
  large, « non chiffré » si une source le dit, etc.
- **Raison** : principe de précaution ; un sous-classement est plus coûteux qu'un sur-classement.
- **Coût** : peut gonfler la priorité si une source se trompe — compensé par la qualification FP.

## D7. Score déterministe et explicable, plutôt qu'un modèle
- **Choix** : formule multiplicative (sensibilité × exposition × volume) + bonus additifs, chaque contribution
  stockée.
- **Raison** : un analyste ou un auditeur doit pouvoir **refaire le calcul** et contester un poids. Le
  multiplicatif traduit qu'une donnée très sensible mais bien protégée n'est pas critique (et inversement).
- **Écarté** : ML (pas de vérité terrain réelle, non explicable), matrice qualitative (pas assez fine pour
  trier 400 incidents).
- **Coût** : les poids sont des choix ; ils sont centralisés dans `config.yaml` et testés (valeurs à la main).

## D8. SLA fixé à l'ouverture, qui se resserre mais ne se relâche jamais
- **Raison** : si la priorité monte (nouvelle source, exposition élargie), le délai doit raccourcir ; si elle
  baisse, on ne veut pas qu'un dépassement disparaisse « par magie ».

## D9. Rejeu chronologique (alertes + actions analystes)
- **Choix** : fusionner alertes normalisées et actions du journal, trier par horodatage, traiter dans l'ordre.
- **Raison** : les décisions dépendent du moment (une re-détection après remédiation = réouverture ; avant =
  simple mise à jour ; une exception expire à une date précise).
- **Coût** : une action qui référence un incident pas encore (ou jamais) ingéré est refusée et tracée.

## D10. Table d'audit riche et snapshots hebdomadaires
- **Choix** : chaque ligne de `status_history` porte statut, priorité, score et échéance SLA ; un job calcule
  une photo hebdomadaire (`metric_snapshots`, format long).
- **Raison** : MTTR et respect des SLA se calculent sur l'**historique réel** (cycles ouverture → clôture) ;
  les tendances et les comparaisons de période se font sans recalcul lourd ; format long = ajouter un
  indicateur ne change pas le schéma.
- **Écarté** : ne garder que l'état courant (impossible de calculer un MTTR honnête après une réouverture).

## D11. SQLite avec SQL explicite
- **Raison** : zéro installation, un fichier, SQL standard (fenêtres `LAG`, `ROW_NUMBER`) lisible en
  entretien ; le schéma est documenté et indexé.
- **Coût** : mono-utilisateur ; en production → PostgreSQL (le SQL est quasi identique).

## D12. KPI/KRI en fonctions pures
- **Choix** : `DataFrame → nombre`, sans accès base ni date « maintenant ».
- **Raison** : testables sur un petit jeu construit à la main (`tests/test_metrics.py`) ; la même fonction
  sert au dashboard, aux snapshots et aux rapports — une seule définition par indicateur.

## D13. Exceptions = risque accepté, compté à part
- **Raison** : une exception n'est pas une remédiation. Elle sort du backlog (décision prise) mais reste
  visible (`accepted_risks`) et redevient une alerte à expiration.

## D14. Simulation « vérité d'abord »
- **Choix** : simuler les vrais problèmes puis ce que les outils en voient, et écrire une vérité terrain que
  le pipeline ne lit pas.
- **Raison** : permet un test de bout en bout fort — aucune empreinte consolidée ne doit être « fantôme »
  malgré 3 formats de chemins — et rend la simulation reproductible (seed).
