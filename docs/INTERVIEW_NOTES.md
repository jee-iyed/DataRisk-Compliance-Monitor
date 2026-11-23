# Notes d'entretien — DataRisk Compliance Monitor

> Pour moi. Chiffres issus de `python -m scripts.simulate --seed 42 && python -m scripts.ingest &&
> python -m scripts.build_metrics`. Données **fictives** : je le dis toujours avant de citer un chiffre.

## 1. Le projet en une phrase
Un outil DSPM me dit *« ce fichier contient des IBAN et il est partagé publiquement »*. Mon projet répond à
la suite : *« sur les 2 000 alertes de 3 outils cette période, quels sont les 418 vrais sujets, lesquels
traiter d'abord, qui s'en occupe, est-ce qu'on tient les délais, et est-ce que le risque baisse ? »*

## 2. Pitch 45 secondes (lien avec DataShield)
« J'ai construit deux projets qui couvrent les deux moitiés d'une démarche DSPM. **DataShield DSPM Lab**
détecte : il scanne un SI fictif, classifie les données sensibles et calcule leur exposition. **DataRisk
Compliance Monitor** pilote, en aval : il ingère les alertes de plusieurs outils — dont DataShield via un
connecteur qui lit sa base — les normalise, les déduplique par empreinte, ce qui transforme 2 140 alertes
brutes en 418 incidents, les priorise avec un score explicable et des SLA, suit la remédiation avec un
workflow, des exceptions qui expirent et un historique d'audit, et calcule des KPI et des KRI hebdomadaires
avec dashboard et rapports. Sur 12 semaines simulées, on voit la campagne de remédiation faire baisser
l'indice de risque de 39 %, et on voit aussi ce qui ne va pas : le SLA P1 n'est tenu que dans 8 % des cas
et une règle de détection de secrets produit 53 % de faux positifs — exactement le type de constat que
l'équipe sécurité des données doit remonter. »

## 3. Chaque module en 2-3 phrases
| Module | Ce qu'il fait | Ce que je dis |
|---|---|---|
| `simulator/world.py` | Simule la **vérité** : 510 actifs, des problèmes cohérents avec leurs attributs (pas de « non chiffré » sur un actif chiffré), des faux positifs portés par des règles bruyantes, le comportement des analystes. | « Vérité d'abord, puis ce que chaque outil en voit : ça me donne une vérité terrain pour tester. » |
| `simulator/exports.py` | Écrit les exports au format de chaque outil, corrompt ~1 % des lignes. | « Les formats différents justifient la normalisation ; les lignes corrompues testent la quarantaine. » |
| `ingestion/normalize.py` | Tables de mapping par source → schéma commun ; validation ; garde-fou de masquage. | « Le mapping est du code lisible, pas de la magie ; une ligne invalide n'est jamais perdue. » |
| `ingestion/connectors.py` | Lit JSON / CSV / base SQLite DataShield ; met en quarantaine avec l'échantillon retiré. | « Le connecteur DataShield a été testé sur une vraie base : 161 alertes, 0 rejet. » |
| `consolidation/dedup.py` | Empreinte actif+type → incident ; fusion au plus défavorable ; réouverture ; suppression des FP. | « 1 incident = 1 problème sur 1 actif, quelle que soit la source. » |
| `prioritization/scoring.py` | Score 0-100 = 80 × sensibilité × exposition × volume + bonus ; P1-P4 ; SLA. | « Chaque point est justifié ; un auditeur peut refaire le calcul. » |
| `governance/workflow.py` | Transitions autorisées, exceptions (justif + validateur + expiration), audit. | « Une exception est un risque accepté, pas une remédiation ; elle expire. » |
| `pipeline.py` | Rejoue alertes + actions dans l'ordre du temps. | « Comme en production : chaque décision avec l'info disponible à l'instant T. » |
| `metrics/state.py` | Reconstitue l'état à une date depuis l'historique ; découpe en cycles. | « C'est ce qui permet un MTTR honnête et des tendances. » |
| `metrics/kpi.py`, `kri.py` | Fonctions pures DataFrame → nombre. | « Testées sur un jeu de 6 incidents où je connais chaque résultat de tête. » |
| `metrics/snapshots.py` | Photo hebdomadaire (format long). | « Flux sur la semaine, stocks à la date, qualité en cumulé. » |
| `reporting/report.py` | Contexte → Markdown + HTML ; synthèse et recommandations générées par règles. | « Rien n'est écrit à la main : rapport reproductible. » |
| `storage/schema.sql` | 12 tables, contraintes CHECK, index. | « SQL explicite, migrable vers PostgreSQL. » |
| `dashboard/app.py` | 4 vues : Direction, Opérationnelle, RGPD, Qualité. | « Une vue par public : comité, analyste, DPO, équipe outillage. » |

## 4. KPI vs KRI (avec exemples)
- **KPI** = *« est-ce que le dispositif fonctionne ? »* — couverture (93,3 %), MTTR (14,1 j), respect des SLA
  (72,6 %), taux de FP (19,3 %), réduction du bruit (80,5 %).
- **KRI** = *« à quel point sommes-nous exposés ? »* — actifs C3 exposés (2), enregistrements personnels non
  chiffrés (757 029), secrets non révoqués (6), indice de risque (18,8).
- Exemple de divergence : semaine 12, la réduction du bruit est bonne, mais le KRI « non chiffré » est
  rouge et continue de monter → le problème n'est pas l'outil mais un chantier d'infrastructure (chiffrement).
- Un KPI se pilote par l'équipe ; un KRI se pilote par le **métier / le propriétaire de la donnée** et
  remonte au comité des risques.

## 5. Chiffres exacts à citer (seed 42, données fictives)
- 510 actifs, 3 entités (Banque A, Banque B, Filiale Assurance), 5 périmètres, 12 semaines (31/08 → 22/11/2026).
- Lignes exportées : vendor A 600, vendor B 951, DataShield 575.
- **2 140 alertes normalisées → 418 incidents, réduction du bruit 80,5 %** ; 43,3 % des incidents corroborés
  par ≥ 2 sources.
- Quarantaine : 22 lignes sources (entité inconnue 10, volume négatif 3, dates invalides 2, sévérités
  inconnues 4, chemin manquant 1, exposition inconnue 1, **échantillon non masqué 1**) + 11 actions refusées.
- Priorités : P1 37 · P2 82 · P3 202 · P4 97.
- Taux de FP 19,3 % ; vendor A 25,2 %, vendor B 16,4 %, DataShield 4,9 %. Règle la plus bruyante `VA-SEC-01`
  (détection de secrets) : 53,3 %. **523 re-détections de FP supprimées**.
- MTTR 14,1 j (médiane 10,3) ; P1 5,5 j. SLA respectés 72,6 % — **P1 : 8,3 %**, P2 40,7 %, P3 83,6 %, P4 100 %.
- Campagne (semaine 6) : 64 remédiations contre 11 à 36 les autres semaines ; indice de risque 30,7 → 18,8
  (−39 %) ; backlog 102 → 60.
- Réouvertures : 18 (5,9 %). Exceptions : 18 accordées, 14 expirées puis redevenues des alertes.
- 77 tests pytest, ruff propre.

## 6. 15 questions probables
1. **Pourquoi ne pas avoir simplement utilisé le dashboard de l'outil DSPM ?** — Un collectif a plusieurs
   outils et plusieurs entités ; chaque outil voit son périmètre et compte ses propres alertes. Il faut une
   vue consolidée, dédupliquée et suivie dans le temps, avec nos SLA et nos indicateurs.
2. **Comment dédupliques-tu ?** — Empreinte sha256 du chemin canonique + type d'alerte. Les chemins sont
   canonisés à la normalisation (`smb://`, UNC `\\`, casse) : c'est ce qui fait que 2 outils retombent sur la
   même empreinte. Test de bout en bout : aucune empreinte fantôme vs la vérité terrain.
3. **Et si un fichier est renommé ?** — Nouvel incident : c'est une limite assumée. Amélioration : corréler
   par hash de contenu ou identifiant d'objet fourni par la source.
4. **Comment réduis-tu les faux positifs ?** — Je ne les supprime pas à l'aveugle : je les **mesure** par
   source, règle et type, je supprime les re-détections d'un FP déjà qualifié (523 ici), et je produis la liste
   des règles les plus bruyantes pour l'équipe qui règle l'outil. La corroboration multi-sources augmente
   la confiance (+5 au score).
5. **Pourquoi ce score et pas du machine learning ?** — Explicabilité et auditabilité : chaque point est
   justifié, les poids sont dans la config et testés. Pas de vérité terrain réelle pour entraîner un modèle.
6. **Pourquoi multiplier sensibilité × exposition ?** — Une donnée très sensible mais restreinte, ou une
   donnée publique mais anodine, ne doivent pas être critiques. Le produit exige les deux.
7. **Comment calcules-tu le MTTR si un incident est rouvert ?** — Par cycles : chaque ouverture (création,
   réouverture, fin d'exception) jusqu'à la clôture suivante. Un incident rouvert compte 2 cycles.
8. **Différence KPI / KRI ?** — Cf. §4, avec l'exemple du non-chiffré.
9. **Pourquoi le SLA P1 n'est tenu que dans 8 % des cas ?** — Dans la simulation, les analystes agissent sur
   une urgence perçue qui n'est pas exactement la priorité calculée, et 2 jours est exigeant. En vrai, c'est
   le constat à porter : SLA irréaliste, ou capacité insuffisante — à trancher avec le management.
10. **Comment gères-tu une exception ?** — Justification, validateur et date d'expiration obligatoires (sinon
    refusée). Elle sort du backlog mais reste comptée comme risque accepté et redevient une alerte à
    expiration (14 cas ici).
11. **Comment garantis-tu qu'aucune donnée sensible n'est stockée ?** — Les sources n'envoient que des
    métadonnées et des échantillons masqués ; en plus, un garde-fou rejette tout échantillon qui ressemble à
    une valeur en clair, et la quarantaine stocke la ligne **sans** l'échantillon. Un test vérifie qu'aucun
    échantillon non masqué n'atteint la base.
12. **Pourquoi SQLite ?** — Zéro installation et SQL standard lisible. En production : PostgreSQL ; les
    requêtes (fenêtres, CTE) sont quasi identiques.
13. **Comment le rapport est-il produit ?** — `generate_report.py --period weekly|monthly --date` : les
    indicateurs de la période et de la précédente sont recalculés depuis l'historique, la synthèse et les
    recommandations sont générées par règles (ex. règle avec ≥ 25 % de FP → recommandation de réglage).
14. **Que ferais-tu avec un vrai outil (Purview, Varonis…) ?** — Un connecteur de plus (API ou export), une
    table de mapping de plus ; le reste (consolidation, score, KPI) ne change pas : c'est l'intérêt du schéma
    commun. Puis brancher le workflow sur l'outil de ticketing (ServiceNow) au lieu d'un CSV.
15. **Quelles limites ?** — Données simulées, formats éditeurs inventés, SLA et poids arbitraires,
    corrélation par chemin seulement, pas de RBAC. Je les liste dans le README.

## 7. Démo en 3 minutes
1. `streamlit run dashboard/app.py` → **Direction** : 6 indicateurs colorés, indice de risque avec la bande
   « campagne », flux nouveaux vs remédiés, risque par entité.
2. **Opérationnelle** : filtrer P1/P2 à traiter, ouvrir un incident corroboré par 3 sources, montrer
   l'explication du score, le dépassement de SLA et l'historique d'audit.
3. **Qualité** : taux de FP par source, `VA-SEC-01` en tête des règles bruyantes.
4. Ouvrir `reports/examples/report_weekly_2026-11-22.html` : synthèse en 5 lignes, tendances, recommandations.
