-- =============================================================================================
-- DataRisk Compliance Monitor — 10 requêtes d'analyse commentées (SQLite)
-- Exécution : sqlite3 data/datarisk.db < docs/queries.sql
-- La date de référence '2026-11-23T00:00:00' est la fin de la période simulée (config.yaml).
-- "À traiter" = statuts open / assigned / in_progress.
-- Toutes ces requêtes sont exécutées par tests/test_queries.py (elles ne peuvent pas "pourrir").
-- =============================================================================================

-- Q1. Backlog par priorité, avec âge moyen et part hors SLA
SELECT priority,
       COUNT(*)                                                             AS a_traiter,
       ROUND(AVG(julianday('2026-11-23T00:00:00') - julianday(opened_at)), 1) AS age_moyen_j,
       SUM(sla_due < '2026-11-23T00:00:00')                                 AS hors_sla
FROM incidents
WHERE status IN ('open', 'assigned', 'in_progress')
GROUP BY priority
ORDER BY priority;

-- Q2. MTTR par entité, calculé sur l'historique (chaque remédiation est rapprochée de la
--     dernière ouverture qui la précède : un incident réouvert compte pour 2 cycles)
WITH remediations AS (
    SELECT h.incident_id, h.changed_at AS closed_at,
           (SELECT MAX(o.changed_at) FROM status_history o
             WHERE o.incident_id = h.incident_id AND o.to_status = 'open'
               AND (o.from_status IS NULL OR o.from_status <> 'open')
               AND o.changed_at <= h.changed_at) AS opened_at
    FROM status_history h
    WHERE h.to_status = 'remediated'
)
SELECT i.entity_id,
       COUNT(*)                                                         AS cycles_remedies,
       ROUND(AVG(julianday(r.closed_at) - julianday(r.opened_at)), 1)   AS mttr_moyen_j
FROM remediations r
JOIN incidents i ON i.incident_id = r.incident_id
GROUP BY i.entity_id
ORDER BY mttr_moyen_j DESC;

-- Q3. Dépassements de SLA en cours, du plus en retard au moins en retard
SELECT incident_id, priority, alert_type, entity_id, asset_id, data_owner, sla_due,
       ROUND(julianday('2026-11-23T00:00:00') - julianday(sla_due), 1) AS retard_j
FROM incidents
WHERE status IN ('open', 'assigned', 'in_progress')
  AND sla_due < '2026-11-23T00:00:00'
ORDER BY retard_j DESC;

-- Q4. Top 10 des actifs les plus risqués (somme des scores de leurs incidents à traiter)
SELECT asset_id, entity_id, perimeter_id,
       COUNT(*)                       AS incidents,
       ROUND(SUM(risk_score), 1)      AS risque_cumule,
       GROUP_CONCAT(alert_type, ', ') AS problemes
FROM incidents
WHERE status IN ('open', 'assigned', 'in_progress')
GROUP BY asset_id, entity_id, perimeter_id
ORDER BY risque_cumule DESC
LIMIT 10;

-- Q5. Évolution hebdomadaire de l'indice de risque, avec variation (fonction fenêtre LAG)
SELECT snapshot_date,
       value                                                    AS indice_risque,
       ROUND(value - LAG(value) OVER (ORDER BY snapshot_date), 1) AS variation
FROM metric_snapshots
WHERE scope_type = 'global' AND metric = 'risk_index'
ORDER BY snapshot_date;

-- Q6. Taux de faux positifs par source (parmi les incidents qualifiés qu'elle a remontés)
SELECT s.source_id,
       COUNT(DISTINCT i.incident_id)                                         AS qualifies,
       COUNT(DISTINCT CASE WHEN i.status = 'false_positive' THEN i.incident_id END) AS faux_positifs,
       ROUND(100.0 * COUNT(DISTINCT CASE WHEN i.status = 'false_positive' THEN i.incident_id END)
             / COUNT(DISTINCT i.incident_id), 1)                             AS taux_fp_pct
FROM incident_sources s
JOIN incidents i ON i.incident_id = s.incident_id
WHERE i.status IN ('remediated', 'false_positive', 'exception_accepted')
GROUP BY s.source_id
ORDER BY taux_fp_pct DESC;

-- Q7. Top 3 des incidents à traiter par entité (ROW_NUMBER)
SELECT entity_id, rang, incident_id, priority, risk_score, alert_type, asset_id
FROM (
    SELECT i.*, ROW_NUMBER() OVER (PARTITION BY entity_id ORDER BY risk_score DESC, incident_id) AS rang
    FROM incidents i
    WHERE status IN ('open', 'assigned', 'in_progress')
)
WHERE rang <= 3
ORDER BY entity_id, rang;

-- Q8. Propriétaires de données avec le plus d'incidents P1 / P2 à traiter
SELECT i.data_owner, o.display_name, i.entity_id,
       SUM(i.priority = 'P1') AS p1_ouverts,
       SUM(i.priority = 'P2') AS p2_ouverts
FROM incidents i
LEFT JOIN owners o ON o.owner_id = i.data_owner
WHERE i.status IN ('open', 'assigned', 'in_progress') AND i.priority IN ('P1', 'P2')
GROUP BY i.data_owner, o.display_name, i.entity_id
ORDER BY p1_ouverts DESC, p2_ouverts DESC
LIMIT 10;

-- Q9. Réduction du bruit : alertes brutes vs incidents distincts, par source et au total
SELECT source_id                                             AS source,
       COUNT(*)                                              AS alertes_brutes,
       COUNT(DISTINCT incident_id)                           AS incidents,
       ROUND(100.0 * (1 - 1.0 * COUNT(DISTINCT incident_id) / COUNT(*)), 1) AS reduction_pct
FROM raw_alerts
GROUP BY source_id
UNION ALL
SELECT 'TOTAL', COUNT(*), COUNT(DISTINCT incident_id),
       ROUND(100.0 * (1 - 1.0 * COUNT(DISTINCT incident_id) / COUNT(*)), 1)
FROM raw_alerts;

-- Q10. Règles les plus bruyantes + re-détections de FP supprimées (à remonter à l'équipe outillage)
--      (DISTINCT : une règle qui a émis 2 identifiants pour le même incident ne compte qu'une fois)
SELECT s.source_id, s.rule_id,
       COUNT(*)                                  AS incidents_qualifies,
       SUM(i.status = 'false_positive')          AS faux_positifs,
       ROUND(100.0 * SUM(i.status = 'false_positive') / COUNT(*), 1) AS taux_fp_pct,
       SUM(CASE WHEN i.status = 'false_positive' THEN i.suppressed_count ELSE 0 END) AS redetections_supprimees
FROM (SELECT DISTINCT incident_id, source_id, rule_id FROM incident_sources) s
JOIN incidents i ON i.incident_id = s.incident_id
WHERE i.status IN ('remediated', 'false_positive', 'exception_accepted')
GROUP BY s.source_id, s.rule_id
HAVING faux_positifs > 0
ORDER BY faux_positifs DESC, taux_fp_pct DESC
LIMIT 10;
