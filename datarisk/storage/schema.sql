-- =============================================================================================
-- DataRisk Compliance Monitor — schéma SQLite
-- Flux : raw_alerts (observations normalisées) -> incidents (consolidés) -> status_history (audit)
--        -> metric_snapshots (photo hebdomadaire des KPI/KRI pour les tendances)
-- Dates : texte ISO 8601 UTC ('YYYY-MM-DDTHH:MM:SS'), compatibles julianday().
-- =============================================================================================

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------------------ référentiels
CREATE TABLE IF NOT EXISTS sources (
    source_id   TEXT PRIMARY KEY,                -- dspm_vendor_a, dspm_vendor_b, datashield
    label       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entities (
    entity_id   TEXT PRIMARY KEY,                -- BQA, BQB, ASS
    name        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS perimeters (
    perimeter_id TEXT PRIMARY KEY,               -- M365, ONEDRIVE, SMB, CLOUD, SQLDB, GIT
    label        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS owners (
    owner_id     TEXT PRIMARY KEY,               -- adresse fictive (domaine .test)
    entity_id    TEXT REFERENCES entities(entity_id),
    display_name TEXT
);

-- Périmètres effectivement scannés, par source et par date de scan (KPI de couverture)
CREATE TABLE IF NOT EXISTS scan_coverage (
    scan_date      TEXT NOT NULL,
    source_id      TEXT NOT NULL REFERENCES sources(source_id),
    entity_id      TEXT NOT NULL REFERENCES entities(entity_id),
    perimeter_id   TEXT NOT NULL REFERENCES perimeters(perimeter_id),
    assets_scanned INTEGER NOT NULL,
    PRIMARY KEY (scan_date, source_id, entity_id, perimeter_id)
);

-- ------------------------------------------------------------------------------ incidents
CREATE TABLE IF NOT EXISTS incidents (
    incident_id       INTEGER PRIMARY KEY,
    fingerprint       TEXT    NOT NULL UNIQUE,   -- sha256(asset_id | alert_type)[:16]
    alert_type        TEXT    NOT NULL,
    entity_id         TEXT    NOT NULL REFERENCES entities(entity_id),
    perimeter_id      TEXT    NOT NULL REFERENCES perimeters(perimeter_id),
    asset_id          TEXT    NOT NULL,          -- chemin canonique
    asset_path        TEXT    NOT NULL,          -- chemin tel que vu par la 1re source
    data_owner        TEXT,
    data_types        TEXT    NOT NULL,          -- JSON
    classification    TEXT    NOT NULL CHECK (classification IN ('C0','C1','C2','C3')),
    rgpd_category     TEXT    NOT NULL,
    exposure          TEXT    NOT NULL,
    encrypted         INTEGER NOT NULL CHECK (encrypted IN (0,1)),
    environment       TEXT    NOT NULL,
    location          TEXT    NOT NULL,
    in_eu             INTEGER NOT NULL CHECK (in_eu IN (0,1)),
    record_count      INTEGER NOT NULL,
    max_severity      INTEGER NOT NULL,
    first_seen        TEXT    NOT NULL,
    last_seen         TEXT    NOT NULL,
    status            TEXT    NOT NULL CHECK (status IN
                      ('open','assigned','in_progress','remediated','false_positive','exception_accepted')),
    lifecycle         TEXT    NOT NULL,          -- nouvelle / recurrente / reouverte / resolue
    opened_at         TEXT    NOT NULL,          -- début du cycle en cours
    resolved_at       TEXT,
    assignee          TEXT,
    reopen_count      INTEGER NOT NULL DEFAULT 0,
    detection_count   INTEGER NOT NULL,
    suppressed_count  INTEGER NOT NULL DEFAULT 0, -- re-détections d'un faux positif déjà qualifié
    source_count      INTEGER NOT NULL,
    risk_score        REAL    NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    priority          TEXT    NOT NULL CHECK (priority IN ('P1','P2','P3','P4')),
    score_explanation TEXT    NOT NULL,          -- JSON : contributions du score
    sla_due           TEXT    NOT NULL
);

-- Quelles sources / règles ont vu quel incident (corroboration, FP par règle)
CREATE TABLE IF NOT EXISTS incident_sources (
    incident_id     INTEGER NOT NULL REFERENCES incidents(incident_id),
    source_id       TEXT    NOT NULL REFERENCES sources(source_id),
    source_alert_id TEXT    NOT NULL,
    rule_id         TEXT    NOT NULL,
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    detections      INTEGER NOT NULL,
    PRIMARY KEY (incident_id, source_id, source_alert_id)
);

-- Observations normalisées (1 ligne par alerte reçue), rattachées à leur incident
CREATE TABLE IF NOT EXISTS raw_alerts (
    alert_id            TEXT PRIMARY KEY,
    source_id           TEXT    NOT NULL REFERENCES sources(source_id),
    source_alert_id     TEXT    NOT NULL,
    rule_id             TEXT    NOT NULL,
    alert_type          TEXT    NOT NULL,
    entity_id           TEXT    NOT NULL,
    perimeter_id        TEXT    NOT NULL,
    asset_path          TEXT    NOT NULL,
    asset_id            TEXT    NOT NULL,
    data_owner          TEXT,
    data_types          TEXT    NOT NULL,
    classification      TEXT    NOT NULL,
    rgpd_category       TEXT    NOT NULL,
    exposure            TEXT    NOT NULL,
    encrypted           INTEGER NOT NULL,
    environment         TEXT    NOT NULL,
    location            TEXT    NOT NULL,
    in_eu               INTEGER NOT NULL,
    record_count        INTEGER NOT NULL,
    masked_sample       TEXT    NOT NULL,        -- toujours masqué (contrôlé à l'ingestion)
    first_seen          TEXT    NOT NULL,
    last_seen           TEXT    NOT NULL,
    status              TEXT,                    -- statut côté source
    raw_severity        TEXT    NOT NULL,
    normalized_severity INTEGER NOT NULL CHECK (normalized_severity BETWEEN 1 AND 4),
    incident_id         INTEGER NOT NULL REFERENCES incidents(incident_id),
    ingest_outcome      TEXT    NOT NULL         -- created / updated / reopened / suppressed_fp / under_exception
);

-- Quarantaine : lignes rejetées avec leur motif (jamais perdues silencieusement)
CREATE TABLE IF NOT EXISTS rejected_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id   TEXT NOT NULL,                   -- source, ou 'workflow' pour une action refusée
    file        TEXT NOT NULL,
    line_no     INTEGER,
    reason      TEXT NOT NULL,
    raw_record  TEXT NOT NULL,                   -- JSON, échantillon retiré
    rejected_at TEXT NOT NULL
);

-- ------------------------------------------------------------------------------ gouvernance
CREATE TABLE IF NOT EXISTS status_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL REFERENCES incidents(incident_id),
    changed_at   TEXT    NOT NULL,
    from_status  TEXT,                           -- NULL à la création
    to_status    TEXT    NOT NULL,
    actor        TEXT    NOT NULL,
    reason       TEXT    NOT NULL,
    priority     TEXT    NOT NULL,               -- priorité / score / SLA au moment du changement
    risk_score   REAL    NOT NULL,
    sla_due      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS exceptions (
    exception_id  INTEGER PRIMARY KEY,
    incident_id   INTEGER NOT NULL REFERENCES incidents(incident_id),
    justification TEXT    NOT NULL CHECK (length(justification) > 0),
    approver      TEXT    NOT NULL CHECK (length(approver) > 0),
    granted_at    TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL CHECK (expires_at > granted_at),
    status        TEXT    NOT NULL CHECK (status IN ('active','expired'))
);

-- ------------------------------------------------------------------------------ tendances
-- Format "long" : 1 ligne = 1 indicateur, pour 1 périmètre d'analyse, à 1 date
CREATE TABLE IF NOT EXISTS metric_snapshots (
    snapshot_date TEXT NOT NULL,                 -- fin de semaine (dimanche)
    scope_type    TEXT NOT NULL,                 -- global / entity / perimeter
    scope_value   TEXT NOT NULL,                 -- 'ALL', 'BQA', 'SMB'...
    metric        TEXT NOT NULL,
    value         REAL,
    PRIMARY KEY (snapshot_date, scope_type, scope_value, metric)
);

-- ------------------------------------------------------------------------------ index
CREATE INDEX IF NOT EXISTS idx_incidents_status_prio ON incidents (status, priority);
CREATE INDEX IF NOT EXISTS idx_incidents_entity      ON incidents (entity_id, perimeter_id);
CREATE INDEX IF NOT EXISTS idx_incidents_owner       ON incidents (data_owner);
CREATE INDEX IF NOT EXISTS idx_raw_incident          ON raw_alerts (incident_id);
CREATE INDEX IF NOT EXISTS idx_raw_source_seen       ON raw_alerts (source_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_history_incident      ON status_history (incident_id, changed_at);
CREATE INDEX IF NOT EXISTS idx_incsrc_source         ON incident_sources (source_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_metric      ON metric_snapshots (metric, scope_type, snapshot_date);
