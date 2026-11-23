"""Ingestion -> normalisation -> consolidation -> priorisation -> workflow -> SQLite.

Usage : python -m scripts.ingest [--raw data/raw] [--db data/datarisk.db]
                                 [--datashield-db chemin/vers/datashield.db]
--datashield-db : remplace l'export DataShield simulé par la VRAIE base de DataShield DSPM Lab.
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from datarisk.config import DB_PATH, RAW_DIR, load_config
from datarisk.pipeline import run_pipeline
from datarisk.storage.db import init_db, purge_raw_alerts, write_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=RAW_DIR)
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--datashield-db", type=Path, default=None)
    args = parser.parse_args()

    cfg = load_config()
    result = run_pipeline(cfg, args.raw, args.datashield_db)
    conn = init_db(args.db, fresh=True)
    write_pipeline(conn, cfg, result, args.raw)
    purged = purge_raw_alerts(conn, result.period_end, cfg["retention"]["raw_alerts_days"])

    ing = result.ingest
    n_raw, n_inc = len(result.raw_links), len(result.incidents)
    print(f"Lignes lues par source  : {ing.rows_read}")
    print(f"Alertes normalisées     : {len(ing.alerts)}")
    reasons = Counter(r["reason"].split(" :")[0] for r in ing.rejected)
    print(f"Lignes en quarantaine   : {len(ing.rejected)} {dict(reasons)}")
    if ing.no_actionable_type:
        print(f"Alertes DataShield sans type actionnable (ignorées) : {ing.no_actionable_type}")
    print(f"Incidents consolidés    : {n_inc}  (réduction du bruit : {1 - n_inc / max(n_raw, 1):.1%})")
    print(f"Issues d'ingestion      : {dict(Counter(o for _, _, o in result.raw_links))}")
    print(f"Statuts des incidents   : {dict(Counter(i.status for i in result.incidents))}")
    print(f"Priorités               : {dict(sorted(Counter(i.priority for i in result.incidents).items()))}")
    print(f"Actions refusées        : {len(result.workflow_rejects)}")
    print(f"Observations purgées (rétention {cfg['retention']['raw_alerts_days']} j) : {purged}")
    print(f"Base écrite : {args.db}")


if __name__ == "__main__":
    main()
