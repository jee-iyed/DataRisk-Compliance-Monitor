from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

from datarisk.config import load_config
from datarisk.ingestion.normalize import NormalizedAlert, canonical_asset
from datarisk.pipeline import run_pipeline
from datarisk.simulator.exports import Exporter
from datarisk.simulator.world import World
from datarisk.storage.db import init_db, load_frames, write_pipeline, write_snapshots


@pytest.fixture(scope="session")
def cfg() -> dict:
    return load_config()


BASE_ALERT = NormalizedAlert(
    alert_id="x", source="dspm_vendor_a", source_alert_id="VA-1", rule_id="VA-PUB-01",
    alert_type="PUBLIC_EXPOSURE", entity="BQA", perimeter="M365",
    asset_path="https://bqa.sharepoint.test/sites/RH/paie.xlsx",
    asset_id=canonical_asset("https://bqa.sharepoint.test/sites/RH/paie.xlsx"),
    data_owner="a.moreau@bqa.test", data_types=["IBAN"], classification="C2", rgpd_category="bancaire",
    exposure="externe", encrypted=True, environment="prod", location="FR", in_eu=True, record_count=100,
    masked_sample="FR76 **** **** 189", first_seen=datetime(2026, 9, 1, 2), last_seen=datetime(2026, 9, 1, 2),
    status="open", raw_severity="high", normalized_severity=3,
)


def make_alert(**overrides) -> NormalizedAlert:
    """Alerte normalisée valide, modifiable champ par champ."""
    if "asset_path" in overrides and "asset_id" not in overrides:
        overrides["asset_id"] = canonical_asset(overrides["asset_path"])
    return replace(BASE_ALERT, data_types=list(BASE_ALERT.data_types), **overrides)


@pytest.fixture(scope="session")
def simulated(tmp_path_factory, cfg) -> dict:
    """Simulation seed 42 + pipeline complet + base SQLite + snapshots (partagé par les tests e2e)."""
    from datarisk.metrics.snapshots import weekly_snapshots

    root: Path = tmp_path_factory.mktemp("sim")
    raw = root / "raw"
    world = World(cfg, 42)
    world.build()
    Exporter(world).write(raw)
    result = run_pipeline(cfg, raw)
    conn = init_db(root / "datarisk.db")
    write_pipeline(conn, cfg, result, raw)
    frames = load_frames(conn)
    write_snapshots(conn, weekly_snapshots(frames, cfg))
    return {"root": root, "raw": raw, "world": world, "result": result, "conn": conn,
            "frames": load_frames(conn)}
