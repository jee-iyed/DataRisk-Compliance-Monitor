"""Score explicable, niveaux de priorité et SLA (valeurs calculées à la main)."""

from __future__ import annotations

from datetime import datetime

import pytest

from datarisk.prioritization.scoring import compute_score, is_sla_breached, priority_for, sla_due, volume_factor

BASE = dict(alert_type="PUBLIC_EXPOSURE", classification="C3", rgpd_category="sensible_art9", exposure="public",
            record_count=1_000_000, encrypted=True, environment="prod", in_eu=True, source_count=1, age_weeks=0)


def test_volume_factor_bounds(cfg):
    assert volume_factor(0, cfg) == 0.6
    assert volume_factor(1_000_000, cfg) == 1.0
    assert volume_factor(10**9, cfg) == 1.0
    assert 0.6 < volume_factor(1000, cfg) < 1.0


def test_base_score_by_hand(cfg):
    # sensibilité min(1, 0.90 + 0.10) = 1.0 ; exposition public 1.0 ; volume 1.0 -> 80 × 1 × 1 × 1 = 80
    r = compute_score(**BASE, cfg=cfg)
    assert r.score == 80.0 and r.priority == "P1"
    assert [c["factor"] for c in r.contributions] == ["base"]


def test_bonuses_are_explained_and_sum_to_score(cfg):
    r = compute_score(**{**BASE, "classification": "C2", "rgpd_category": "bancaire", "exposure": "externe",
                         "record_count": 0, "encrypted": False, "environment": "dev", "in_eu": False,
                         "source_count": 2, "age_weeks": 3}, cfg=cfg)
    # base = 80 × min(1, 0.70 + 0.10) × 0.80 × 0.6 = 30.72 -> 30.7 ; bonus 6 + 6 + 5 + 5 + 3 = 25
    factors = {c["factor"]: c["points"] for c in r.contributions}
    assert factors == {"base": 30.7, "unencrypted": 6, "prod_in_dev": 6, "non_eu": 5, "corroborated": 5, "age": 3}
    assert r.score == pytest.approx(55.7) and r.priority == "P2"
    assert r.score == pytest.approx(sum(factors.values()))


def test_score_is_capped_at_100(cfg):
    r = compute_score(**{**BASE, "alert_type": "EXPOSED_SECRET", "encrypted": False, "environment": "dev",
                         "source_count": 3, "age_weeks": 10}, cfg=cfg)
    assert r.score == 100.0


def test_unencrypted_bonus_only_for_sensitive_data(cfg):
    r = compute_score(**{**BASE, "classification": "C1", "encrypted": False}, cfg=cfg)
    assert "unencrypted" not in {c["factor"] for c in r.contributions}


@pytest.mark.parametrize(("score", "level"), [(100, "P1"), (60, "P1"), (59.9, "P2"), (45, "P2"),
                                              (44.9, "P3"), (28, "P3"), (27.9, "P4"), (0, "P4")])
def test_priority_thresholds(cfg, score, level):
    assert priority_for(score, cfg) == level


def test_sla_due_and_breach(cfg):
    opened = datetime(2026, 9, 1, 10)
    assert sla_due(opened, "P1", cfg) == datetime(2026, 9, 3, 10)
    assert sla_due(opened, "P4", cfg) == datetime(2026, 11, 30, 10)
    due = sla_due(opened, "P2", cfg)
    assert not is_sla_breached(due, as_of=datetime(2026, 9, 5))
    assert is_sla_breached(due, as_of=datetime(2026, 9, 9))
    assert not is_sla_breached(due, as_of=datetime(2026, 12, 1), resolved_at=datetime(2026, 9, 7))
