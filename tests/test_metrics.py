"""KPI / KRI sur un petit jeu construit à la main : chaque valeur attendue est calculable de tête.

Scénario (as_of = 2026-10-01) :
  I1 PUBLIC_EXPOSURE C3 BQA A1  P1 : ouvert 09-01, remédié 09-04 (SLA 09-03 dépassé), réouvert 09-10 (ouvert)
  I2 UNENCRYPTED    C2 BQA A2  P3 : ouvert 09-01, remédié 09-11 (SLA 10-01 tenu)
  I3 UNENCRYPTED    C2 BQB A3  P2 : ouvert 09-05, en cours (SLA 09-12 dépassé), 500 enregistrements bancaires
  I4 EXPOSED_SECRET C3 BQB A4  P2 : ouvert 09-05, faux positif 09-06
  I5 RETENTION      C1 ASS A5  P4 : ouvert 09-10, exception 09-15
  I6 EXTERNAL_SHARING C3 ASS A6 P1 : ouvert 09-20 (SLA 09-22 dépassé)
"""

from __future__ import annotations

import pandas as pd
import pytest

from datarisk.metrics import kpi, kri
from datarisk.metrics.state import remediation_cycles, state_as_of

AS_OF = pd.Timestamp("2026-10-01")
D = pd.Timestamp


@pytest.fixture
def incidents() -> pd.DataFrame:
    rows = [
        (1, "PUBLIC_EXPOSURE", "BQA", "M365", "A1", "C3", "bancaire", "public", 100),
        (2, "UNENCRYPTED", "BQA", "SMB", "A2", "C2", "personnelle", "restreint", 1000),
        (3, "UNENCRYPTED", "BQB", "SMB", "A3", "C2", "bancaire", "restreint", 500),
        (4, "EXPOSED_SECRET", "BQB", "CLOUD", "A4", "C3", "secret", "restreint", 1),
        (5, "RETENTION_EXCEEDED", "ASS", "SMB", "A5", "C1", "personnelle", "restreint", 50),
        (6, "EXTERNAL_SHARING", "ASS", "ONEDRIVE", "A6", "C3", "bancaire", "externe", 20),
    ]
    cols = ["incident_id", "alert_type", "entity_id", "perimeter_id", "asset_id", "classification",
            "rgpd_category", "exposure", "record_count"]
    return pd.DataFrame(rows, columns=cols).assign(status="stale", priority="stale", risk_score=0.0)


@pytest.fixture
def history() -> pd.DataFrame:
    rows = [  # incident, date, de, vers, priorité, score, échéance SLA
        (1, "2026-09-01", None, "open", "P1", 80, "2026-09-03"),
        (1, "2026-09-02", "open", "assigned", "P1", 80, "2026-09-03"),
        (1, "2026-09-02 12:00", "assigned", "in_progress", "P1", 80, "2026-09-03"),
        (1, "2026-09-04", "in_progress", "remediated", "P1", 80, "2026-09-03"),
        (1, "2026-09-10", "remediated", "open", "P1", 80, "2026-09-12"),
        (2, "2026-09-01", None, "open", "P3", 35, "2026-10-01"),
        (2, "2026-09-02", "open", "assigned", "P3", 35, "2026-10-01"),
        (2, "2026-09-03", "assigned", "in_progress", "P3", 35, "2026-10-01"),
        (2, "2026-09-11", "in_progress", "remediated", "P3", 35, "2026-10-01"),
        (3, "2026-09-05", None, "open", "P2", 40, "2026-09-12"),
        (3, "2026-09-06", "open", "assigned", "P2", 40, "2026-09-12"),
        (3, "2026-09-07", "assigned", "in_progress", "P2", 40, "2026-09-12"),
        (4, "2026-09-05", None, "open", "P2", 50, "2026-09-12"),
        (4, "2026-09-06", "open", "false_positive", "P2", 50, "2026-09-12"),
        (5, "2026-09-10", None, "open", "P4", 20, "2026-12-09"),
        (5, "2026-09-15", "open", "exception_accepted", "P4", 20, "2026-12-09"),
        (6, "2026-09-20", None, "open", "P1", 60, "2026-09-22"),
    ]
    df = pd.DataFrame(rows, columns=["incident_id", "changed_at", "from_status", "to_status", "priority",
                                     "risk_score", "sla_due"])
    df["changed_at"] = pd.to_datetime(df["changed_at"], format="ISO8601")
    df["sla_due"] = pd.to_datetime(df["sla_due"], format="ISO8601")
    return df.assign(id=range(1, len(df) + 1), actor="test", reason="test")


@pytest.fixture
def state(incidents, history) -> pd.DataFrame:
    return state_as_of(incidents, history, AS_OF)


@pytest.fixture
def sources() -> pd.DataFrame:
    rows = [(1, "dspm_vendor_a", "VA-PUB-01"), (2, "dspm_vendor_b", "VB-103"), (2, "datashield", "DS-unencrypted"),
            (4, "dspm_vendor_a", "VA-SEC-01"), (5, "dspm_vendor_b", "VB-105")]
    return pd.DataFrame(rows, columns=["incident_id", "source_id", "rule_id"])


# ------------------------------------------------------------------------------ état / cycles
def test_state_is_reconstructed_at_any_date(incidents, history, state):
    assert state.set_index("incident_id")["status"].to_dict() == {
        1: "open", 2: "remediated", 3: "in_progress", 4: "false_positive", 5: "exception_accepted", 6: "open"}
    assert state.set_index("incident_id").loc[1, "opened_at"] == D("2026-09-10")  # début du cycle en cours
    early = state_as_of(incidents, history, D("2026-09-05 12:00")).set_index("incident_id")["status"]
    assert early.to_dict() == {1: "remediated", 2: "in_progress", 3: "open", 4: "open"}


def test_remediation_cycles(history):
    cycles = remediation_cycles(history)
    assert len(cycles) == 7                            # I1 compte 2 cycles (réouverture)
    i1 = cycles[cycles["incident_id"] == 1]
    assert i1["outcome"].iloc[0] == "remediated" and pd.isna(i1["outcome"].iloc[1])   # 2e cycle en cours
    assert cycles.set_index("incident_id").loc[5, "outcome"] == "exception_accepted"


# ------------------------------------------------------------------------------ KPI
def test_mttr_mean_median_and_by_priority(history):
    cycles = remediation_cycles(history)
    overall = kpi.mttr(cycles, by=None).iloc[0]
    assert (overall["n"], overall["mean_days"], overall["median_days"]) == (2, 6.5, 6.5)   # 3 j et 10 j
    assert kpi.mttr(cycles).set_index("priority")["mean_days"].to_dict() == {"P1": 3.0, "P3": 10.0}


def test_sla_compliance(history):
    assert kpi.sla_compliance(remediation_cycles(history)) == 50.0   # I1 en retard, I2 à l'heure
    assert kpi.sla_compliance_by_priority(remediation_cycles(history)) == {"P1": 0.0, "P3": 100.0}


def test_backlog_and_open_sla_breaches(state):
    b = kpi.backlog(state, AS_OF)
    assert b["backlog"] == 3 and b["by_priority"] == {"P1": 2, "P2": 1}
    assert b["mean_age_days"] == round((21 + 26 + 11) / 3, 1)
    assert kpi.open_sla_breaches(state, AS_OF) == 3


def test_reopen_rate(history):
    assert kpi.reopen_rate(history) == 50.0                       # 1 réouverture / 2 remédiations
    assert kpi.reopen_rate(history, D("2026-09-05")) == 0.0


def test_fp_rate_global_and_by_source_rule_type(state, sources):
    assert kpi.fp_rate(state) == pytest.approx(33.3)               # 1 FP / 3 qualifiés (I2, I4, I5)
    by_source = kpi.fp_rate_by(state, sources, "source_id").set_index("source_id")
    assert by_source.loc["dspm_vendor_a", "fp_rate_pct"] == 100.0
    assert by_source.loc["dspm_vendor_b", "fp_rate_pct"] == 0.0
    assert kpi.fp_rate_by(state, sources, "rule_id").iloc[0]["rule_id"] == "VA-SEC-01"
    by_type = kpi.fp_rate_by(state, sources, "alert_type").set_index("alert_type")
    assert by_type.loc["EXPOSED_SECRET", "false_positives"] == 1


def test_fp_rate_is_none_when_nothing_is_qualified(state):
    assert kpi.fp_rate(state[state["status"] == "open"]) is None


def test_coverage(cfg):
    cov = pd.DataFrame({
        "scan_date": pd.to_datetime(["2026-09-28", "2026-09-28", "2026-09-29", "2026-09-29", "2026-08-01"]),
        "source_id": ["a", "b", "a", "a", "a"],
        "entity_id": ["BQA", "BQA", "BQB", "BQA", "ASS"],
        "perimeter_id": ["M365", "M365", "SMB", "GIT", "SQLDB"],   # GIT hors scope, ASS/SQLDB hors fenêtre
    })
    res = kpi.coverage(cov, cfg["scope"], D("2026-09-24"), AS_OF)
    assert (res["scanned"], res["expected"], res["coverage_pct"]) == (2, 15, 13.3)
    assert "ASS/SQLDB" in res["missing"]


def test_noise_reduction_and_corroboration(sources):
    raw = pd.DataFrame({"incident_id": [1, 1, 1, 2, 2, 3, 9],
                        "last_seen": pd.to_datetime(["2026-09-01"] * 6 + ["2026-12-01"])})
    assert kpi.noise_reduction(raw, end=AS_OF) == {"raw_alerts": 6, "incidents": 3, "noise_reduction_pct": 50.0}
    assert kpi.corroboration_rate(sources) == 25.0                # I2 vu par 2 sources sur 4 incidents


# ------------------------------------------------------------------------------ KRI
def test_kri_values(state, incidents, history):
    assert kri.c3_exposed_public_external(state) == 2                 # A1 (public), A6 (externe)
    assert kri.unencrypted_personal_records(state) == 500             # I3 seul (I2 remédié)
    assert kri.open_exposed_secrets(state) == 0                       # I4 = faux positif
    assert kri.open_exposed_secrets(state_as_of(incidents, history, D("2026-09-05 12:00"))) == 1
    assert kri.retention_exceeded(state) == 0 and kri.accepted_risks(state) == 1
    assert kri.p1_over_sla(state, AS_OF) == 2                         # I1, I6
    assert kri.risk_index(state) == 1.8                               # (80 + 40 + 60) / 100
    assert kri.risk_index(state, by="entity_id").to_dict() == {"ASS": 0.6, "BQA": 0.8, "BQB": 0.4}


@pytest.mark.parametrize(("value", "threshold", "expected"), [
    (0, {"direction": "lower_is_better", "green": 0, "amber": 3}, "vert"),
    (3, {"direction": "lower_is_better", "green": 0, "amber": 3}, "orange"),
    (4, {"direction": "lower_is_better", "green": 0, "amber": 3}, "rouge"),
    (95, {"direction": "higher_is_better", "green": 95, "amber": 80}, "vert"),
    (80, {"direction": "higher_is_better", "green": 95, "amber": 80}, "orange"),
    (79.9, {"direction": "higher_is_better", "green": 95, "amber": 80}, "rouge"),
    (None, {"direction": "higher_is_better", "green": 95, "amber": 80}, "n/a"),
])
def test_rag_thresholds(value, threshold, expected):
    assert kri.rag(value, threshold) == expected
