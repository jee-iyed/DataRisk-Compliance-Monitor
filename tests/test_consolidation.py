"""Déduplication par empreinte, corroboration, cycle de vie (récurrence, réouverture, suppression FP)."""

from __future__ import annotations

from datetime import datetime, timedelta

from datarisk.consolidation.dedup import Consolidator, fingerprint
from datarisk.governance.workflow import Workflow
from tests.conftest import make_alert

T0 = datetime(2026, 9, 1, 2)


def new_consolidator(cfg) -> Consolidator:
    return Consolidator(cfg, Workflow(cfg))


def test_fingerprint_is_deterministic_and_type_sensitive():
    assert fingerprint("srv/rh/a.xlsx", "UNENCRYPTED") == fingerprint("srv/rh/a.xlsx", "UNENCRYPTED")
    assert fingerprint("srv/rh/a.xlsx", "UNENCRYPTED") != fingerprint("srv/rh/a.xlsx", "PUBLIC_EXPOSURE")
    assert len(fingerprint("x", "y")) == 16


def test_two_sources_same_asset_become_one_corroborated_incident(cfg):
    cons = new_consolidator(cfg)
    a = make_alert(source="dspm_vendor_a", asset_path="smb://SRV-01/RH/paie.xlsx", perimeter="SMB")
    b = make_alert(source="dspm_vendor_b", source_alert_id="B1", rule_id="VB-100",
                   asset_path=r"\\srv-01\rh\paie.xlsx", perimeter="SMB", last_seen=T0 + timedelta(days=2))
    inc_a, out_a = cons.ingest(a)
    inc_b, out_b = cons.ingest(b)
    assert inc_a is inc_b and (out_a, out_b) == ("created", "updated")
    assert len(cons.incidents) == 1
    assert inc_a.source_names == ["dspm_vendor_a", "dspm_vendor_b"]
    assert any(c["factor"] == "corroborated" for c in inc_a.explanation)


def test_redetection_next_week_is_recurring_not_new(cfg):
    cons = new_consolidator(cfg)
    inc, _ = cons.ingest(make_alert())
    cons.ingest(make_alert(last_seen=T0 + timedelta(weeks=1)))
    assert inc.detection_count == 2 and inc.lifecycle == "recurrente"
    assert inc.sources[("dspm_vendor_a", "VA-1")]["detections"] == 2


def test_attributes_are_merged_with_precaution(cfg):
    cons = new_consolidator(cfg)
    inc, _ = cons.ingest(make_alert(classification="C1", exposure="restreint", encrypted=True, record_count=10))
    cons.ingest(make_alert(source="datashield", source_alert_id="7/X", classification="C3", exposure="public",
                           encrypted=False, record_count=5, in_eu=False, location="US", rgpd_category="sensible_art9"))
    assert (inc.classification, inc.exposure, inc.encrypted, inc.record_count) == ("C3", "public", False, 10)
    assert (inc.in_eu, inc.location, inc.rgpd_category) == (False, "US", "sensible_art9")


def test_redetection_after_remediation_reopens(cfg):
    cons = new_consolidator(cfg)
    wf = cons.workflow
    inc, _ = cons.ingest(make_alert())
    for action, day in (("assign", 1), ("start", 2), ("remediate", 3)):
        wf.apply(inc, action, T0 + timedelta(days=day), "analyste.1")
    _, outcome = cons.ingest(make_alert(last_seen=T0 + timedelta(days=10)))
    assert outcome == "reopened" and inc.status == "open" and inc.reopen_count == 1
    assert inc.opened_at == T0 + timedelta(days=10) and inc.lifecycle == "reouverte"


def test_false_positive_redetections_are_suppressed(cfg):
    cons = new_consolidator(cfg)
    inc, _ = cons.ingest(make_alert())
    cons.workflow.apply(inc, "false_positive", T0 + timedelta(days=1), "analyste.1")
    _, outcome = cons.ingest(make_alert(last_seen=T0 + timedelta(days=7)))
    assert outcome == "suppressed_fp" and inc.status == "false_positive" and inc.suppressed_count == 1
