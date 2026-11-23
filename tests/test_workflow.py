"""Workflow de remédiation, exceptions (justification, validateur, expiration) et audit."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from datarisk.consolidation.dedup import Consolidator
from datarisk.governance.workflow import InvalidTransition, Workflow
from tests.conftest import make_alert

T0 = datetime(2026, 9, 1, 2)


@pytest.fixture
def setup(cfg):
    wf = Workflow(cfg)
    cons = Consolidator(cfg, wf)
    inc, _ = cons.ingest(make_alert())
    return wf, cons, inc


def test_nominal_chain_is_audited(setup):
    wf, _, inc = setup
    wf.apply(inc, "assign", T0 + timedelta(hours=5), "analyste.1", assignee="a.moreau@bqa.test")
    wf.apply(inc, "start", T0 + timedelta(days=1), "analyste.1")
    wf.apply(inc, "remediate", T0 + timedelta(days=3), "analyste.1")
    assert inc.status == "remediated" and inc.resolved_at == T0 + timedelta(days=3)
    assert inc.assignee == "a.moreau@bqa.test"
    assert [(h["from_status"], h["to_status"]) for h in wf.history] == [
        (None, "open"), ("open", "assigned"), ("assigned", "in_progress"), ("in_progress", "remediated")]
    assert all(h["priority"] and h["sla_due"] for h in wf.history)


@pytest.mark.parametrize("action", ["remediate", "start"])
def test_forbidden_transitions(setup, action):
    wf, _, inc = setup
    with pytest.raises(InvalidTransition):
        wf.apply(inc, action, T0 + timedelta(days=1), "analyste.1")
    assert inc.status == "open" and len(wf.history) == 1


def test_unknown_action_is_refused(setup):
    wf, _, inc = setup
    with pytest.raises(InvalidTransition, match="action inconnue"):
        wf.apply(inc, "delete", T0, "analyste.1")


@pytest.mark.parametrize(("justification", "approver", "expires", "message"), [
    ("", "RSSI BQA", T0 + timedelta(days=30), "justification"),
    ("CCT signées", "", T0 + timedelta(days=30), "validateur"),
    ("CCT signées", "RSSI BQA", None, "expiration"),
    ("CCT signées", "RSSI BQA", T0, "expiration"),
])
def test_exception_requires_justification_approver_and_future_expiry(setup, justification, approver, expires,
                                                                     message):
    wf, _, inc = setup
    with pytest.raises(InvalidTransition, match=message):
        wf.apply(inc, "accept_exception", T0 + timedelta(days=1), "analyste.1", justification=justification,
                 approver=approver, expires_at=expires)
    assert inc.status == "open" and not wf.exceptions


def test_expired_exception_becomes_an_alert_again(setup, cfg):
    wf, cons, inc = setup
    granted, expiry = T0 + timedelta(days=1), T0 + timedelta(days=31)
    wf.apply(inc, "accept_exception", granted, "analyste.1", justification="Migration planifiée",
             approver="RSSI BQA", expires_at=expiry)
    assert inc.status == "exception_accepted"
    assert wf.expire_exceptions(cons.by_id, expiry - timedelta(seconds=1)) == 0
    assert wf.expire_exceptions(cons.by_id, expiry + timedelta(days=2)) == 1
    assert inc.status == "open" and inc.opened_at == expiry          # daté à l'expiration, pas à la détection
    assert inc.sla_due == expiry + timedelta(days=cfg["sla_days"][inc.priority])
    assert wf.exceptions[0].status == "expired"
    assert wf.history[-1]["reason"].startswith("exception n°1 expirée")
    assert inc.reopen_count == 0     # une fin d'exception n'est pas une régression


def test_priority_escalation_tightens_sla_but_never_relaxes_it(setup, cfg):
    wf, _, inc = setup
    first_due = inc.sla_due
    old = inc.priority
    inc.priority = "P1"
    wf.on_priority_change(inc, T0 + timedelta(days=1), old)
    assert inc.sla_due == min(first_due, inc.opened_at + timedelta(days=cfg["sla_days"]["P1"]))
    tightened = inc.sla_due
    inc.priority = "P4"
    wf.on_priority_change(inc, T0 + timedelta(days=1), "P1")
    assert inc.sla_due == tightened
    assert wf.history[-1]["reason"] == "priorité P1 -> P4"
