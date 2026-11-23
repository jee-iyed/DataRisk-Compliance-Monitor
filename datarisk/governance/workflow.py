"""Workflow de remédiation, exceptions et table d'audit (status_history).

    Ouverte -> Assignée -> En cours -> Remédiée | Faux positif | Exception acceptée

- Toute transition est contrôlée (TRANSITIONS) et journalisée avec la priorité, le score et l'échéance
  SLA du moment : on peut ainsi recalculer les délais réels et l'état à n'importe quelle date.
- Une exception exige justification + validateur + date d'expiration future. À expiration, l'incident
  redevient "Ouverte" (nouveau cycle, nouveau SLA).
- Remédiée -> Ouverte (réouverture) est déclenchée par une re-détection (cf. consolidation).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from datarisk.constants import (
    ACTIVE_STATUSES,
    ASSIGNED,
    CLOSED_STATUSES,
    EXCEPTION,
    FALSE_POSITIVE,
    IN_PROGRESS,
    OPEN,
    REMEDIATED,
)
from datarisk.prioritization.scoring import sla_due

if TYPE_CHECKING:
    from datarisk.consolidation.dedup import Incident

TRANSITIONS: dict[str, set[str]] = {
    OPEN: {ASSIGNED, FALSE_POSITIVE, EXCEPTION},
    ASSIGNED: {IN_PROGRESS, FALSE_POSITIVE, EXCEPTION},
    IN_PROGRESS: {REMEDIATED, FALSE_POSITIVE, EXCEPTION},
    REMEDIATED: {OPEN},          # réouverture (re-détection)
    FALSE_POSITIVE: {OPEN},      # requalification manuelle
    EXCEPTION: {OPEN},           # expiration de l'exception
}
ACTIONS = {"assign": ASSIGNED, "start": IN_PROGRESS, "remediate": REMEDIATED,
           "false_positive": FALSE_POSITIVE, "accept_exception": EXCEPTION, "reopen": OPEN}


class InvalidTransition(ValueError):
    pass


@dataclass
class ExceptionRecord:
    exception_id: int
    incident_id: int
    justification: str
    approver: str
    granted_at: datetime
    expires_at: datetime
    status: str = "active"          # active | expired


def can_transition(current: str | None, target: str) -> bool:
    return current is None and target == OPEN or target in TRANSITIONS.get(current or "", set())


def validate_exception(justification: str | None, approver: str | None, expires_at: datetime | None,
                       at: datetime) -> None:
    if not (justification or "").strip():
        raise InvalidTransition("exception refusée : justification obligatoire")
    if not (approver or "").strip():
        raise InvalidTransition("exception refusée : validateur obligatoire")
    if expires_at is None or expires_at <= at:
        raise InvalidTransition("exception refusée : date d'expiration future obligatoire")


class Workflow:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.history: list[dict] = []
        self.exceptions: list[ExceptionRecord] = []

    def _log(self, inc: Incident, at: datetime, frm: str | None, to: str, actor: str, reason: str) -> None:
        self.history.append({
            "incident_id": inc.incident_id, "changed_at": at, "from_status": frm, "to_status": to,
            "actor": actor, "reason": reason, "priority": inc.priority, "risk_score": inc.risk_score,
            "sla_due": inc.sla_due,
        })

    def open(self, inc: Incident, at: datetime, reason: str, actor: str = "pipeline") -> None:
        """Ouverture d'un cycle : création, réouverture ou fin d'exception. Fixe l'échéance SLA."""
        previous = inc.status
        if not can_transition(previous, OPEN):
            raise InvalidTransition(f"{previous} -> {OPEN} interdit")
        if previous is not None:
            inc.reopen_count += 1 if previous == REMEDIATED else 0
        inc.status, inc.opened_at, inc.resolved_at, inc.assignee = OPEN, at, None, None
        inc.sla_due = sla_due(at, inc.priority, self.cfg)
        self._log(inc, at, previous, OPEN, actor, reason)

    def apply(self, inc: Incident, action: str, at: datetime, actor: str, *, assignee: str | None = None,
              justification: str | None = None, approver: str | None = None,
              expires_at: datetime | None = None, comment: str | None = None) -> None:
        if action not in ACTIONS:
            raise InvalidTransition(f"action inconnue : {action!r}")
        target = ACTIONS[action]
        if target == OPEN:
            self.open(inc, at, comment or "requalification manuelle", actor)
            return
        if not can_transition(inc.status, target):
            raise InvalidTransition(f"transition interdite : {inc.status} -> {target}")
        reason = comment or action
        if target == EXCEPTION:
            validate_exception(justification, approver, expires_at, at)
            assert expires_at is not None
            self.exceptions.append(ExceptionRecord(len(self.exceptions) + 1, inc.incident_id,
                                                   justification or "", approver or "", at, expires_at))
            reason = f"exception validée par {approver} jusqu'au {expires_at.date()} : {justification}"
        if target == ASSIGNED:
            inc.assignee = assignee
        if target in CLOSED_STATUSES:
            inc.resolved_at = at
        previous, inc.status = inc.status, target
        self._log(inc, at, previous, target, actor, reason)

    def expire_exceptions(self, incidents_by_id: dict[int, Incident], now: datetime) -> int:
        """Les exceptions arrivées à échéance rouvrent l'incident (daté à l'expiration)."""
        expired = 0
        for exc in self.exceptions:
            if exc.status == "active" and exc.expires_at <= now:
                exc.status = "expired"
                inc = incidents_by_id[exc.incident_id]
                if inc.status == EXCEPTION:
                    self.open(inc, exc.expires_at, f"exception n°{exc.exception_id} expirée", "pipeline")
                    expired += 1
        return expired

    def on_priority_change(self, inc: Incident, at: datetime, old_priority: str) -> None:
        """Une priorité qui monte resserre l'échéance SLA (elle ne se relâche jamais)."""
        if inc.status not in ACTIVE_STATUSES or inc.opened_at is None or inc.sla_due is None:
            return
        inc.sla_due = min(inc.sla_due, sla_due(inc.opened_at, inc.priority, self.cfg))
        self._log(inc, at, inc.status, inc.status, "pipeline",
                  f"priorité {old_priority} -> {inc.priority}")
