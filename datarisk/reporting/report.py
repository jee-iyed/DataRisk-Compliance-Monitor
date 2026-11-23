"""Construction du rapport périodique : un CONTEXTE (données) rendu en Markdown et en HTML.

Toutes les phrases de la synthèse et des recommandations sont générées par des règles simples à
partir des chiffres : rien n'est écrit à la main, le rapport est reproductible.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from pathlib import Path

import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape

from datarisk.constants import ACTIVE_STATUSES, ALERT_TYPES, EXCEPTION, PRIORITY_LABELS, STATUS_LABELS
from datarisk.metrics import kpi
from datarisk.metrics.definitions import INDICATORS
from datarisk.metrics.kri import rag
from datarisk.metrics.snapshots import KPI_KEYS, KRI_KEYS, indicators
from datarisk.metrics.state import state_as_of

TEMPLATES = Path(__file__).with_name("templates")
RAG_ICON = {"vert": "🟢", "orange": "🟠", "rouge": "🔴", "n/a": "⚪", "": ""}


def period_window(period: str, day: date) -> tuple[pd.Timestamp, pd.Timestamp, pd.Timestamp]:
    """(début, fin exclue, début de la période précédente). Hebdo = 7 jours finissant à `day` ;
    mensuel = mois calendaire de `day` (jusqu'à `day` inclus)."""
    end = pd.Timestamp(day) + timedelta(days=1)
    if period == "weekly":
        start = end - timedelta(days=7)
        return start, end, start - timedelta(days=7)
    if period == "monthly":
        start = pd.Timestamp(day.replace(day=1))
        return start, end, pd.Timestamp((start - timedelta(days=1)).replace(day=1))
    raise ValueError(f"période inconnue : {period!r} (weekly | monthly)")


def trend(current: float | None, previous: float | None, direction: str | None) -> dict:
    """Flèche de tendance + jugement (amélioration / dégradation) selon le sens souhaité."""
    if current is None or previous is None:
        return {"arrow": "–", "delta": None, "judgement": ""}
    delta = round(current - previous, 1)
    arrow = "↑" if delta > 0 else "↓" if delta < 0 else "→"
    judgement = ""
    if delta and direction:
        better = delta < 0 if direction == "lower_is_better" else delta > 0
        judgement = "amélioration" if better else "dégradation"
    return {"arrow": arrow, "delta": delta, "judgement": judgement}


def fmt(value: float | None, unit: str = "") -> str:
    if value is None:
        return "n/a"
    text = f"{value:,.0f}".replace(",", " ") if float(value).is_integer() else f"{value:.1f}"
    return f"{text} {unit}".strip() if unit and unit != "%" else f"{text}{unit}"


def _incident_rows(df: pd.DataFrame, as_of: pd.Timestamp, sources: pd.DataFrame) -> list[dict]:
    names = sources.groupby("incident_id")["source_id"].apply(lambda s: ", ".join(sorted(set(s))))
    rows = []
    for r in df.itertuples(index=False):
        overdue = (as_of - r.sla_due).total_seconds() / 86400
        rows.append({
            "id": int(r.incident_id), "type": ALERT_TYPES[r.alert_type], "entity": r.entity_id,
            "perimeter": r.perimeter_id, "asset": r.asset_id, "owner": r.data_owner, "score": r.risk_score,
            "priority": r.priority, "status": STATUS_LABELS[r.status], "sla_due": r.sla_due.strftime("%Y-%m-%d"),
            "overdue_days": round(overdue, 1) if overdue > 0 else 0, "sources": names.get(r.incident_id, ""),
        })
    return rows


def build_context(frames: dict[str, pd.DataFrame], cfg: dict, period: str, day: date) -> dict:
    start, end, prev_start = period_window(period, day)
    cur = indicators(frames, cfg, end, start)
    prev = indicators(frames, cfg, start, prev_start)

    table = []
    for key in KPI_KEYS + KRI_KEYS:
        meta, threshold = INDICATORS[key], cfg["thresholds"].get(key)
        table.append({
            "key": key, "label": meta["label"], "kind": meta["kind"], "unit": meta["unit"],
            "current": fmt(cur[key], meta["unit"]), "previous": fmt(prev[key], meta["unit"]),
            "status": rag(cur[key], threshold) if threshold else "",
            **trend(cur[key], prev[key], threshold["direction"] if threshold else None),
        })

    st = state_as_of(frames["incidents"], frames["status_history"], end)
    active = st[st["status"].isin(ACTIVE_STATUSES)]
    top = active[active["priority"].isin(["P1", "P2"])].sort_values("risk_score", ascending=False).head(10)
    breaches = active[active["sla_due"] < end].sort_values(["priority", "sla_due"]).head(15)
    noisy = kpi.fp_rate_by(st, frames["incident_sources"], "rule_id")
    noisy = noisy[noisy["false_positives"] > 0].head(5)
    expiring = frames["exceptions"]
    expiring = expiring[(expiring["status"] == "active") & (expiring["granted_at"] < end)
                        & (expiring["expires_at"] >= end) & (expiring["expires_at"] < end + timedelta(days=30))]

    ctx = {
        "title": f"Rapport {'hebdomadaire' if period == 'weekly' else 'mensuel'} de sécurité des données",
        "period": period, "start": start.date(), "end": (end - timedelta(days=1)).date(),
        "prev_start": prev_start.date(), "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "cur": cur, "prev": prev, "table": table,
        "top_incidents": _incident_rows(top, end, frames["incident_sources"]),
        "sla_breaches": _incident_rows(breaches, end, frames["incident_sources"]),
        "n_breaches": int((active["sla_due"] < end).sum()),
        "noisy_rules": noisy.to_dict("records"),
        "risk_by_entity": (active.groupby("entity_id")["risk_score"].sum() / 100).round(1).to_dict(),
        "expiring_exceptions": len(expiring),
        "accepted": int((st["status"] == EXCEPTION).sum()),
        "quarantine": len(frames["rejected_alerts"]),
        "priority_labels": PRIORITY_LABELS,
        "definitions": INDICATORS, "cfg": cfg, "rag_icon": RAG_ICON,
    }
    ctx["summary"] = executive_summary(ctx)
    ctx["recommendations"] = recommendations(ctx)
    return ctx


def executive_summary(ctx: dict) -> list[str]:
    """Synthèse direction en 5 lignes, générée depuis les chiffres."""
    c, p, th = ctx["cur"], ctx["prev"], ctx["cfg"]["thresholds"]
    t = trend(c["risk_index"], p["risk_index"], "lower_is_better")
    reds = [r["label"] for r in ctx["table"] if r["status"] == "rouge"]
    worst_entity = max(ctx["risk_by_entity"], key=ctx["risk_by_entity"].get) if ctx["risk_by_entity"] else "n/a"
    noisy = ctx["noisy_rules"][0] if ctx["noisy_rules"] else None
    return [
        f"Indice de risque : {fmt(c['risk_index'])} ({t['arrow']} {fmt(abs(t['delta'] or 0))} vs période précédente, "
        f"{rag(c['risk_index'], th['risk_index'])}) ; entité la plus exposée : {worst_entity}.",
        f"{c['backlog']} incidents à traiter, dont {ctx['n_breaches']} hors SLA "
        f"(P1 hors SLA : {c['p1_over_sla']}).",
        f"Sur la période : {c['new_incidents']} nouveaux incidents, {c['remediated']} remédiations ; "
        f"{c['raw_alerts']} alertes brutes consolidées (réduction du bruit {fmt(c['noise_reduction_pct'], '%')}).",
        ("Indicateurs au rouge : " + ", ".join(reds) + ".") if reds else "Aucun indicateur au rouge.",
        f"Qualité : taux de faux positifs {fmt(c['fp_rate_pct'], '%')}"
        + (f", règle la plus bruyante {noisy['rule_id']} ({noisy['fp_rate_pct']} % de FP)." if noisy else "."),
    ]


def recommendations(ctx: dict) -> list[str]:
    """Recommandations déclenchées par des règles explicites sur les indicateurs."""
    c, th, out = ctx["cur"], ctx["cfg"]["thresholds"], []
    if c["p1_over_sla"]:
        out.append(f"Escalader les {c['p1_over_sla']} incident(s) P1 hors SLA auprès des propriétaires et du RSSI.")
    if c["open_exposed_secrets"]:
        out.append(f"Révoquer et faire tourner les {c['open_exposed_secrets']} secret(s) exposé(s), puis purger "
                   "les fichiers et l'historique qui les contiennent.")
    if rag(c["unencrypted_personal_records"], th["unencrypted_personal_records"]) != "vert":
        out.append(f"Prioriser le chiffrement des stockages portant {fmt(c['unencrypted_personal_records'])} "
                   "enregistrements personnels non chiffrés (RGPD art. 32).")
    if c["c3_exposed_public_external"]:
        out.append(f"Supprimer les liens publics / partages externes sur les {c['c3_exposed_public_external']} "
                   "actif(s) C3 concernés.")
    if c["retention_exceeded"]:
        out.append(f"Lancer l'archivage ou la purge des {c['retention_exceeded']} jeu(x) de données hors durée "
                   "de conservation (RGPD art. 5.1.e).")
    for rule in ctx["noisy_rules"]:
        if rule["fp_rate_pct"] >= 25:
            out.append(f"Demander à l'équipe outillage DSPM de revoir la règle {rule['rule_id']} "
                       f"({rule['fp_rate_pct']} % de faux positifs sur {rule['qualified']} incidents qualifiés).")
    if c["coverage_pct"] is not None and c["coverage_pct"] < 100:
        out.append(f"Étendre la couverture (actuellement {fmt(c['coverage_pct'], '%')}) aux périmètres non scannés.")
    if ctx["expiring_exceptions"]:
        out.append(f"Revoir les {ctx['expiring_exceptions']} exception(s) qui expirent dans les 30 jours.")
    return out or ["Aucune action prioritaire : maintenir le rythme de traitement."]


def render_markdown(ctx: dict) -> str:
    lines = [f"# {ctx['title']}", "",
             f"**Période :** {ctx['start']} → {ctx['end']} · comparée à la période débutant le {ctx['prev_start']}  ",
             f"**Généré le :** {ctx['generated_at']} · **Données : FICTIVES (simulation)**", "",
             "## 1. Synthèse direction", ""]
    lines += [f"{i}. {s}" for i, s in enumerate(ctx["summary"], 1)]
    lines += ["", "## 2. KPI / KRI vs période précédente", "",
              "| Type | Indicateur | Période | Précédente | Tendance | Statut |", "|---|---|---:|---:|:---:|:---:|"]
    for r in ctx["table"]:
        trend_txt = f"{r['arrow']} {r['judgement']}".strip()
        lines.append(f"| {r['kind']} | {r['label']} | {r['current']} | {r['previous']} | {trend_txt} | "
                     f"{RAG_ICON[r['status']]} {r['status']} |")
    lines += ["", "## 3. Top incidents P1 / P2 à traiter", ""]
    lines += _md_incidents(ctx["top_incidents"])
    lines += ["", f"## 4. Dépassements de SLA ({ctx['n_breaches']} incidents à traiter hors délai)", ""]
    lines += _md_incidents(ctx["sla_breaches"], overdue=True)
    lines += ["", "## 5. Règles les plus bruyantes (à remonter à l'équipe outillage DSPM)", "",
              "| Règle | Incidents qualifiés | Faux positifs | Taux FP |", "|---|---:|---:|---:|"]
    lines += [f"| {r['rule_id']} | {r['qualified']} | {r['false_positives']} | {r['fp_rate_pct']} % |"
              for r in ctx["noisy_rules"]]
    lines += ["", "## 6. Recommandations", ""] + [f"- {r}" for r in ctx["recommendations"]]
    lines += ["", "## Annexe — Méthodologie", "",
              "- Sources : 2 exports d'éditeurs DSPM simulés (JSON, CSV) + export DataShield DSPM Lab ; "
              f"{ctx['quarantine']} lignes en quarantaine (rejetées avec motif).",
              "- Consolidation : empreinte sha256(chemin canonique | type d'alerte) ; attributs au plus défavorable.",
              "- Score : 80 × sensibilité × exposition × volume + bonus (non chiffré, prod en dev, hors UE, secret, "
              "corroboration, persistance), borné à 100 ; P1 ≥ 60, P2 ≥ 45, P3 ≥ 28.",
              "- SLA : " + ", ".join(f"{k} = {v} j" for k, v in ctx["cfg"]["sla_days"].items()) + ".",
              "- Flux sur la période ; stocks à la fin de période ; qualité (FP, MTTR, SLA) cumulée depuis le début.",
              "", "| Indicateur | Type | Formule |", "|---|---|---|"]
    lines += [f"| {d['label']} | {d['kind']} | {d['formula']} |" for d in ctx["definitions"].values()]
    return "\n".join(lines) + "\n"


def _md_incidents(rows: list[dict], overdue: bool = False) -> list[str]:
    if not rows:
        return ["_Aucun._"]
    head = "| # | Prio | Score | Type | Entité | Actif | Propriétaire | Statut | Échéance |"
    out = [head + (" Retard (j) |" if overdue else ""), "|" + "---|" * (10 if overdue else 9)]
    for r in rows:
        out.append(f"| {r['id']} | {r['priority']} | {r['score']} | {r['type']} | {r['entity']} | `{r['asset']}` | "
                   f"{r['owner']} | {r['status']} | {r['sla_due']} |" + (f" {r['overdue_days']} |" if overdue else ""))
    return out


def render_html(ctx: dict) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    return env.get_template("report.html.j2").render(**ctx)
