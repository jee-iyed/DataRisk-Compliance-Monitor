"""Dashboard Streamlit — 4 vues : Direction, Opérationnelle, Conformité RGPD, Qualité.

Lancement : streamlit run dashboard/app.py   (après simulate -> ingest -> build_metrics)
Lecture seule sur data/datarisk.db : le dashboard n'écrit rien.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from datarisk.config import DB_PATH, load_config  # noqa: E402
from datarisk.constants import ACTIVE_STATUSES, ALERT_TYPES, STATUS_LABELS  # noqa: E402
from datarisk.metrics import kpi  # noqa: E402
from datarisk.metrics.definitions import INDICATORS  # noqa: E402
from datarisk.metrics.kri import rag  # noqa: E402
from datarisk.metrics.snapshots import snapshot_frame  # noqa: E402
from datarisk.metrics.state import state_as_of  # noqa: E402
from datarisk.pipeline import period_end  # noqa: E402
from datarisk.storage.db import connect, load_frames  # noqa: E402

st.set_page_config(page_title="DataRisk Compliance Monitor", page_icon="🛡️", layout="wide")
RAG_COLORS = {"vert": "#2f9e44", "orange": "#e8890c", "rouge": "#d64545", "n/a": "#868e96"}
RAG_ICONS = {"vert": "🟢", "orange": "🟠", "rouge": "🔴", "n/a": "⚪"}
PRIO_COLORS ={"P1": "#c92a2a", "P2": "#e8590c", "P3": "#f2c94c", "P4": "#91a7ff"}
TEMPLATE = "plotly_white"
HIGHER_IS_BETTER = {"coverage_pct", "sla_compliance_pct", "remediated", "noise_reduction_pct"}


@st.cache_data
def load() -> tuple[dict, dict]:
    if not DB_PATH.exists():
        st.error("Base absente : lancez `python -m scripts.simulate`, `python -m scripts.ingest` puis "
                 "`python -m scripts.build_metrics`.")
        st.stop()
    return load_config(), load_frames(connect(DB_PATH))


cfg, f = load()
AS_OF = pd.Timestamp(period_end(cfg))
state = state_as_of(f["incidents"], f["status_history"], AS_OF)
active = state[state["status"].isin(ACTIVE_STATUSES)].copy()
active["hors_sla"] = active["sla_due"] < AS_OF
weekly = snapshot_frame(f["metric_snapshots"])
c_start, c_end = cfg["simulation"]["campaign_weeks"][0], cfg["simulation"]["campaign_weeks"][-1]
campaign = (pd.Timestamp(cfg["simulation"]["start_date"]) + timedelta(weeks=c_start - 1),
            pd.Timestamp(cfg["simulation"]["start_date"]) + timedelta(weeks=c_end) - timedelta(days=1))


def shade_campaign(fig: go.Figure) -> go.Figure:
    fig.add_vrect(x0=campaign[0], x1=campaign[1], fillcolor="#2f9e44", opacity=0.08, line_width=0,
                  annotation_text="campagne de remédiation", annotation_position="top left")
    return fig.update_layout(template=TEMPLATE, margin=dict(l=10, r=10, t=40, b=10), height=320)


def card(col, key: str) -> None:
    """Indicateur clé : valeur, variation vs semaine précédente, pastille vert/orange/rouge."""
    meta, th = INDICATORS[key], cfg["thresholds"].get(key)
    cur, prev = weekly[key].iloc[-1], weekly[key].iloc[-2]
    status = rag(cur, th) if th else "n/a"
    unit = meta["unit"] if meta["unit"] != "%" else " %"
    col.metric(f"{RAG_ICONS[status]} {meta['label']}", f"{cur:g}{unit}", f"{cur - prev:+.1f} vs S-1",
               delta_color="normal" if key in HIGHER_IS_BETTER else "inverse",
               help=f"{meta['formula']} — statut : {status}", border=True)


st.title("🛡️ DataRisk Compliance Monitor")
st.caption(f"Pilotage de la sécurité des données (aval DSPM) · état au {AS_OF.date()} · "
           "**données 100 % fictives** issues de la simulation")
tab_dir, tab_ops, tab_rgpd, tab_qual = st.tabs(["Direction", "Opérationnelle", "Conformité RGPD", "Qualité"])

# =============================================================================================== Direction
with tab_dir:
    cols = st.columns(6)
    for col, key in zip(cols, ["risk_index", "backlog", "p1_over_sla", "sla_compliance_pct", "fp_rate_pct",
                               "coverage_pct"], strict=True):
        card(col, key)

    left, right = st.columns(2)
    fig = px.line(weekly, y="risk_index", markers=True, title="Indice de risque (Σ scores ouverts / 100)",
                  labels={"risk_index": "indice", "snapshot_date": ""})
    left.plotly_chart(shade_campaign(fig), width="stretch")
    flows = weekly[["new_incidents", "remediated"]].rename(
        columns={"new_incidents": "Nouveaux incidents", "remediated": "Remédiations"})
    fig = px.bar(flows, barmode="group", title="Effet de la campagne : flux entrant vs remédiations",
                 labels={"value": "incidents", "snapshot_date": "", "variable": ""})
    right.plotly_chart(shade_campaign(fig), width="stretch")

    left, right = st.columns(2)
    ent = f["metric_snapshots"]
    ent = ent[(ent["scope_type"] == "entity") & (ent["metric"] == "risk_index")]
    ent = ent.assign(entite=ent["scope_value"].map(cfg["entities"]))
    fig = px.line(ent, x="snapshot_date", y="value", color="entite", markers=True,
                  title="Indice de risque par entité", labels={"value": "indice", "snapshot_date": ""})
    left.plotly_chart(shade_campaign(fig), width="stretch")
    kri_df = pd.DataFrame([{"KRI": INDICATORS[k]["label"], "Valeur": weekly[k].iloc[-1],
                            "S-1": weekly[k].iloc[-2], "Statut": rag(weekly[k].iloc[-1], cfg["thresholds"][k])}
                           for k in ["c3_exposed_public_external", "unencrypted_personal_records",
                                     "open_exposed_secrets", "retention_exceeded", "p1_over_sla"]])
    right.markdown("**KRI à la date**")
    right.dataframe(kri_df.style.map(lambda v: f"color:{RAG_COLORS.get(v, 'inherit')};font-weight:600",
                                     subset=["Statut"]), hide_index=True, width="stretch")
    by_perim = active.groupby("perimeter_id")["risk_score"].sum().div(100).round(1).reset_index()
    fig = px.bar(by_perim, x="perimeter_id", y="risk_score", title="Indice de risque par périmètre",
                 labels={"perimeter_id": "", "risk_score": "indice"})
    right.plotly_chart(fig.update_layout(template=TEMPLATE, height=260, margin=dict(t=40, b=10)),
                       width="stretch")

# =============================================================================================== Opérationnelle
with tab_ops:
    st.subheader("File priorisée des incidents")
    c1, c2, c3, c4, c5 = st.columns(5)
    ents = c1.multiselect("Entité", sorted(state["entity_id"].unique()))
    perims = c2.multiselect("Périmètre", sorted(state["perimeter_id"].unique()))
    prios = c3.multiselect("Priorité", ["P1", "P2", "P3", "P4"])
    statuses = c4.multiselect("Statut", list(STATUS_LABELS), default=list(ACTIVE_STATUSES),
                              format_func=STATUS_LABELS.get)
    owners = c5.multiselect("Propriétaire", sorted(state["data_owner"].unique()))
    q = state.copy()
    for column, chosen in (("entity_id", ents), ("perimeter_id", perims), ("priority", prios),
                           ("status", statuses), ("data_owner", owners)):
        if chosen:
            q = q[q[column].isin(chosen)]
    q = q.assign(hors_sla=(q["sla_due"] < AS_OF) & q["status"].isin(ACTIVE_STATUSES),
                 type=q["alert_type"].map(ALERT_TYPES), statut=q["status"].map(STATUS_LABELS))
    q = q.sort_values(["hors_sla", "risk_score"], ascending=[False, False])
    st.caption(f"{len(q)} incidents · {int(q['hors_sla'].sum())} hors SLA")
    st.dataframe(q[["incident_id", "priority", "risk_score", "type", "entity_id", "perimeter_id", "asset_id",
                    "data_owner", "statut", "sla_due", "hors_sla", "source_count", "lifecycle"]],
                 hide_index=True, width="stretch", height=360,
                 column_config={"risk_score": st.column_config.ProgressColumn("score", min_value=0, max_value=100,
                                                                              format="%.0f"),
                                "sla_due": st.column_config.DatetimeColumn("échéance SLA", format="YYYY-MM-DD")})

    if len(q):
        inc_id = st.selectbox("Détail de l'incident", q["incident_id"].tolist())
        inc = f["incidents"].set_index("incident_id").loc[inc_id]
        d1, d2 = st.columns([3, 2])
        d1.markdown(f"**#{inc_id} — {ALERT_TYPES[inc['alert_type']]}** · `{inc['asset_id']}`  \n"
                    f"{inc['entity_id']} / {inc['perimeter_id']} · propriétaire {inc['data_owner']} · "
                    f"{inc['classification']} · {inc['rgpd_category']} · exposition {inc['exposure']} · "
                    f"{inc['record_count']} enregistrements")
        expl = pd.DataFrame(json.loads(inc["score_explanation"]))
        d1.markdown(f"**Score {inc['risk_score']} → {inc['priority']}** (explication) :")
        d1.dataframe(expl, hide_index=True, width="stretch")
        d2.markdown("**Sources corroborantes**")
        d2.dataframe(f["incident_sources"][f["incident_sources"]["incident_id"] == inc_id]
                     [["source_id", "rule_id", "first_seen", "last_seen", "detections"]],
                     hide_index=True, width="stretch")
        overdue = (AS_OF - inc["sla_due"]).days
        msg = f"échéance SLA {inc['sla_due'].date()}"
        if inc["status"] in ACTIVE_STATUSES and overdue > 0:
            d2.error(f"Hors SLA de {overdue} j ({msg})")
        else:
            d2.info(msg)
        st.markdown("**Historique (audit)**")
        hist = f["status_history"][f["status_history"]["incident_id"] == inc_id]
        st.dataframe(hist[["changed_at", "from_status", "to_status", "actor", "reason", "priority", "sla_due"]],
                     hide_index=True, width="stretch")

# =============================================================================================== RGPD
with tab_rgpd:
    retention = active[active["alert_type"] == "RETENTION_EXCEEDED"]
    non_eu = active[active["alert_type"] == "NON_EU_LOCATION"]
    art9 = active[(active["rgpd_category"] == "sensible_art9") & (active["exposure"] != "restreint")]
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Hors durée de conservation", len(retention), help="RGPD art. 5.1.e")
    m2.metric("Enregistrements hors rétention", f"{int(retention['record_count'].sum()):,}".replace(",", " "))
    m3.metric("Données personnelles hors UE", len(non_eu), help="Transferts : RGPD chapitre V")
    m4.metric("Art. 9 exposées (non restreint)", len(art9), help="Données de santé : RGPD art. 9")
    left, right = st.columns(2)
    by_cat = active.groupby("rgpd_category").agg(incidents=("incident_id", "count"),
                                                 enregistrements=("record_count", "sum")).reset_index()
    fig = px.bar(by_cat, x="rgpd_category", y="incidents", title="Incidents à traiter par catégorie RGPD",
                 labels={"rgpd_category": ""}, hover_data=["enregistrements"])
    left.plotly_chart(fig.update_layout(template=TEMPLATE, height=330), width="stretch")
    mix = active.groupby(["rgpd_category", "alert_type"]).size().reset_index(name="n")
    mix["type"] = mix["alert_type"].map(ALERT_TYPES)
    fig = px.bar(mix, x="n", y="rgpd_category", color="type", orientation="h",
                 title="Nature des problèmes par catégorie", labels={"rgpd_category": "", "n": "incidents"})
    right.plotly_chart(fig.update_layout(template=TEMPLATE, height=330, legend_font_size=10),
                       width="stretch")
    st.markdown("**Données sensibles art. 9 exposées au-delà d'un accès restreint**")
    st.dataframe(art9[["incident_id", "priority", "risk_score", "alert_type", "entity_id", "asset_id", "exposure",
                       "record_count", "data_owner"]], hide_index=True, width="stretch")
    st.markdown("**Données hébergées hors UE**")
    st.dataframe(non_eu[["incident_id", "priority", "entity_id", "asset_id", "location", "rgpd_category",
                         "record_count"]], hide_index=True, width="stretch")

# =============================================================================================== Qualité
with tab_qual:
    noise = kpi.noise_reduction(f["raw_alerts"])
    q1, q2, q3, q4 = st.columns(4)
    q1.metric("Alertes brutes (12 sem.)", noise["raw_alerts"])
    q2.metric("Incidents consolidés", noise["incidents"])
    q3.metric("Réduction du bruit", f"{noise['noise_reduction_pct']} %")
    q4.metric("Lignes en quarantaine", len(f["rejected_alerts"]))
    left, right = st.columns(2)
    by_src = kpi.fp_rate_by(state, f["incident_sources"], "source_id")
    fig = px.bar(by_src, x="source_id", y="fp_rate_pct", text="fp_rate_pct", title="Taux de FP par source (%)",
                 labels={"source_id": "", "fp_rate_pct": "% FP"})
    left.plotly_chart(fig.update_layout(template=TEMPLATE, height=300), width="stretch")
    by_type = kpi.fp_rate_by(state, f["incident_sources"], "alert_type")
    by_type["type"] = by_type["alert_type"].map(ALERT_TYPES)
    fig = px.bar(by_type.sort_values("fp_rate_pct"), x="fp_rate_pct", y="type", orientation="h",
                 title="Taux de FP par type d'alerte (%)", labels={"type": "", "fp_rate_pct": "% FP"})
    right.plotly_chart(fig.update_layout(template=TEMPLATE, height=340, yaxis_dtick=1), width="stretch")
    left, right = st.columns(2)
    weekly_noise = weekly[["raw_alerts", "noise_reduction_pct"]].copy()
    weekly_noise["incidents"] = weekly_noise["raw_alerts"] * (1 - weekly_noise["noise_reduction_pct"] / 100)
    fig = px.bar(weekly_noise[["raw_alerts", "incidents"]].round(0), barmode="group",
                 title="Dédup inter-sources par semaine : alertes brutes vs incidents distincts",
                 labels={"value": "volume", "snapshot_date": "", "variable": ""})
    left.plotly_chart(fig.update_layout(template=TEMPLATE, height=300), width="stretch")
    right.markdown("**Règles les plus bruyantes** (à remonter à l'équipe qui règle l'outil DSPM)")
    right.dataframe(kpi.fp_rate_by(state, f["incident_sources"], "rule_id").head(8), hide_index=True,
                    width="stretch")
    st.markdown("**Quarantaine : motifs de rejet**")
    rej = f["rejected_alerts"].assign(motif=f["rejected_alerts"]["reason"].str.split(" :").str[0])
    st.dataframe(rej.groupby(["source_id", "motif"]).size().reset_index(name="lignes"), hide_index=True,
                 width="stretch")
