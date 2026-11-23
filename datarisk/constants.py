"""Vocabulaire commun : types d'alertes, statuts, catégories. Codes en anglais, libellés en français."""

from __future__ import annotations

# Types d'alertes du schéma commun (indépendants des sources)
ALERT_TYPES: dict[str, str] = {
    "PUBLIC_EXPOSURE": "Donnée sensible exposée publiquement",
    "EXTERNAL_SHARING": "Partage externe",
    "OVERLY_BROAD_GROUP": "Groupe trop large",
    "UNENCRYPTED": "Données non chiffrées",
    "PROD_DATA_IN_DEV": "Données de prod en environnement de dev",
    "RETENTION_EXCEEDED": "Données hors durée de conservation (RGPD art. 5)",
    "EXPOSED_SECRET": "Secret exposé",
    "INACTIVE_ACCOUNT_ACCESS": "Compte inactif avec droits",
    "NON_EU_LOCATION": "Localisation hors UE",
}

CLASSIFICATIONS = ("C0", "C1", "C2", "C3")
RGPD_CATEGORIES = ("aucune", "personnelle", "bancaire", "secret", "sensible_art9")
EXPOSURES = ("public", "externe", "groupe_large", "restreint")
ENVIRONMENTS = ("prod", "dev")
# Catégories qui comptent comme "données personnelles" pour les KRI
PERSONAL_CATEGORIES = ("personnelle", "bancaire", "sensible_art9")

# Workflow de remédiation
OPEN, ASSIGNED, IN_PROGRESS = "open", "assigned", "in_progress"
REMEDIATED, FALSE_POSITIVE, EXCEPTION = "remediated", "false_positive", "exception_accepted"
ACTIVE_STATUSES = (OPEN, ASSIGNED, IN_PROGRESS)          # backlog à traiter
CLOSED_STATUSES = (REMEDIATED, FALSE_POSITIVE, EXCEPTION)  # incident qualifié
STATUS_LABELS = {
    OPEN: "Ouverte", ASSIGNED: "Assignée", IN_PROGRESS: "En cours",
    REMEDIATED: "Remédiée", FALSE_POSITIVE: "Faux positif", EXCEPTION: "Exception acceptée",
}

PRIORITY_LABELS = {"P1": "P1 Critique", "P2": "P2 Élevé", "P3": "P3 Moyen", "P4": "P4 Faible"}
