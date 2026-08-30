"""Vocabulaire de sévérité et seuil de blocage, communs aux audits de sécurité.

`secaudit-code` et `cve-scan` posent des questions différentes mais prennent la
même décision : ce constat mérite-t-il d'arrêter une pull request. Écrire cette
décision deux fois donnerait deux seuils qui divergent au premier ajustement, et
c'est exactement ce que ce dépôt existe pour éviter.

Chaque action garde en revanche son propre fichier `politique.yaml` : les
sévérités qui bloquent et les exemptions n'ont aucune raison d'être les mêmes
pour un secret en clair et pour une CVE transitive.

Ce module est importé par chemin explicite depuis le dossier de chaque action,
qui vit un cran plus bas dans l'arborescence du dépôt.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Protocol

import yaml

CRITIQUE: Final = "CRITIQUE"
ELEVEE: Final = "ELEVEE"
MOYENNE: Final = "MOYENNE"
FAIBLE: Final = "FAIBLE"
INCONNUE: Final = "INCONNUE"

# Ordre de gravité décroissante, utilisé pour trier les rapports.
ORDRE: Final[dict[str, int]] = {
    CRITIQUE: 0,
    ELEVEE: 1,
    MOYENNE: 2,
    FAIBLE: 3,
    INCONNUE: 4,
}

# Vocabulaire de sévérité des outils vers le nôtre. Tout ce qui n'est pas
# reconnu devient INCONNUE plutôt que FAIBLE : une sévérité non comprise n'est
# pas une sévérité basse, et la confondre avec « pas grave » est exactement la
# façon dont un constat sérieux disparaît d'un rapport.
EQUIVALENCES: Final[dict[str, str]] = {
    "critical": CRITIQUE,
    "critique": CRITIQUE,
    "high": ELEVEE,
    "error": ELEVEE,
    "medium": MOYENNE,
    "moderate": MOYENNE,
    "warning": MOYENNE,
    "low": FAIBLE,
    "info": FAIBLE,
    "informational": FAIBLE,
    "note": FAIBLE,
    "style": FAIBLE,
    "unknown": INCONNUE,
    "none": INCONNUE,
}

# Seuils CVSS v3, tels que publiés par le FIRST. Ils ne sont pas un choix
# Baseline : les reprendre tels quels permet de comparer nos rapports à ceux
# des avis amont sans traduction mentale.
SEUILS_CVSS: Final[tuple[tuple[float, str], ...]] = (
    (9.0, CRITIQUE),
    (7.0, ELEVEE),
    (4.0, MOYENNE),
    (0.1, FAIBLE),
)


def normaliser_severite(brute: object) -> str:
    """Traduit la sévérité d'un outil dans le vocabulaire commun."""
    if not isinstance(brute, str):
        return INCONNUE
    return EQUIVALENCES.get(brute.strip().lower(), INCONNUE)


def severite_depuis_score(brute: object) -> str:
    """Traduit un score CVSS numérique, éventuellement donné en texte."""
    try:
        score = float(brute)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return INCONNUE
    for seuil, severite in SEUILS_CVSS:
        if score >= seuil:
            return severite
    return INCONNUE


class Constatable(Protocol):
    """Ce qu'une politique a besoin de savoir d'un constat pour le trier."""

    @property
    def outil(self) -> str: ...

    @property
    def regle(self) -> str: ...

    @property
    def severite(self) -> str: ...


@dataclass(frozen=True)
class Exemption:
    """Une règle qu'on accepte de ne pas bloquer, pour un temps borné."""

    outil: str
    motif: re.Pattern[str]
    justification: str
    expire: dt.date | None

    def couvre(self, constat: Constatable, aujourdhui: dt.date) -> bool:
        """Une exemption échue ne couvre plus rien.

        C'est tout l'intérêt de la date : sans elle, une exemption prise pour
        débloquer une livraison un mardi devient une politique permanente que
        plus personne ne relit.
        """
        if self.expire is not None and self.expire < aujourdhui:
            return False
        if self.outil not in ("*", constat.outil):
            return False
        return bool(self.motif.fullmatch(constat.regle))


@dataclass
class Politique:
    """Décide ce qui bloque une pull request."""

    bloquantes: set[str] = field(default_factory=lambda: {CRITIQUE, ELEVEE})
    exemptions: list[Exemption] = field(default_factory=list)

    @classmethod
    def charger(cls, chemin: Path) -> Politique:
        """Lit la politique YAML.

        Une politique vidée par erreur bloque encore CRITIQUE : un fichier
        tronqué ne doit pas se traduire par « tout passe », qui est le seul
        échec de ce mécanisme qu'on ne verrait jamais.
        """
        contenu: dict[str, Any] = yaml.safe_load(chemin.read_text(encoding="utf-8")) or {}
        bloquantes = {str(s).strip().upper() for s in contenu.get("bloquantes") or []}
        exemptions = []
        for brute in contenu.get("exemptions") or []:
            if not isinstance(brute, dict) or not brute.get("regle"):
                continue
            expire = brute.get("expire")
            exemptions.append(
                Exemption(
                    outil=str(brute.get("outil", "*")),
                    motif=re.compile(str(brute["regle"]), re.IGNORECASE),
                    justification=str(brute.get("justification", "")),
                    expire=expire if isinstance(expire, dt.date) else None,
                )
            )
        return cls(bloquantes=bloquantes or {CRITIQUE}, exemptions=exemptions)

    def trier[T: Constatable](
        self, constats: list[T], aujourdhui: dt.date | None = None
    ) -> tuple[list[T], list[T]]:
        """Sépare les constats bloquants du reste, exemptions appliquées."""
        jour = aujourdhui or dt.date.today()
        bloquants: list[T] = []
        autres: list[T] = []
        for constat in constats:
            exempte = any(e.couvre(constat, jour) for e in self.exemptions)
            if not exempte and constat.severite in self.bloquantes:
                bloquants.append(constat)
            else:
                autres.append(constat)
        return bloquants, autres
