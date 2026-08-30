"""Agrège le rapport mensuel de licences de toute l'organisation.

Ce script ne fait qu'une chose : fusionner les rapports par dépôt en un résumé
prêt pour Slack. L'énumération des dépôts et l'envoi à Windmill sont communs à
tous les balayages de l'organisation et vivent dans `actions/sweep/sweep.py`,
appelé par des étapes distinctes du même workflow.

Le scan lui-même n'est pas ici : chaque dépôt est analysé par un job de matrice
qui réutilise la même action que les pull requests, donc le rapport mensuel et
le blocage en PR ne peuvent pas diverger.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def agreger(dossier: Path) -> tuple[list[dict[str, Any]], int]:
    """Fusionne les rapports par dépôt en une liste prête pour Slack.

    Un dépôt sans dépendance problématique n'apparaît pas dans la liste, mais
    compte dans le total analysé : c'est ce total qui permet de distinguer
    « rien à signaler » de « le balayage n'a rien scanné ».
    """
    depots: list[dict[str, Any]] = []
    analyses = 0

    for fichier in sorted(dossier.glob("**/*.json")):
        try:
            rapport: dict[str, Any] = json.loads(fichier.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("Rapport illisible ignoré : %s", fichier)
            continue

        analyses += 1
        problemes = list(rapport.get("interdites") or []) + list(rapport.get("a_surveiller") or [])
        if not problemes:
            continue

        # Une licence peut toucher plusieurs paquets d'un même dépôt. Lister la
        # licence une seule fois garde le message lisible ; le détail par paquet
        # reste dans le résumé de job GitHub.
        licences = sorted({str(p.get("licence", "")) for p in problemes if p.get("licence")})
        depots.append({"depot": str(rapport.get("depot", "inconnu")), "elements": licences})

    return depots, analyses


def main(argv: list[str] | None = None) -> int:
    """Agrège les rapports d'un dossier et écrit le résumé sur le disque."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("--dossier", type=Path, required=True)
    analyseur.add_argument("--sortie", type=Path, required=True)
    arguments = analyseur.parse_args(argv)

    depots, analyses = agreger(arguments.dossier)
    arguments.sortie.write_text(
        json.dumps({"depots": depots, "total_analyses": analyses}, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"{len(depots)} dépôt(s) avec au moins une licence à arbitrer, sur {analyses} analysés")
    return 0


if __name__ == "__main__":
    sys.exit(main())
