"""Construit le rapport mensuel de licences de toute l'organisation.

Deux sous-commandes, appelées par des étapes différentes du même workflow :

  lister   énumère les dépôts à scanner et les sort en matrice GitHub Actions
  agreger  fusionne les rapports par dépôt et envoie le résultat à Windmill

Le scan lui-même n'est pas ici : chaque dépôt est analysé par un job de matrice
qui réutilise la même action que les pull requests, donc le rapport mensuel et
le blocage en PR ne peuvent pas diverger.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DELAI_GH = 60
DELAI_WINDMILL = 30
LIMITE_DEPOTS = 500
TYPE_RAPPORT = "licences"


def lister_depots(org: str, exclus: set[str]) -> list[str]:
    """Liste les dépôts non archivés de l'organisation."""
    resultat = subprocess.run(
        [
            "gh",
            "repo",
            "list",
            org,
            "--limit",
            str(LIMITE_DEPOTS),
            "--no-archived",
            "--source",
            "--json",
            "nameWithOwner",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=DELAI_GH,
    )
    if resultat.returncode != 0:
        logger.error("Impossible de lister les dépôts : %s", resultat.stderr.strip())
        return []

    noms = [str(e.get("nameWithOwner", "")) for e in json.loads(resultat.stdout or "[]")]
    return [n for n in noms if n and n not in exclus and n.split("/")[-1] not in exclus]


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


def envoyer(depots: list[dict[str, Any]], analyses: int) -> bool:
    """Envoie le rapport au script Windmill qui le poste dans Slack."""
    url = os.environ.get("WINDMILL_WEBHOOK_URL", "").strip()
    token = os.environ.get("WINDMILL_TOKEN", "").strip()
    if not url or not token:
        logger.info("Windmill non configuré, rapport Slack sauté")
        return False

    charge = {
        "type_rapport": TYPE_RAPPORT,
        "depots": depots,
        "total_analyses": analyses,
        "channel_id": "",
    }
    requete = urllib.request.Request(
        url,
        data=json.dumps(charge).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(requete, timeout=DELAI_WINDMILL) as reponse:
            logger.info("Rapport envoyé (HTTP %s)", reponse.status)
            return True
    except urllib.error.HTTPError as exc:
        logger.warning("Windmill a répondu HTTP %s : %s", exc.code, exc.read()[:200])
    except (urllib.error.URLError, TimeoutError) as exc:
        logger.warning("Windmill injoignable : %s", exc)
    return False


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée des deux sous-commandes."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    analyseur = argparse.ArgumentParser(description=__doc__)
    sous = analyseur.add_subparsers(dest="commande", required=True)

    lister = sous.add_parser("lister", help="Énumère les dépôts à scanner")
    lister.add_argument("--org", required=True)
    lister.add_argument("--exclure", default="")

    agregation = sous.add_parser("agreger", help="Fusionne les rapports et envoie à Windmill")
    agregation.add_argument("--dossier", type=Path, required=True)

    arguments = analyseur.parse_args(argv)

    if arguments.commande == "lister":
        exclus = {e.strip() for e in arguments.exclure.split(",") if e.strip()}
        depots = lister_depots(arguments.org, exclus)
        if not depots:
            # Sous SSO SAML, un jeton non autorisé fait retourner une liste vide
            # sans erreur. Terminer en succès ferait croire à une organisation
            # sans dépôt et le rapport annoncerait fièrement zéro problème.
            print("::error title=Aucun depot::Aucun depot listable, verifier l'autorisation SSO.")
            return 1
        sortie = os.environ.get("GITHUB_OUTPUT")
        if sortie:
            with Path(sortie).open("a", encoding="utf-8") as fichier:
                fichier.write(f"depots={json.dumps(depots)}\n")
        print(f"{len(depots)} dépôt(s) à scanner")
        return 0

    depots, analyses = agreger(arguments.dossier)
    print(f"{len(depots)} dépôt(s) avec au moins une licence à arbitrer, sur {analyses} analysés")
    envoyer(depots, analyses)
    return 0


if __name__ == "__main__":
    sys.exit(main())
