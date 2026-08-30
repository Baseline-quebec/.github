"""Mécanique commune aux balayages mensuels de toute l'organisation.

Trois balayages posent aujourd'hui des questions différentes sur le même
périmètre : les licences, les CVE, les modèles LLM dépréciés. Ce qui ne change
pas d'un balayage à l'autre vit ici, en deux sous-commandes appelées depuis les
workflows :

  lister   énumère les dépôts atteignables et les sort en matrice GitHub Actions
  envoyer  poste un rapport déjà agrégé au script Windmill qui écrit dans Slack

Ce qui change d'un balayage à l'autre, c'est l'agrégation : elle reste dans le
dossier de l'action concernée, avec ses tests. Les deux moitiés se parlent par
un fichier JSON sur le disque, jamais par un import : chaque script est appelé
en ligne de commande depuis une étape de workflow distincte, sans dépendre de la
position de l'autre dans l'arborescence.
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
TAILLE_PAGE = 100


def lister_depots(exclus: set[str]) -> list[str]:
    """Liste les dépôts que l'installation de la GitHub App peut atteindre.

    Volontairement pas `gh repo list` : cette commande interroge GraphQL en tant
    qu'utilisateur, et un jeton d'installation ne peut pas énumérer une
    organisation par ce chemin. L'endpoint d'installation retourne exactement ce
    que l'App a le droit de toucher, ce qui est aussi la définition honnête du
    périmètre du rapport.
    """
    resultat = subprocess.run(
        [
            "gh",
            "api",
            "--paginate",
            f"/installation/repositories?per_page={TAILLE_PAGE}",
            "--jq",
            ".repositories[] | select(.archived == false) | .full_name",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=DELAI_GH,
    )
    if resultat.returncode != 0:
        logger.error("Impossible de lister les dépôts : %s", resultat.stderr.strip())
        return []

    noms = [ligne.strip() for ligne in resultat.stdout.splitlines() if ligne.strip()]
    return [n for n in noms if n not in exclus and n.split("/")[-1] not in exclus]


def envoyer(type_rapport: str, depots: list[dict[str, Any]], analyses: int) -> bool:
    """Envoie le rapport au script Windmill qui le poste dans Slack.

    Le message part même quand rien n'est trouvé : un canal silencieux est
    ambigu, on ne sait pas si le balayage a tourné ou s'il est cassé. C'est le
    script Windmill qui choisit la formulation selon `type_rapport`.
    """
    url = os.environ.get("WINDMILL_WEBHOOK_URL", "").strip()
    token = os.environ.get("WINDMILL_TOKEN", "").strip()
    if not url or not token:
        logger.info("Windmill non configuré, rapport Slack sauté")
        return False

    charge = {
        "type_rapport": type_rapport,
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


def lire_resume(fichier: Path) -> tuple[list[dict[str, Any]], int]:
    """Lit le résumé produit par l'agrégation propre à un balayage.

    Un résumé illisible n'est pas envoyé comme un rapport vide : un « rien à
    signaler » mensonger est pire qu'un rapport manquant, parce qu'il se lit
    comme une preuve de conformité.
    """
    contenu: dict[str, Any] = json.loads(fichier.read_text(encoding="utf-8"))
    depots = list(contenu.get("depots") or [])
    return depots, int(contenu.get("total_analyses") or 0)


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée des deux sous-commandes."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    analyseur = argparse.ArgumentParser(description=__doc__)
    sous = analyseur.add_subparsers(dest="commande", required=True)

    lister = sous.add_parser("lister", help="Énumère les dépôts à scanner")
    lister.add_argument("--exclure", default="")

    envoi = sous.add_parser("envoyer", help="Poste un résumé déjà agrégé dans Slack")
    envoi.add_argument("--type-rapport", required=True)
    envoi.add_argument("--fichier", type=Path, required=True)

    arguments = analyseur.parse_args(argv)

    if arguments.commande == "lister":
        exclus = {e.strip() for e in arguments.exclure.split(",") if e.strip()}
        depots = lister_depots(exclus)
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

    try:
        depots, analyses = lire_resume(arguments.fichier)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"::error title=Resume illisible::{arguments.fichier} : {exc}")
        return 1

    envoyer(arguments.type_rapport, depots, analyses)
    return 0


if __name__ == "__main__":
    sys.exit(main())
