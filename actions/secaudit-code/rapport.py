"""Normalise les constats des outils de sécurité et applique la politique Baseline.

Chaque outil parle son propre dialecte : gitleaks liste des secrets à plat,
semgrep imbrique la sévérité dans `extra`, bandit sépare sévérité et confiance,
trivy range les erreurs de configuration par cible, checkov parle de contrôles
échoués, hadolint de niveaux. Comparer ces sorties à l'œil est impossible et
brancher chaque outil sur son propre seuil produirait six politiques.

Ce module ramène tout à un `Constat` unique, puis une seule politique décide de
ce qui bloque. Un outil dont le rapport est absent ou illisible n'est jamais
compté comme « rien trouvé » : il est signalé comme muet, parce qu'un scanner
cassé ressemble exactement à un dépôt propre.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

# Le vocabulaire de sévérité et le mécanisme de seuil sont partagés avec
# cve-scan : deux copies dériveraient au premier ajustement. Le dossier commun
# vit un cran plus haut dans le dépôt de l'action.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "commun"))

from politique import (
    CRITIQUE,
    ELEVEE,
    FAIBLE,
    INCONNUE,
    MOYENNE,
    ORDRE,
    Politique,
    normaliser_severite,
)

__all__ = [
    "CRITIQUE",
    "ELEVEE",
    "FAIBLE",
    "INCONNUE",
    "MOYENNE",
    "ORDRE",
    "Constat",
    "Politique",
    "annotation",
    "collecter",
    "normaliser_severite",
    "resumer",
]


@dataclass(frozen=True)
class Constat:
    """Un constat de sécurité, quel que soit l'outil qui l'a produit."""

    outil: str
    regle: str
    severite: str
    fichier: str
    ligne: int
    message: str

    def en_dict(self) -> dict[str, Any]:
        """Représentation JSON, telle qu'agrégée par le rapport mensuel."""
        return {
            "outil": self.outil,
            "regle": self.regle,
            "severite": self.severite,
            "fichier": self.fichier,
            "ligne": self.ligne,
            "message": self.message,
        }


def _texte(valeur: object, defaut: str = "") -> str:
    return valeur.strip() if isinstance(valeur, str) else defaut


def _entier(valeur: object) -> int:
    return valeur if isinstance(valeur, int) and not isinstance(valeur, bool) else 0


def lire_gitleaks(charge: object) -> list[Constat]:
    """Un secret trouvé est toujours critique : la sévérité n'est pas négociable.

    gitleaks ne classe pas ses trouvailles. Leur donner INCONNUE les ferait
    passer sous n'importe quel seuil, alors qu'un identifiant en clair dans le
    dépôt est le constat le plus actionnable de toute la suite.
    """
    if not isinstance(charge, list):
        return []
    constats = []
    for entree in charge:
        if not isinstance(entree, dict):
            continue
        constats.append(
            Constat(
                outil="gitleaks",
                regle=_texte(entree.get("RuleID"), "secret"),
                severite=CRITIQUE,
                fichier=_texte(entree.get("File")),
                ligne=_entier(entree.get("StartLine")),
                message=_texte(entree.get("Description"), "Secret détecté"),
            )
        )
    return constats


def lire_semgrep(charge: object) -> list[Constat]:
    """Sortie `semgrep scan --json` : la sévérité vit dans `extra`."""
    if not isinstance(charge, dict):
        return []
    constats = []
    for entree in charge.get("results") or []:
        if not isinstance(entree, dict):
            continue
        extra = entree.get("extra") if isinstance(entree.get("extra"), dict) else {}
        debut = entree.get("start") if isinstance(entree.get("start"), dict) else {}
        constats.append(
            Constat(
                outil="semgrep",
                regle=_texte(entree.get("check_id"), "semgrep"),
                severite=normaliser_severite(extra.get("severity")),
                fichier=_texte(entree.get("path")),
                ligne=_entier(debut.get("line")),
                message=_texte(extra.get("message"), "Motif suspect"),
            )
        )
    return constats


def lire_bandit(charge: object) -> list[Constat]:
    """Sortie `bandit -f json`.

    Un constat de sévérité haute mais de confiance basse est rétrogradé d'un
    cran : bandit signale volontiers du code de test ou une chaîne qui ressemble
    à un mot de passe. Sans cette nuance, le seuil de blocage se remplit de faux
    positifs et l'équipe apprend à ignorer le gate, ce qui coûte plus cher que
    de rater un constat de confiance basse.
    """
    if not isinstance(charge, dict):
        return []
    constats = []
    for entree in charge.get("results") or []:
        if not isinstance(entree, dict):
            continue
        severite = normaliser_severite(entree.get("issue_severity"))
        confiance = normaliser_severite(entree.get("issue_confidence"))
        if confiance == FAIBLE and severite in (CRITIQUE, ELEVEE):
            severite = MOYENNE
        constats.append(
            Constat(
                outil="bandit",
                regle=_texte(entree.get("test_id"), "bandit"),
                severite=severite,
                fichier=_texte(entree.get("filename")),
                ligne=_entier(entree.get("line_number")),
                message=_texte(entree.get("issue_text"), "Motif suspect"),
            )
        )
    return constats


def lire_trivy(charge: object) -> list[Constat]:
    """Sortie `trivy fs --format json`, limitée aux erreurs de configuration
    et aux secrets.

    Les vulnérabilités de dépendances sont volontairement ignorées ici : elles
    sont la charge de `cve-scan`, qui lit les fichiers de verrouillage. Les
    compter aux deux endroits ferait apparaître la même CVE dans deux rapports
    avec deux verdicts possibles.
    """
    if not isinstance(charge, dict):
        return []
    constats = []
    for resultat in charge.get("Results") or []:
        if not isinstance(resultat, dict):
            continue
        cible = _texte(resultat.get("Target"))
        for erreur in resultat.get("Misconfigurations") or []:
            if not isinstance(erreur, dict):
                continue
            cause = erreur.get("CauseMetadata")
            ligne = _entier(cause.get("StartLine")) if isinstance(cause, dict) else 0
            constats.append(
                Constat(
                    outil="trivy",
                    regle=_texte(erreur.get("ID"), "trivy"),
                    severite=normaliser_severite(erreur.get("Severity")),
                    fichier=cible,
                    ligne=ligne,
                    message=_texte(erreur.get("Title"), "Configuration risquée"),
                )
            )
        for secret in resultat.get("Secrets") or []:
            if not isinstance(secret, dict):
                continue
            constats.append(
                Constat(
                    outil="trivy",
                    regle=_texte(secret.get("RuleID"), "secret"),
                    severite=CRITIQUE,
                    fichier=cible,
                    ligne=_entier(secret.get("StartLine")),
                    message=_texte(secret.get("Title"), "Secret détecté"),
                )
            )
    return constats


def lire_checkov(charge: object) -> list[Constat]:
    """Sortie `checkov -o json`, qui est un objet seul ou une liste par cadriciel.

    checkov ne renseigne `severity` que sous licence commerciale. Sans elle, un
    contrôle échoué vaut MOYENNE : ni ignoré, ni bloquant par défaut.
    """
    cadres = charge if isinstance(charge, list) else [charge]
    constats = []
    for cadre in cadres:
        if not isinstance(cadre, dict):
            continue
        resultats = cadre.get("results")
        if not isinstance(resultats, dict):
            continue
        for echec in resultats.get("failed_checks") or []:
            if not isinstance(echec, dict):
                continue
            plage = echec.get("file_line_range")
            ligne = _entier(plage[0]) if isinstance(plage, list) and plage else 0
            severite = normaliser_severite(echec.get("severity"))
            constats.append(
                Constat(
                    outil="checkov",
                    regle=_texte(echec.get("check_id"), "checkov"),
                    severite=MOYENNE if severite == INCONNUE else severite,
                    fichier=_texte(echec.get("file_path")),
                    ligne=ligne,
                    message=_texte(echec.get("check_name"), "Contrôle échoué"),
                )
            )
    return constats


def lire_hadolint(charge: object) -> list[Constat]:
    """Sortie `hadolint -f json`."""
    if not isinstance(charge, list):
        return []
    constats = []
    for entree in charge:
        if not isinstance(entree, dict):
            continue
        constats.append(
            Constat(
                outil="hadolint",
                regle=_texte(entree.get("code"), "hadolint"),
                severite=normaliser_severite(entree.get("level")),
                fichier=_texte(entree.get("file"), "Dockerfile"),
                ligne=_entier(entree.get("line")),
                message=_texte(entree.get("message"), "Dockerfile risqué"),
            )
        )
    return constats


LECTEURS: Final[dict[str, Callable[[Any], list[Constat]]]] = {
    "gitleaks": lire_gitleaks,
    "semgrep": lire_semgrep,
    "bandit": lire_bandit,
    "trivy": lire_trivy,
    "checkov": lire_checkov,
    "hadolint": lire_hadolint,
}


def collecter(
    dossier: Path, non_applicables: set[str] | None = None
) -> tuple[list[Constat], list[str]]:
    """Lit les rapports présents dans le dossier et signale les outils muets.

    Le fichier attendu porte le nom de l'outil : `gitleaks.json`, `semgrep.json`.
    Un outil dont le fichier manque ou ne se parse pas est rendu visible plutôt
    que compté comme propre.

    `non_applicables` liste les outils que la détection a délibérément sautés,
    faute de Python, de Dockerfile ou d'infrastructure à analyser. Les confondre
    avec les muets crierait au scanner cassé sur chaque dépôt qui n'a pas de
    Dockerfile, et un avertissement qui se déclenche toujours cesse d'être lu.
    """
    ignores = non_applicables or set()
    constats: list[Constat] = []
    muets: list[str] = []
    for outil, lecteur in LECTEURS.items():
        if outil in ignores:
            continue
        fichier = dossier / f"{outil}.json"
        if not fichier.is_file() or fichier.stat().st_size == 0:
            muets.append(outil)
            continue
        try:
            charge = json.loads(fichier.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            muets.append(outil)
            continue
        constats.extend(lecteur(charge))
    constats.sort(key=lambda c: (ORDRE.get(c.severite, 9), c.outil, c.fichier, c.ligne))
    return constats, muets


def resumer(bloquants: list[Constat], autres: list[Constat], muets: list[str]) -> str:
    """Compose le résumé Markdown affiché dans l'onglet Summary du job."""
    lignes = ["## Audit de sécurité du code", ""]
    total = len(bloquants) + len(autres)
    if not total:
        lignes.append("Aucun constat.")
    else:
        lignes.append(f"{total} constat(s), dont {len(bloquants)} au-dessus du seuil.")
        lignes += ["", "| Sévérité | Outil | Règle | Fichier | Message |", "|---|---|---|---|---|"]
        for constat in (bloquants + autres)[:50]:
            emplacement = f"{constat.fichier}:{constat.ligne}" if constat.fichier else "-"
            message = constat.message.replace("|", "/").replace("\n", " ")[:120]
            lignes.append(
                f"| {constat.severite} | {constat.outil} | `{constat.regle}` "
                f"| {emplacement} | {message} |"
            )
        if total > 50:
            lignes.append("")
            lignes.append(f"_{total - 50} constat(s) supplémentaires, voir les artefacts._")
    if muets:
        lignes += [
            "",
            f"**Outils sans rapport exploitable : {', '.join(muets)}.** "
            "Un scanner muet n'est pas une preuve de conformité.",
        ]
    return "\n".join(lignes) + "\n"


def annotation(constat: Constat) -> str:
    """Compose l'annotation GitHub qui epingle le constat dans le diff.

    Les proprietes sont assemblees et non concatenees a l'aveugle : un constat
    sans fichier produisait « ::error ,title=… », que GitHub affiche mal. Une
    ligne 0 est omise aussi, les annotations etant numerotees a partir de 1.
    """
    proprietes = []
    if constat.fichier:
        proprietes.append(f"file={constat.fichier}")
        if constat.ligne > 0:
            proprietes.append(f"line={constat.ligne}")
    proprietes.append(f"title={constat.outil} {constat.regle}")
    # Les retours a la ligne coupent l'annotation : GitHub ne lit que la
    # premiere ligne et le reste s'affiche comme du texte brut.
    message = constat.message.replace("\n", " ").strip()
    return f"::error {','.join(proprietes)}::{message}"


def ecrire_sortie(nom: str, valeur: str) -> None:
    """Écrit une sortie d'action si le job en fournit le canal."""
    fichier = os.environ.get("GITHUB_OUTPUT")
    if fichier:
        with Path(fichier).open("a", encoding="utf-8") as sortie:
            sortie.write(f"{nom}={valeur}\n")


def main(argv: list[str] | None = None) -> int:
    """Applique la politique aux rapports et décide du sort du job."""
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("--rapports", type=Path, required=True)
    analyseur.add_argument("--politique", type=Path, required=True)
    analyseur.add_argument("--depot", default=os.environ.get("GITHUB_REPOSITORY", "inconnu"))
    analyseur.add_argument(
        "--non-applicables",
        default="",
        help="Outils sautes par la detection, separes par des virgules.",
    )
    analyseur.add_argument("--sortie-json", type=Path, default=None)
    analyseur.add_argument(
        "--sans-blocage",
        action="store_true",
        help="Produit le rapport sans jamais faire échouer le job.",
    )
    arguments = analyseur.parse_args(argv)

    ignores = {o.strip() for o in arguments.non_applicables.split(",") if o.strip()}
    constats, muets = collecter(arguments.rapports, ignores)
    politique = Politique.charger(arguments.politique)
    bloquants, autres = politique.trier(constats)

    resume = resumer(bloquants, autres, muets)
    print(resume)
    fichier_resume = os.environ.get("GITHUB_STEP_SUMMARY")
    if fichier_resume:
        with Path(fichier_resume).open("a", encoding="utf-8") as sortie:
            sortie.write(resume)

    if arguments.sortie_json:
        arguments.sortie_json.write_text(
            json.dumps(
                {
                    "depot": arguments.depot,
                    "bloquants": [c.en_dict() for c in bloquants],
                    "autres": [c.en_dict() for c in autres],
                    "muets": muets,
                    "non_applicables": sorted(ignores),
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    ecrire_sortie("bloquants", str(len(bloquants)))

    for constat in bloquants:
        print(annotation(constat))

    if bloquants and not arguments.sans_blocage:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
