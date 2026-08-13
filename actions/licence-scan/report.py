"""Classifie les licences extraites par extraire.py selon la politique Baseline.

L'extraction dit quelle licence porte quelle dépendance, ce module décide si
elle est acceptable. La séparation permet de changer la politique sans toucher
à la lecture des métadonnées, et de tester la décision sans dépôt réel.

Sortie : un rapport Markdown dans le résumé de job GitHub, des annotations sur
la PR, et un code de retour non nul si au moins une licence interdite subsiste
après application des exceptions.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Final

import yaml

# Métadonnées de licence en texte libre rencontrées dans l'écosystème Python,
# où PEP 639 (expressions SPDX) reste récent et inégalement adopté. Sans cette
# normalisation, « GNU General Public License v3 » ne correspond à aucun motif
# et passerait pour une licence inconnue au lieu d'une copyleft.
SYNONYMES: Final[dict[str, str]] = {
    r"gnu affero general public license.*v?3": "AGPL-3.0",
    r"gnu affero.*": "AGPL-3.0",
    r"gnu lesser general public license.*v?2\.1": "LGPL-2.1",
    r"gnu lesser general public license.*v?3": "LGPL-3.0",
    r"gnu lesser.*|lgplv?2\.1": "LGPL-2.1",
    r"gnu general public license.*v?2": "GPL-2.0",
    r"gnu general public license.*v?3": "GPL-3.0",
    r"gplv?3.*": "GPL-3.0",
    r"gplv?2.*": "GPL-2.0",
    r"mozilla public license.*2": "MPL-2.0",
    r"apache software license.*|apache license.*2.*|apache 2.*": "Apache-2.0",
    r"bsd license|bsd|new bsd.*|modified bsd.*": "BSD-3-Clause",
    r"simplified bsd.*": "BSD-2-Clause",
    r"mit license": "MIT",
    r"python software foundation license.*": "PSF-2.0",
    r"business source license.*": "BUSL-1.1",
    r"server side public license.*": "SSPL-1.0",
    r"elastic license.*2.*": "Elastic-2.0",
    r"redis source available license.*": "RSAL-2.0",
    r"creative commons attribution.non.?commercial.*": "CC-BY-NC-4.0",
    r"creative commons attribution.share.?alike.*": "CC-BY-SA-4.0",
    r"creative commons zero.*|public domain": "CC0-1.0",
}

# Valeurs que Trivy ou les métadonnées de paquets utilisent pour dire
# « pas de licence déclarée ».
MARQUEURS_INCONNUE: Final[frozenset[str]] = frozenset(
    {"", "unknown", "none", "unlicensed", "other/proprietary license", "proprietary"}
)

SEPARATEURS: Final[re.Pattern[str]] = re.compile(r"\s+(?:AND|OR|WITH)\s+|[;,/]", re.IGNORECASE)


class Verdict(Enum):
    """Résultat de la classification d'une licence."""

    INTERDITE = "interdite"
    A_SURVEILLER = "a_surveiller"
    INCONNUE = "inconnue"
    ACCEPTEE = "acceptee"
    EXEMPTEE = "exemptee"


@dataclass(frozen=True)
class Constat:
    """Une licence détectée sur une dépendance."""

    paquet: str
    licence: str
    verdict: Verdict
    cible: str
    raison_exception: str = ""


@dataclass
class Politique:
    """Politique de licences chargée depuis politique.yaml."""

    interdites: list[re.Pattern[str]] = field(default_factory=list)
    a_surveiller: list[re.Pattern[str]] = field(default_factory=list)
    ignorees: list[re.Pattern[str]] = field(default_factory=list)
    licence_inconnue: str = "signaler"
    exceptions: list[dict[str, str]] = field(default_factory=list)

    @classmethod
    def charger(cls, chemin: Path) -> Politique:
        brut: dict[str, Any] = yaml.safe_load(chemin.read_text(encoding="utf-8")) or {}

        def compiler(cle: str) -> list[re.Pattern[str]]:
            motifs = (brut.get(cle) or {}).get("motifs") or []
            return [re.compile(rf"^{motif}$", re.IGNORECASE) for motif in motifs]

        inconnue = str(brut.get("licence_inconnue", "signaler")).lower()
        if inconnue not in {"signaler", "bloquer", "taire"}:
            raise ValueError(
                f"licence_inconnue doit valoir signaler, bloquer ou taire, reçu : {inconnue!r}"
            )

        return cls(
            interdites=compiler("interdites"),
            a_surveiller=compiler("a_surveiller"),
            ignorees=compiler("ignorees"),
            licence_inconnue=inconnue,
            exceptions=list(brut.get("exceptions") or []),
        )

    def exception_pour(self, paquet: str, licence: str) -> str:
        """Retourne la raison de l'exception applicable, ou une chaîne vide."""
        for exception in self.exceptions:
            meme_paquet = str(exception.get("paquet", "")).lower() == paquet.lower()
            licence_visee = str(exception.get("licence", "")).lower()
            meme_licence = not licence_visee or licence_visee == licence.lower()
            if meme_paquet and meme_licence:
                return str(exception.get("raison", "sans justification"))
        return ""

    def classifier(self, paquet: str, licence: str) -> Verdict:
        if est_inconnue(licence):
            return {
                "bloquer": Verdict.INTERDITE,
                "taire": Verdict.ACCEPTEE,
            }.get(self.licence_inconnue, Verdict.INCONNUE)

        # `interdites` est volontairement évalué avant `ignorees` : si une
        # licence figure dans les deux listes, c'est une erreur de politique et
        # le comportement sûr est de bloquer, pas de taire.
        if any(motif.match(licence) for motif in self.interdites):
            raison = self.exception_pour(paquet, licence)
            return Verdict.EXEMPTEE if raison else Verdict.INTERDITE
        if any(motif.match(licence) for motif in self.a_surveiller):
            return Verdict.A_SURVEILLER
        return Verdict.ACCEPTEE


def est_inconnue(licence: str) -> bool:
    return licence.strip().lower() in MARQUEURS_INCONNUE


def normaliser(brut: str) -> list[str]:
    """Découpe une expression de licence et normalise chaque terme en SPDX.

    « (MIT OR Apache-2.0) » donne ["MIT", "Apache-2.0"]. Une expression
    composée est évaluée terme par terme, donc un paquet double-licencié
    MIT ou GPL sera signalé sur le terme GPL. C'est délibérément prudent :
    le choix du terme applicable est une décision humaine, pas automatique.
    """
    nettoye = brut.strip().strip("()").strip()
    if not nettoye:
        return [""]

    termes: list[str] = []
    for terme in SEPARATEURS.split(nettoye):
        terme = terme.strip().strip("()").strip()
        if not terme:
            continue
        minuscule = terme.lower()
        for motif, spdx in SYNONYMES.items():
            if re.fullmatch(motif, minuscule):
                terme = spdx
                break
        termes.append(terme)
    return termes or [""]


def extraire(rapport: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Extrait les triplets (cible, paquet, licence brute) du JSON de Trivy."""
    trouvailles: list[tuple[str, str, str]] = []
    for resultat in rapport.get("Results") or []:
        cible = str(resultat.get("Target", "inconnu"))
        for licence in resultat.get("Licenses") or []:
            paquet = str(licence.get("PkgName") or licence.get("FilePath") or "inconnu")
            trouvailles.append((cible, paquet, str(licence.get("Name", ""))))
    return trouvailles


def analyser(rapport: dict[str, Any], politique: Politique) -> list[Constat]:
    constats: list[Constat] = []
    vus: set[tuple[str, str]] = set()
    for cible, paquet, brut in extraire(rapport):
        for licence in normaliser(brut):
            cle = (paquet.lower(), licence.lower())
            if cle in vus:
                continue
            vus.add(cle)
            verdict = politique.classifier(paquet, licence)
            constats.append(
                Constat(
                    paquet=paquet,
                    licence=licence or "non déclarée",
                    verdict=verdict,
                    cible=cible,
                    raison_exception=(
                        politique.exception_pour(paquet, licence)
                        if verdict is Verdict.EXEMPTEE
                        else ""
                    ),
                )
            )
    return constats


def rediger(constats: list[Constat], depot: str) -> str:
    """Produit le rapport Markdown affiché dans le résumé du job."""
    par_verdict: dict[Verdict, list[Constat]] = defaultdict(list)
    for constat in constats:
        par_verdict[constat.verdict].append(constat)

    interdites = par_verdict[Verdict.INTERDITE]
    surveiller = par_verdict[Verdict.A_SURVEILLER]
    inconnues = par_verdict[Verdict.INCONNUE]
    exemptees = par_verdict[Verdict.EXEMPTEE]

    lignes = [f"## Conformité des licences : {depot}", ""]

    if not constats:
        lignes += [
            "Aucune dépendance analysée.",
            "",
            "Cela signifie soit que le dépôt n'a pas de dépendances gérées, soit que "
            "l'installation n'a pas produit de métadonnées lisibles. Un dépôt Python "
            "sans `.venv` installé ne peut pas être scanné : Trivy lit les fichiers "
            "`METADATA` des paquets installés, pas le fichier de verrouillage.",
        ]
        return "\n".join(lignes)

    lignes += [
        f"- Licences interdites : **{len(interdites)}**",
        f"- À surveiller (copyleft) : **{len(surveiller)}**",
        f"- Non déclarées : **{len(inconnues)}**",
        f"- Exemptées : **{len(exemptees)}**",
        f"- Total analysé : {len(constats)}",
        "",
    ]

    def tableau(titre: str, groupe: list[Constat], colonne: str = "") -> list[str]:
        if not groupe:
            return []
        entete = f"| Paquet | Licence | {colonne or 'Source'} |"
        separateur = "|---|---|---|"
        corps = [
            f"| `{c.paquet}` | {c.licence} | {c.raison_exception or c.cible} |"
            for c in sorted(groupe, key=lambda c: c.paquet.lower())
        ]
        return [f"### {titre}", "", entete, separateur, *corps, ""]

    lignes += tableau("Bloquant : licences interdites", interdites)
    lignes += tableau("À arbitrer : copyleft", surveiller)
    lignes += tableau("Licence non déclarée", inconnues)
    lignes += tableau("Exceptions appliquées", exemptees, colonne="Justification")

    if interdites:
        lignes += [
            "---",
            "",
            "Trois façons de débloquer cette PR : retirer la dépendance, la remplacer "
            "par une équivalente sous licence permissive, ou ajouter une exception "
            "justifiée dans `politique.yaml` du dépôt "
            "`Baseline-quebec/.github` si l'usage est réellement conforme.",
        ]

    return "\n".join(lignes)


def _serialiser(constats: list[Constat], verdict: Verdict) -> list[dict[str, str]]:
    """Extrait les constats d'un verdict, pour agrégation entre dépôts."""
    return [{"paquet": c.paquet, "licence": c.licence} for c in constats if c.verdict is verdict]


def annoter(constats: list[Constat]) -> None:
    """Émet les annotations GitHub visibles directement dans la PR."""
    for constat in constats:
        if constat.verdict is Verdict.INTERDITE:
            print(
                f"::error title=Licence interdite::{constat.paquet} est distribué sous "
                f"{constat.licence}, non conforme à la politique Baseline"
            )
        elif constat.verdict is Verdict.A_SURVEILLER:
            print(
                f"::warning title=Licence copyleft::{constat.paquet} est distribué sous "
                f"{constat.licence}, à valider selon le mode de livraison"
            )


def main() -> int:
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("--rapport-trivy", type=Path, required=True)
    analyseur.add_argument("--politique", type=Path, required=True)
    analyseur.add_argument("--depot", default=os.environ.get("GITHUB_REPOSITORY", "dépôt local"))
    analyseur.add_argument(
        "--sortie-json",
        type=Path,
        help="Écrit les constats en JSON, pour agrégation par le rapport mensuel.",
    )
    analyseur.add_argument(
        "--sans-blocage",
        action="store_true",
        help="Produit le rapport mais retourne toujours 0 (mode observation).",
    )
    arguments = analyseur.parse_args()

    politique = Politique.charger(arguments.politique)

    if not arguments.rapport_trivy.exists():
        print(f"::error::Rapport Trivy introuvable : {arguments.rapport_trivy}")
        return 1

    contenu = arguments.rapport_trivy.read_text(encoding="utf-8").strip()
    rapport: dict[str, Any] = json.loads(contenu) if contenu else {}

    constats = analyser(rapport, politique)
    markdown = rediger(constats, arguments.depot)

    resume = os.environ.get("GITHUB_STEP_SUMMARY")
    if resume:
        Path(resume).write_text(markdown + "\n", encoding="utf-8")
    print(markdown)

    annoter(constats)

    if arguments.sortie_json:
        arguments.sortie_json.write_text(
            json.dumps(
                {
                    "depot": arguments.depot,
                    "total": len(constats),
                    "interdites": _serialiser(constats, Verdict.INTERDITE),
                    "a_surveiller": _serialiser(constats, Verdict.A_SURVEILLER),
                    "inconnues": _serialiser(constats, Verdict.INCONNUE),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    interdites = [c for c in constats if c.verdict is Verdict.INTERDITE]

    sortie = os.environ.get("GITHUB_OUTPUT")
    if sortie:
        with Path(sortie).open("a", encoding="utf-8") as fichier:
            fichier.write(f"interdites={len(interdites)}\n")
            fichier.write(
                f"a-surveiller={sum(1 for c in constats if c.verdict is Verdict.A_SURVEILLER)}\n"
            )

    if interdites and not arguments.sans_blocage:
        return 1
    if interdites:
        print(
            f"::warning::{len(interdites)} licence(s) interdite(s) détectée(s). "
            "Mode observation actif, la PR n'est pas bloquée."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
