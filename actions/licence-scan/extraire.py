"""Extrait la licence déclarée de chaque dépendance installée.

Remplace Trivy pour cette étape. Trivy a été écarté après vérification sur un
dépôt réel de 238 paquets : ses analyseurs `uv.lock`, `poetry.lock` et
`requirements.txt` ne portent aucune information de licence, il ne lit pas les
fichiers `.dist-info/METADATA`, et son mode `--license-full` ne produit que des
correspondances de texte sans attribution par paquet (1140 entrées dont
« Copyright »). Un scan Trivy sur un projet Python retourne donc zéro licence,
ce qui ressemble exactement à un succès.

Les métadonnées sont lues à la source :
  Python : `.dist-info/METADATA` et `.egg-info/PKG-INFO` sous site-packages
  Node   : `package.json` sous node_modules

La sortie reprend la structure JSON de Trivy pour que report.py reste inchangé.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

# Classifiers Trove vers identifiants SPDX. Seuls comptent ici les classifiers
# qui changent une décision : les licences restrictives et, surtout, les quatre
# classifiers à usage restreint, qui sont la seule façon dont une licence non
# commerciale se déclare dans l'écosystème Python.
CLASSIFIERS: Final[dict[str, str]] = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
    "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",  # noqa: E501
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",  # noqa: E501
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",  # noqa: E501
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",  # noqa: E501
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",  # noqa: E501
    "License :: OSI Approved :: European Union Public Licence 1.2 (EUPL 1.2)": "EUPL-1.2",
    # Usage restreint : ces classifiers n'ont pas d'équivalent SPDX. On leur
    # attribue un identifiant synthétique, repris tel quel dans politique.yaml.
    "License :: Free for non-commercial use": "Non-Commercial",
    "License :: Free For Educational Use": "Non-Commercial",
    "License :: Free For Home Use": "Non-Commercial",
    "License :: Free To Use But Restricted": "Non-Commercial",
    "License :: Other/Proprietary License": "Proprietary",
}

# Au-delà de cette longueur, le champ `License` contient le texte de la licence
# et non son nom. Certains paquets y collent les 11 kilo-octets de la GPL.
LONGUEUR_MAX_NOM: Final[int] = 120

# Valeurs de remplissage rencontrées dans le champ `License`. Elles doivent
# être ignorées au profit des classifiers : ptyprocess déclare
# « License: UNKNOWN » tout en portant un classifier ISC parfaitement valide.
REMPLISSAGE: Final[frozenset[str]] = frozenset(
    {"unknown", "none", "n/a", "na", "unlicensed", "see license", "see license file", "todo", "-"}
)


@dataclass(frozen=True)
class Trouvaille:
    """Une dépendance installée et sa licence déclarée."""

    ecosysteme: str
    paquet: str
    version: str
    licence: str


def _lire_entetes(contenu: str) -> dict[str, list[str]]:
    """Analyse les en-têtes façon RFC 822 d'un METADATA ou PKG-INFO.

    Les en-têtes s'arrêtent à la première ligne réellement vide : tout ce qui
    suit est la description longue du paquet. Sans cette coupure, une
    description contenant « License: ... » serait lue comme une déclaration.

    La nuance entre ligne vide et ligne d'espaces est déterminante. numpy 1.26.4
    colle le texte complet de la BSD dans son champ License, dont les
    paragraphes sont séparés par des lignes d'indentation seule. Traiter ces
    lignes comme une fin d'en-têtes coupe la lecture au huitième en-tête et fait
    manquer le classifier de licence, situé 970 lignes plus bas.

    Les lignes de continuation sont ignorées plutôt que concaténées. C'est le
    comportement utile ici : quand un paquet embarque le texte complet de sa
    licence dans le champ, la première ligne porte le nom et les suivantes le
    texte. tiktoken 0.13.0 déclare « License: MIT License » suivi des vingt
    lignes de la licence MIT ; concaténer transformerait une déclaration nette
    en pavé illisible qui ne correspond à aucun motif.
    """
    entetes: dict[str, list[str]] = {}
    for ligne in contenu.splitlines():
        if not ligne:
            break
        if ligne[0] in " \t":
            continue
        cle, separateur, valeur = ligne.partition(":")
        if not separateur:
            continue
        entetes.setdefault(cle.strip(), []).append(valeur.strip())
    return entetes


def _est_remplissage(valeur: str) -> bool:
    """Vrai si le champ ne déclare pas réellement une licence.

    Une notice de copyright n'est pas une déclaration de licence : isodate
    remplit son champ `License` avec « Copyright (c) 2021, ... », ce qui
    n'indique en rien sous quelles conditions le paquet est distribué.
    """
    normalise = valeur.strip().lower().rstrip(".")
    return normalise in REMPLISSAGE or normalise.startswith("copyright")


def licence_depuis_entetes(entetes: dict[str, list[str]]) -> str:
    """Choisit la déclaration de licence la plus fiable disponible.

    Ordre : License-Expression (PEP 639, expression SPDX normalisée) d'abord,
    puis le champ License libre s'il ressemble à un nom et non à un texte de
    licence, puis les classifiers Trove en dernier recours.
    """
    expression = next(iter(entetes.get("License-Expression", [])), "").strip()
    if expression:
        return expression

    libre = next(iter(entetes.get("License", [])), "").strip()
    if libre and len(libre) <= LONGUEUR_MAX_NOM and not _est_remplissage(libre):
        return libre

    for classifier in entetes.get("Classifier", []):
        if classifier.startswith("License ::"):
            spdx = CLASSIFIERS.get(classifier.strip())
            if spdx:
                return spdx
            # Classifier de licence inconnu : on remonte son dernier segment
            # plutôt que de le taire, pour qu'il apparaisse au rapport.
            return classifier.rsplit("::", 1)[-1].strip()

    # Le champ libre était trop long pour être un nom : on le signale comme
    # non déclaré plutôt que de charrier un texte de licence entier.
    return ""


def extraire_python(racine: Path) -> list[Trouvaille]:
    trouvailles: list[Trouvaille] = []
    vus: set[tuple[str, str]] = set()

    fichiers = [
        *racine.glob("**/site-packages/*.dist-info/METADATA"),
        *racine.glob("**/site-packages/*.egg-info/PKG-INFO"),
    ]
    for fichier in fichiers:
        try:
            entetes = _lire_entetes(fichier.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        nom = next(iter(entetes.get("Name", [])), "") or fichier.parent.name.split("-")[0]
        version = next(iter(entetes.get("Version", [])), "")
        cle = (nom.lower(), version)
        if cle in vus:
            continue
        vus.add(cle)
        trouvailles.append(
            Trouvaille(
                ecosysteme="Python",
                paquet=nom,
                version=version,
                licence=licence_depuis_entetes(entetes),
            )
        )
    return trouvailles


def _licence_node(manifeste: dict[str, Any]) -> str:
    """Lit le champ de licence d'un package.json.

    Le champ `license` est la forme moderne. La forme historique `licenses`,
    une liste d'objets, reste présente dans de vieux paquets encore largement
    installés en dépendance transitive.
    """
    licence = manifeste.get("license")
    if isinstance(licence, str):
        return licence.strip()
    if isinstance(licence, dict):
        return str(licence.get("type", "")).strip()
    anciennes = manifeste.get("licenses")
    if isinstance(anciennes, list):
        types = [str(item.get("type", "")).strip() for item in anciennes if isinstance(item, dict)]
        return " OR ".join(t for t in types if t)
    return ""


def extraire_node(racine: Path) -> list[Trouvaille]:
    trouvailles: list[Trouvaille] = []
    vus: set[tuple[str, str]] = set()

    for manifeste in racine.glob("**/node_modules/**/package.json"):
        # Seuls les manifestes à la racine d'un paquet comptent : un
        # package.json niché dans src/ ou dist/ n'est pas une dépendance.
        if manifeste.parent.parent.name != "node_modules" and not (
            manifeste.parent.parent.parent.name == "node_modules"
            and manifeste.parent.parent.name.startswith("@")
        ):
            continue
        try:
            contenu: dict[str, Any] = json.loads(manifeste.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        nom = str(contenu.get("name", "")) or manifeste.parent.name
        version = str(contenu.get("version", ""))
        cle = (nom.lower(), version)
        if cle in vus:
            continue
        vus.add(cle)
        trouvailles.append(
            Trouvaille(
                ecosysteme="Node",
                paquet=nom,
                version=version,
                licence=_licence_node(contenu),
            )
        )
    return trouvailles


def au_format_trivy(trouvailles: list[Trouvaille]) -> dict[str, Any]:
    """Sérialise dans la structure JSON attendue par report.py."""
    par_ecosysteme: dict[str, list[dict[str, str]]] = {}
    for trouvaille in trouvailles:
        par_ecosysteme.setdefault(trouvaille.ecosysteme, []).append(
            {
                "PkgName": trouvaille.paquet,
                "Name": trouvaille.licence,
                "PkgVersion": trouvaille.version,
            }
        )
    return {
        "Results": [
            {"Target": ecosysteme, "Class": "license", "Licenses": licences}
            for ecosysteme, licences in sorted(par_ecosysteme.items())
        ]
    }


def main() -> int:
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("--racine", type=Path, default=Path())
    analyseur.add_argument("--sortie", type=Path, required=True)
    arguments = analyseur.parse_args()

    trouvailles = extraire_python(arguments.racine) + extraire_node(arguments.racine)
    arguments.sortie.write_text(
        json.dumps(au_format_trivy(trouvailles), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    python = sum(1 for t in trouvailles if t.ecosysteme == "Python")
    node = len(trouvailles) - python
    print(f"{python} paquet(s) Python et {node} paquet(s) Node analysés.")
    if not trouvailles:
        print(
            "::warning title=Aucun paquet trouvé::Aucune dépendance installée détectée. "
            "Les licences se lisent dans les paquets installés, pas dans le fichier de "
            "verrouillage : vérifier que l'installation a réussi."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
