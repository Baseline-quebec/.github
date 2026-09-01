"""La version de Python des scripts du depot est EXPLICITE, jamais heritee.

Constate en production le 2026-09-01, sur la premiere execution du workflow de
conformite reuni : `actions/commun/politique.py` utilise la syntaxe generique
de PEP 695 (`def trier[T: Constatable](`), qui exige Python 3.12, et l'audit de
securite est mort sur `SyntaxError: expected '('`.

La cause n'est pas dans le script. Reunir les quatre scans dans un SEUL job les
a fait partager le meme environnement : l'etape qui analyse les modeles LLM
installe Python 3.11 par `setup-python`, ce qui repositionne `pythonLocation`
pour TOUTES les etapes suivantes du job. `uv run` sans version demandee prenait
donc 3.11, alors que le runner offre 3.12. En jobs separes, chacun avait son
propre runner et le probleme ne pouvait pas exister.

D'ou cette garde : ce qui fait tourner du code du depot doit nommer sa version,
au lieu de dependre de ce qu'une etape voisine a laisse derriere elle.
"""

from __future__ import annotations

import re
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent.parent

# Un `uv run` qui execute un script DU DEPOT (`python "$ACTION_PATH/x.py"`), par
# opposition a un outil telecharge (semgrep, checkov, bandit), qui apporte ses
# propres contraintes de version.
LANCE_UN_SCRIPT_DU_DEPOT = re.compile(r"uv run [^\n]*python \"\$ACTION_PATH/[^\"]+\.py\"")


def test_chaque_script_du_depot_nomme_sa_version_de_python() -> None:
    manquants: list[str] = []
    for manifeste in sorted(RACINE.glob("actions/*/action.yml")):
        for ligne in manifeste.read_text(encoding="utf-8").splitlines():
            if LANCE_UN_SCRIPT_DU_DEPOT.search(ligne) and "--python" not in ligne:
                manquants.append(f"{manifeste.relative_to(RACINE)} : {ligne.strip()}")

    assert not manquants, (
        "Ces commandes heritent du Python que l'etape precedente a laisse dans "
        "le job, ce qui a deja tue l'audit de securite sur une SyntaxError :\n  "
        + "\n  ".join(manquants)
    )


def test_la_version_nommee_supporte_la_syntaxe_utilisee() -> None:
    """Le module partage utilise PEP 695, donc 3.12 au minimum."""
    politique = (RACINE / "actions/commun/politique.py").read_text(encoding="utf-8")
    if not re.search(r"^\s*(def|class)\s+\w+\[", politique, re.MULTILINE):
        return  # la syntaxe generique n'est plus utilisee, la contrainte tombe

    for manifeste in sorted(RACINE.glob("actions/*/action.yml")):
        for ligne in manifeste.read_text(encoding="utf-8").splitlines():
            trouve = re.search(r"--python (\d+)\.(\d+)", ligne)
            if trouve:
                majeur, mineur = int(trouve.group(1)), int(trouve.group(2))
                assert (majeur, mineur) >= (3, 12), (
                    f"{manifeste.relative_to(RACINE)} demande Python {majeur}.{mineur}, "
                    "or actions/commun/politique.py utilise la syntaxe generique de "
                    "PEP 695, qui exige 3.12."
                )
