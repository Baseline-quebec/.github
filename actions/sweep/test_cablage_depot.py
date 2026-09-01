"""Vérifie que chaque balayage nomme le dépôt qu'il a réellement scanné.

Ces tests ne portent pas sur du Python mais sur du câblage YAML, et c'est
délibéré : le bug qu'ils figent n'était pas dans le code des scanners, il était
dans ce qui ne leur était pas passé. Le 2026-09-01, le rapport mensuel de
licences a annoncé neuf dépôts sous le même nom, `Baseline-quebec/.github`,
parce que l'action n'avait pas d'entrée `depot` et que les scripts retombaient
sur `GITHUB_REPOSITORY`, qui vaut le dépôt hébergeant le workflow. Le rapport
était juste sur le nombre et faux sur chaque nom, donc inexploitable : aucun
test Python ne pouvait le voir.

Le job de matrice est le seul endroit de tout ce dépôt où « le dépôt courant »
et « le dépôt analysé » diffèrent. Le défaut de l'entrée reste donc correct
partout ailleurs, ce qui est exactement ce qui rend l'oubli facile à refaire.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

RACINE = Path(__file__).resolve().parents[2]

# Un couple (workflow de balayage, action qu'il appelle) par balayage mensuel.
BALAYAGES = [
    ("licence-digest.yml", "licence-scan", "report.py"),
    ("cve-digest.yml", "cve-scan", "cve.py"),
]


def charger(chemin: Path) -> dict[str, Any]:
    contenu = yaml.safe_load(chemin.read_text(encoding="utf-8"))
    assert isinstance(contenu, dict), f"{chemin} ne se lit pas comme un objet YAML"
    return contenu


def etapes_de_scan(workflow: dict[str, Any], action: str) -> list[dict[str, Any]]:
    """Retourne les étapes du workflow qui appellent l'action de scan."""
    trouvees: list[dict[str, Any]] = []
    for job in (workflow.get("jobs") or {}).values():
        for etape in job.get("steps") or []:
            if f"actions/{action}@" in str(etape.get("uses", "")):
                trouvees.append(etape)
    return trouvees


@pytest.mark.parametrize(("workflow", "action", "_script"), BALAYAGES)
def test_le_balayage_passe_le_depot_de_la_matrice(workflow: str, action: str, _script: str) -> None:
    """Sans cette entrée, tous les constats sont attribués à `.github`."""
    etapes = etapes_de_scan(charger(RACINE / ".github" / "workflows" / workflow), action)
    assert etapes, f"{workflow} n'appelle plus l'action {action}"
    for etape in etapes:
        with_ = etape.get("with") or {}
        assert with_.get("depot") == "${{ matrix.depot }}", (
            f"{workflow} appelle {action} sans depot: le rapport nommera .github"
        )


@pytest.mark.parametrize(("_workflow", "action", "script"), BALAYAGES)
def test_l_action_declare_le_depot_et_le_transmet(_workflow: str, action: str, script: str) -> None:
    """L'entrée doit exister ET arriver au script, sinon elle est décorative."""
    definition = charger(RACINE / "actions" / action / "action.yml")
    entree = (definition.get("inputs") or {}).get("depot")
    assert entree is not None, f"{action} ne déclare pas l'entrée depot"
    assert entree.get("default") == "${{ github.repository }}", (
        f"{action} doit retomber sur le dépôt courant hors balayage"
    )

    etapes = definition["runs"]["steps"]
    passeurs = [
        etape
        for etape in etapes
        if "--depot" in str(etape.get("run", "")) and script in str(etape.get("run", ""))
    ]
    assert passeurs, f"{action} ne passe jamais --depot à {script}"
    for etape in passeurs:
        assert (etape.get("env") or {}).get("DEPOT") == "${{ inputs.depot }}", (
            f"{action} passe --depot depuis autre chose que l'entrée depot"
        )
