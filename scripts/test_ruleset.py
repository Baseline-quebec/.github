"""Tests de la définition partagée du ruleset de conformité.

Ce fichier est censé être la source de vérité du périmètre imposé à
l'organisation : ce qui est scanné, et ce qui ne l'est pas. Il a déjà dérivé du
ruleset réel une fois — `Marketing` et `Ventes` en étaient exclus en production
sans que le script les nomme, ce qui aurait fait reconstruire un périmètre plus
large que le vrai après un incident.

Les tests portent donc sur la forme exacte de la charge utile envoyée à GitHub,
pas sur des détails de style : une clé mal nommée est acceptée en silence par
l'API, qui ignore ce qu'elle ne connaît pas.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

COMMUN = Path(__file__).parent / "ruleset-commun.sh"


def appeler(fonction: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Source le fichier commun et rend le JSON produit par une de ses fonctions."""
    resultat = subprocess.run(
        ["bash", "-c", f'source "{COMMUN}" && {fonction}'],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return json.loads(resultat.stdout)


def variable(nom: str) -> list[str]:
    """Rend le contenu d'un tableau bash déclaré dans le fichier commun."""
    resultat = subprocess.run(
        ["bash", "-c", f'source "{COMMUN}" && printf "%s\\n" "${{{nom}[@]}}"'],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return [ligne for ligne in resultat.stdout.splitlines() if ligne]


# --------------------------------------------------------------------------
# Périmètre
# --------------------------------------------------------------------------


def test_exclusions_connues_sont_declarees() -> None:
    """Le périmètre déclaré doit être celui du ruleset réel.

    tracking-llm-discontinued porte le registre des modèles dépréciés : le
    scanner y produirait une issue par modèle, 182 en une exécution. Marketing
    et Ventes sont des dépôts de travail, essentiellement du HTML de sites et
    de présentations. bswh-baylee et serko-northsky sont hors maintenance
    Baseline depuis le 2026-09-01 : personne n'y traite les checks imposés sur
    les pull requests.
    """
    assert set(variable("EXCLUS")) == {
        "tracking-llm-discontinued",
        "Marketing",
        "Ventes",
        "bswh-baylee",
        "serko-northsky",
    }


def test_conditions_ciblent_la_branche_par_defaut_de_tous_les_depots() -> None:
    conditions = appeler("conditions_ruleset")
    assert conditions["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    assert conditions["repository_name"]["include"] == ["~ALL"]


def test_chaque_exclusion_arrive_dans_les_conditions() -> None:
    """Une exclusion perdue en route remettrait un dépôt dans le périmètre."""
    conditions = appeler("conditions_ruleset")
    assert sorted(conditions["repository_name"]["exclude"]) == sorted(variable("EXCLUS"))


# --------------------------------------------------------------------------
# Workflows imposés
# --------------------------------------------------------------------------


def test_les_quatre_controles_sont_imposes() -> None:
    regles = appeler("regles_workflows")
    chemins = [w["path"] for w in regles[0]["parameters"]["workflows"]]
    assert sorted(chemins) == [
        ".github/workflows/cve-scan.yml",
        ".github/workflows/licence-scan.yml",
        ".github/workflows/llm-scan.yml",
        ".github/workflows/secaudit-code.yml",
    ]


def test_chaque_workflow_impose_existe_dans_le_depot() -> None:
    """Un chemin fautif fait échouer le check sur toutes les PR de l'organisation.

    Le seul symptôme est un workflow « introuvable », sans indication du
    chemin attendu.
    """
    racine = Path(__file__).parent.parent
    for chemin in variable("WORKFLOWS"):
        assert (racine / chemin).is_file(), f"{chemin} est imposé mais absent du dépôt"


def test_regle_a_la_forme_attendue_par_lapi() -> None:
    """L'API ignore silencieusement les clés qu'elle ne connaît pas.

    Une faute de frappe sur `repository_id` ne produirait donc aucune erreur,
    seulement un ruleset qui n'impose rien.
    """
    regles = appeler("regles_workflows")
    assert len(regles) == 1
    assert regles[0]["type"] == "workflows"
    for workflow in regles[0]["parameters"]["workflows"]:
        assert set(workflow) == {"repository_id", "path", "ref"}
        assert isinstance(workflow["repository_id"], int)
        assert workflow["ref"] == "refs/tags/v1"


def test_toutes_les_regles_pointent_le_meme_depot_source() -> None:
    regles = appeler("regles_workflows")
    identifiants = {w["repository_id"] for w in regles[0]["parameters"]["workflows"]}
    assert len(identifiants) == 1


# --------------------------------------------------------------------------
# Charge utile de création
# --------------------------------------------------------------------------


def test_charge_de_creation_est_complete() -> None:
    charge = appeler("charge_ruleset")
    assert set(charge) == {"name", "target", "enforcement", "conditions", "rules"}
    assert charge["target"] == "branch"


@pytest.mark.parametrize("mode", ["evaluate", "active"])
def test_mode_dapplication_est_celui_demande(mode: str) -> None:
    assert appeler(f"charge_ruleset {mode}")["enforcement"] == mode


def test_creation_par_defaut_est_en_evaluate() -> None:
    """La création par défaut ne doit jamais activer un ruleset sans qu'on le veuille."""
    assert appeler("charge_ruleset")["enforcement"] == "evaluate"


def test_charge_de_creation_porte_le_meme_perimetre_que_les_conditions() -> None:
    """Création et mise à jour doivent parler du même périmètre.

    Deux définitions divergeraient au premier ajustement, et le ruleset
    reconstruit après un incident ne serait plus celui qu'on croyait.
    """
    assert appeler("charge_ruleset")["conditions"] == appeler("conditions_ruleset")


def test_charge_de_creation_porte_les_memes_regles() -> None:
    assert appeler("charge_ruleset")["rules"] == appeler("regles_workflows")
