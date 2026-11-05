"""`conformite.yml` garde les contrôles complets, sans condition de mode.

Le partage selon la cible de la pull request ne se fait PAS dans ce fichier
(décision du Directeur général du 2026-11-05, refaite après la revue : un choix
par `base_ref` dans le workflow se contourne en reciblant la pull request).
Deux rulesets imposent deux workflows : `secrets.yml` sur toutes les branches,
celui-ci sur la branche par défaut seulement. Ces tests gardent donc ce qui doit
rester vrai ici : le nom que les rulesets exigent, un seul job, et aucune
logique de mode qui allégerait un contrôle.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

RACINE = Path(__file__).resolve().parent.parent.parent
WORKFLOW = RACINE / ".github/workflows/conformite.yml"

ETAPES_COMPLETES = ("sentry", "cve", "modeles", "licences", "securite", "secrets")


def charger() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def job() -> dict[str, Any]:
    return charger()["jobs"]["conformite"]


def test_le_job_et_le_check_gardent_leur_nom() -> None:
    assert charger()["name"] == "Conformité Baseline"
    assert job()["name"] == "Conformité Baseline"


def test_un_seul_job() -> None:
    """Facturation à la minute entière : un job de plus annule l'économie."""
    assert list(charger()["jobs"]) == ["conformite"]


def test_aucune_logique_de_mode_dans_le_workflow_complet() -> None:
    texte = WORKFLOW.read_text(encoding="utf-8")
    assert "SECRETS_SEULEMENT" not in texte
    assert "base_ref" not in texte
    assert "default_branch" not in texte
    assert "env" not in job()


def test_les_six_controles_tournent_toujours() -> None:
    etapes = {e["id"]: e for e in job()["steps"] if "id" in e}
    for ident in ETAPES_COMPLETES:
        assert etapes[ident]["if"] == "always()", ident


def test_profondeur_de_checkout_par_defaut() -> None:
    """Le scan de l'arbre n'a pas besoin de l'historique."""
    checkout = job()["steps"][0]
    assert checkout["uses"].startswith("actions/checkout@")
    assert "with" not in checkout


def test_gitleaks_complet_lit_l_arbre() -> None:
    gitleaks = next(e for e in job()["steps"] if e.get("id") == "secrets")
    assert "dir /src" in gitleaks["run"]
    assert "--log-opts" not in gitleaks["run"]


def test_le_verdict_tourne_toujours() -> None:
    verdict = next(e for e in job()["steps"] if e.get("name") == "Verdict")
    assert verdict["if"] == "always()"
