"""`conformite.yml` garde les contrôles complets, sans condition de mode.

Le partage selon la cible de la pull request ne se fait PAS dans ce fichier
(décision du Directeur général du 2026-11-05 : un choix par `base_ref` dans le
workflow se contourne en reciblant la pull request). Un ruleset impose ce
workflow sur la branche par défaut seulement ; vers une autre branche, aucun
check d'organisation (les secrets sont arrêtés au pre-commit). Ces tests gardent
donc ce qui doit rester vrai ici : le nom que le ruleset exige, un seul job, et
aucune logique de mode qui allégerait un contrôle, gitleaks sur l'arbre compris.
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


def declencheurs() -> dict[str, Any]:
    """Le bloc `on` : PyYAML lit la clé `on` comme le booléen True."""
    flux = charger()
    return flux["on"] if "on" in flux else flux[True]


def test_le_workflow_est_appelable_par_un_autre_depot() -> None:
    """Pour tourner après la fusion sur develop, depuis un workflow de chaque
    dépôt. Le bloc `on` est ignoré en exécution imposée : le rôle de check requis
    ne change pas."""
    on = declencheurs()
    assert "workflow_call" in on
    appel = on["workflow_call"] or {}
    # Aucune entrée obligatoire, et le secret du webhook est facultatif.
    assert not [n for n, e in (appel.get("inputs") or {}).items() if e.get("required")]
    secrets = appel.get("secrets") or {}
    assert not [n for n, e in secrets.items() if e.get("required")]
    # Les déclencheurs d'origine restent là.
    assert {"pull_request", "merge_group", "workflow_dispatch"} <= set(on)


def test_le_nom_du_job_est_inchange_avec_workflow_call() -> None:
    assert job()["name"] == "Conformité Baseline"
    assert job()["if"] == "github.repository != 'Baseline-quebec/.github'"


def test_plus_de_workflow_secrets_ni_de_mention_dans_conformite() -> None:
    """« Secrets Baseline » est retiré : un seul workflow est imposé."""
    assert not (RACINE / ".github/workflows/secrets.yml").exists()
    texte = WORKFLOW.read_text(encoding="utf-8")
    assert "Secrets Baseline" not in texte
    assert "secrets.yml" not in texte
