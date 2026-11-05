"""Le partage des contrôles selon la cible de la pull request est verrouillé.

Décision du Directeur général du 2026-11-05 : une pull request dont la cible
n'est PAS la branche par défaut du dépôt (par exemple `develop`) ne rejoue que
gitleaks, sur ses seuls commits ; la pull request vers la branche par défaut,
le `merge_group` et le `workflow_dispatch` gardent les contrôles complets.

Ces tests lisent `.github/workflows/conformite.yml` tel que GitHub le lira. Ils
gardent trois choses qu'une retouche anodine casserait en silence :

- le nom du job, que les rulesets de l'organisation exigent à la lettre ;
- l'expression qui choisit le mode, évaluée ici sur toutes les entrées utiles,
  avec l'échec fermé (donnée manquante : contrôles complets) ;
- le script gitleaks, exécuté pour de vrai sur un dépôt jetable avec un faux
  `docker`, pour voir la commande exacte qu'il construirait.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

RACINE = Path(__file__).resolve().parent.parent.parent
WORKFLOW = RACINE / ".github/workflows/conformite.yml"

ETAPES_COMPLETES = ("sentry", "cve", "modeles", "licences", "securite")


def charger() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def job() -> dict[str, Any]:
    return charger()["jobs"]["conformite"]


def etape(ident: str) -> dict[str, Any]:
    for e in job()["steps"]:
        if e.get("id") == ident or e.get("name") == ident:
            return e
    raise AssertionError(f"étape introuvable : {ident}")


# --------------------------------------------------------------------------
# Ce que les rulesets exigent
# --------------------------------------------------------------------------


def test_le_job_et_le_check_gardent_leur_nom() -> None:
    assert charger()["name"] == "Conformité Baseline"
    assert job()["name"] == "Conformité Baseline"


def test_un_seul_job() -> None:
    """Facturation à la minute entière : un job de plus annule l'économie."""
    assert list(charger()["jobs"]) == ["conformite"]


# --------------------------------------------------------------------------
# Le choix du mode
# --------------------------------------------------------------------------


def secrets_seulement(evenement: str, cible: str, defaut: str) -> bool:
    """Évalue l'expression `SECRETS_SEULEMENT` du workflow, telle qu'écrite."""
    brut = job()["env"]["SECRETS_SEULEMENT"]
    corps = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", brut)
    assert corps, f"expression attendue, trouvé : {brut}"
    python = (
        corps.group(1)
        .replace("github.event.repository.default_branch", "defaut")
        .replace("github.event_name", "evenement")
        .replace("github.base_ref", "cible")
        .replace("&&", " and ")
    )
    # Tout ce qui reste doit être un opérateur ou une de nos trois variables :
    # une expression qui en lit d'autres ne serait pas évaluée fidèlement ici.
    assert not re.search(r"github\.|\|\|", python), python
    variables = {"evenement": evenement, "cible": cible, "defaut": defaut}
    return bool(eval(python, {"__builtins__": {}}, variables))


@pytest.mark.parametrize(
    ("evenement", "cible", "defaut", "attendu"),
    [
        # PR vers une branche d'intégration : secrets seulement.
        ("pull_request", "develop", "main", True),
        ("pull_request", "release/2026-11", "main", True),
        # PR vers la branche par défaut : complet, quel que soit son nom.
        ("pull_request", "main", "main", False),
        ("pull_request", "master", "master", False),
        ("pull_request", "develop", "develop", False),
        # Dépôt dont la branche par défaut n'est pas main : `main` n'est alors
        # PAS la branche par défaut, donc secrets seulement (risque documenté).
        ("pull_request", "main", "develop", True),
        # Les deux autres événements gardent le mode complet.
        ("merge_group", "", "main", False),
        ("merge_group", "develop", "main", False),
        ("workflow_dispatch", "", "main", False),
        ("workflow_dispatch", "develop", "main", False),
        # Échec fermé : une donnée absente ne peut jamais alléger les contrôles.
        ("pull_request", "", "main", False),
        ("pull_request", "develop", "", False),
        ("pull_request", "", "", False),
    ],
)
def test_choix_du_mode(evenement: str, cible: str, defaut: str, attendu: bool) -> None:
    assert secrets_seulement(evenement, cible, defaut) is attendu


def test_les_cinq_controles_complets_sautent_en_mode_secrets_seulement() -> None:
    for ident in ETAPES_COMPLETES:
        condition = etape(ident)["if"]
        assert "always()" in condition, f"{ident} ne rend plus son verdict après un échec"
        assert "env.SECRETS_SEULEMENT != 'true'" in condition, ident


def test_gitleaks_tourne_dans_les_deux_modes() -> None:
    """Bloquant partout : aucune condition ne doit le sauter."""
    assert etape("secrets")["if"] == "always()"


def test_le_verdict_tourne_toujours() -> None:
    assert etape("Verdict")["if"] == "always()"


def test_historique_complet_seulement_pour_le_scan_du_diff() -> None:
    checkout = job()["steps"][0]
    assert checkout["uses"].startswith("actions/checkout@")
    profondeur = checkout["with"]["fetch-depth"]
    # Chaînes '0' et '1' : le nombre 0 est faux et ferait choisir 1 à `&& ... ||`.
    assert "env.SECRETS_SEULEMENT == 'true' && '0' || '1'" in profondeur


# --------------------------------------------------------------------------
# Le script gitleaks, exécuté avec un faux docker
# --------------------------------------------------------------------------


def git(depot: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    return subprocess.run(
        ["git", "-C", str(depot), *args],
        capture_output=True,
        text=True,
        check=True,
        env=env,
        timeout=60,
    ).stdout.strip()


@pytest.fixture
def depot_fusion(tmp_path: Path) -> tuple[Path, str, str]:
    """Dépôt au commit de fusion que GitHub extrait pour une PR : (dépôt, base, tête)."""
    depot = tmp_path / "depot"
    depot.mkdir()
    git(depot, "init", "-q", "-b", "develop")
    (depot / "a.txt").write_text("a\n")
    git(depot, "add", ".")
    git(depot, "commit", "-q", "-m", "base")
    git(depot, "checkout", "-q", "-b", "feature")
    (depot / "b.txt").write_text("b\n")
    git(depot, "add", ".")
    git(depot, "commit", "-q", "-m", "pr")
    git(depot, "checkout", "-q", "develop")
    (depot / "c.txt").write_text("c\n")
    git(depot, "add", ".")
    git(depot, "commit", "-q", "-m", "develop avance")
    git(depot, "checkout", "-q", "-b", "fusion")
    git(depot, "merge", "-q", "--no-ff", "-m", "fusion", "feature")
    return depot, git(depot, "rev-parse", "HEAD^1"), git(depot, "rev-parse", "HEAD^2")


def lancer_gitleaks(
    depot: Path, tmp_path: Path, seulement: bool
) -> tuple[subprocess.CompletedProcess[str], str, str]:
    """Exécute le `run:` de l'étape gitleaks ; rend le résultat, les arguments
    transmis au faux docker (un par ligne) et le contenu de GITHUB_OUTPUT."""
    script = tmp_path / "etape.sh"
    script.write_text(etape("secrets")["run"], encoding="utf-8")
    faux = tmp_path / "bin"
    faux.mkdir()
    journal = tmp_path / "docker.args"
    docker = faux / "docker"
    docker.write_text(f'#!/bin/bash\nprintf "%s\\n" "$@" > "{journal}"\nexit 0\n')
    docker.chmod(0o755)
    sortie = tmp_path / "github_output"
    sortie.write_text("")
    env = {
        **os.environ,
        "PATH": f"{faux}:{os.environ['PATH']}",
        "RUNNER_TEMP": str(tmp_path / "temp"),
        "GITHUB_OUTPUT": str(sortie),
        "GITHUB_REPOSITORY": "Baseline-quebec/exemple",
        "SECRETS_SEULEMENT": "true" if seulement else "false",
        "CIBLE": "develop",
    }
    (tmp_path / "temp").mkdir()
    resultat = subprocess.run(
        ["bash", str(script)],
        cwd=depot,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    arguments = journal.read_text() if journal.exists() else ""
    return resultat, arguments, sortie.read_text()


def test_pr_vers_develop_scanne_le_diff_de_la_pr(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    depot, base, tete = depot_fusion
    resultat, args, sortie = lancer_gitleaks(depot, tmp_path, True)
    assert resultat.returncode == 0, resultat.stderr
    plage = f"{base}..{tete}"
    assert f"git\n/src\n--log-opts={plage}\n" in args
    assert "dir\n" not in args
    assert "portee=diff" in sortie


def test_le_scan_du_diff_garde_les_options_de_la_decision_d3(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    _, args, _ = lancer_gitleaks(depot_fusion[0], tmp_path, True)
    options = (
        "--redact",
        "--ignore-gitleaks-allow",
        "--gitleaks-ignore-path",
        "/dev/null",
        "--exit-code",
        "1",
    )
    for option in options:
        assert f"{option}\n" in args, option
    assert "GITLEAKS_CONFIG_TOML=[extend]\nuseDefault = true\n" in args
    assert "ghcr.io/gitleaks/gitleaks@sha256:" in args


def test_pr_vers_la_branche_par_defaut_scanne_l_arbre(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    resultat, args, sortie = lancer_gitleaks(depot_fusion[0], tmp_path, False)
    assert resultat.returncode == 0, resultat.stderr
    assert "dir\n/src\n" in args
    assert "--log-opts" not in args
    assert "portee=arbre" in sortie


def test_historique_tronque_bascule_sur_l_arbre(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    clone = tmp_path / "clone"
    source = f"file://{depot_fusion[0]}"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", "--branch", "fusion", source, str(clone)],
        check=True,
        capture_output=True,
        timeout=60,
    )
    resultat, args, sortie = lancer_gitleaks(clone, tmp_path, True)
    assert resultat.returncode == 0, resultat.stderr
    assert "dir\n/src\n" in args
    assert "--log-opts" not in args
    assert "portee=arbre" in sortie
    assert "::warning title=gitleaks::Diff de la pull request" in resultat.stdout


def test_sans_commit_de_fusion_bascule_sur_l_arbre(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    depot = depot_fusion[0]
    git(depot, "checkout", "-q", "feature")  # un seul parent
    resultat, args, sortie = lancer_gitleaks(depot, tmp_path, True)
    assert resultat.returncode == 0, resultat.stderr
    assert "dir\n/src\n" in args
    assert "portee=arbre" in sortie


def test_l_exception_datee_de_decor_st_canevas_vaut_dans_les_deux_modes() -> None:
    """Le bloc des exceptions suit le scan : il ne dépend d'aucun mode."""
    script = etape("secrets")["run"]
    assert 'exceptions="Baseline-quebec/decor-st-Canevas:20270412"' in script
    avant_scan, apres_scan = script.split('"${scan[@]}"', 1)
    assert "exceptions=" not in avant_scan
    assert "exceptions=" in apres_scan
    assert "SECRETS_SEULEMENT" not in apres_scan


# --------------------------------------------------------------------------
# Le verdict
# --------------------------------------------------------------------------


def test_le_verdict_nomme_le_mode_et_ne_compte_pas_les_etapes_sautees() -> None:
    script = etape("Verdict")["run"]
    assert "PR vers $CIBLE : secrets seulement" in script
    assert "PR vers la branche par défaut : contrôles complets" in script
    # Une étape sautée s'écrit « non exécuté », jamais « skipped » ni « success ».
    assert "non exécuté" in script
    assert 'echo "non exécuté"' in script
