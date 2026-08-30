"""Tests de la détection de ce qu'il y a à analyser dans un dépôt.

Cette logique décide quels outils tournent. Une erreur ici ne casse rien de
visible : elle fait silencieusement sauter un scanner, et le dépôt passe pour
propre. Elle vivait dans un bloc `run:` de l'action, où rien ne pouvait la
tester ; ces tests sont la contrepartie de son extraction.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent / "detecter.sh"


def lancer(racine: Path) -> subprocess.CompletedProcess[str]:
    """Lance le script sans exiger qu'il réussisse."""
    return subprocess.run(
        ["bash", str(SCRIPT), str(racine)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def detecter(racine: Path) -> dict[str, str]:
    """Lance le script et rend ses trois sorties sous forme de dictionnaire.

    Exige un succès et une sortie d'erreur vide : un scanner qui bavarde dans
    les journaux finit par ne plus être lu, et c'est ainsi qu'un vrai message
    passe inaperçu.
    """
    resultat = lancer(racine)
    assert resultat.returncode == 0, resultat.stderr
    assert resultat.stderr == "", f"sortie d'erreur non vide : {resultat.stderr}"
    return dict(ligne.split("=", 1) for ligne in resultat.stdout.splitlines() if "=" in ligne)


def creer(racine: Path, *chemins: str) -> Path:
    """Crée une arborescence de fichiers vides."""
    for chemin in chemins:
        fichier = racine / chemin
        fichier.parent.mkdir(parents=True, exist_ok=True)
        fichier.write_text("", encoding="utf-8")
    return racine


def test_depot_vide_ne_declenche_aucun_outil(tmp_path: Path) -> None:
    assert detecter(tmp_path) == {"python": "non", "docker": "non", "iac": "non"}


def test_le_script_sort_toujours_les_trois_cles(tmp_path: Path) -> None:
    """Une clé manquante laisserait la sortie de l'étape vide, donc l'outil muet."""
    assert set(detecter(tmp_path)) == {"python", "docker", "iac"}


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------


def test_python_est_detecte_en_profondeur(tmp_path: Path) -> None:
    creer(tmp_path, "src/paquet/module.py")
    assert detecter(tmp_path)["python"] == "oui"


def test_python_dans_venv_ne_compte_pas(tmp_path: Path) -> None:
    """Le code d'un tiers n'est pas le nôtre.

    Sans l'élagage, bandit tournerait sur les dépendances installées et
    noierait les vrais constats sous ceux de paquets qu'on ne maintient pas.
    """
    creer(tmp_path, ".venv/lib/python3.12/site-packages/requests/api.py")
    assert detecter(tmp_path)["python"] == "non"


@pytest.mark.parametrize(
    "dossier", ["node_modules", ".venv", "venv", "vendor", "dist", "build", ".git"]
)
def test_tous_les_dossiers_elagues_le_sont_vraiment(tmp_path: Path, dossier: str) -> None:
    creer(tmp_path, f"{dossier}/quelque/part/module.py")
    assert detecter(tmp_path)["python"] == "non"


def test_un_dossier_elague_nempeche_pas_de_voir_le_reste(tmp_path: Path) -> None:
    """L'élagage doit retirer une branche, pas arrêter la recherche."""
    creer(tmp_path, "node_modules/paquet/index.py", "src/vrai.py")
    assert detecter(tmp_path)["python"] == "oui"


# --------------------------------------------------------------------------
# Dockerfile
# --------------------------------------------------------------------------


@pytest.mark.parametrize("nom", ["Dockerfile", "Dockerfile.prod", "docker/Dockerfile"])
def test_variantes_de_dockerfile_sont_vues(tmp_path: Path, nom: str) -> None:
    creer(tmp_path, nom)
    assert detecter(tmp_path)["docker"] == "oui"


def test_dockerfile_implique_iac(tmp_path: Path) -> None:
    """checkov porte ses propres contrôles sur les Dockerfile, en plus de hadolint."""
    creer(tmp_path, "Dockerfile")
    resultat = detecter(tmp_path)
    assert resultat["docker"] == "oui"
    assert resultat["iac"] == "oui"


def test_un_dossier_nomme_dockerfile_ne_compte_pas(tmp_path: Path) -> None:
    """`-type f` : un répertoire ne se scanne pas avec hadolint."""
    (tmp_path / "Dockerfile").mkdir()
    assert detecter(tmp_path)["docker"] == "non"


# --------------------------------------------------------------------------
# Infrastructure
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "nom",
    [
        "main.tf",
        "infra/main.tf",
        "config.tf.json",
        "modele.bicep",
        "docker-compose.yml",
        "docker-compose.prod.yaml",
        "charts/app/Chart.yaml",
    ],
)
def test_formes_dinfrastructure_reconnues(tmp_path: Path, nom: str) -> None:
    creer(tmp_path, nom)
    assert detecter(tmp_path)["iac"] == "oui"


def test_un_workflow_github_seul_ne_declenche_pas_checkov(tmp_path: Path) -> None:
    """Presque tous nos dépôts ont un workflow.

    Lancer checkov dessus rendrait le contrôle bruyant partout, et un gate
    bruyant finit ignoré.
    """
    creer(tmp_path, ".github/workflows/ci.yml", "README.md")
    assert detecter(tmp_path)["iac"] == "non"


def test_un_yaml_quelconque_ne_declenche_pas_checkov(tmp_path: Path) -> None:
    creer(tmp_path, "config.yaml", "donnees/valeurs.yml")
    assert detecter(tmp_path)["iac"] == "non"


# --------------------------------------------------------------------------
# Robustesse
# --------------------------------------------------------------------------


def test_racine_absente_est_une_erreur_bruyante(tmp_path: Path) -> None:
    """Rendre « rien à analyser » serait le pire des comportements.

    L'audit passerait au vert sans avoir rien scanné, ce qui est exactement le
    mode de panne que cette action existe pour rendre visible. Un `chemin` mal
    renseigné doit arrêter le job.
    """
    resultat = lancer(tmp_path / "nexiste_pas")
    assert resultat.returncode == 1
    assert "Chemin introuvable" in resultat.stderr
    assert "python=" not in resultat.stdout


def test_un_fichier_passe_comme_racine_est_refuse(tmp_path: Path) -> None:
    fichier = tmp_path / "pas_un_dossier.txt"
    fichier.write_text("", encoding="utf-8")
    assert lancer(fichier).returncode == 1


def test_chemin_avec_espace_est_gere(tmp_path: Path) -> None:
    racine = tmp_path / "un dossier avec espaces"
    creer(racine, "src/module.py")
    assert detecter(racine)["python"] == "oui"


def test_lien_symbolique_casse_ninterrompt_pas_la_detection(tmp_path: Path) -> None:
    """Et ne fait pas bavarder find dans les journaux du job."""
    (tmp_path / "casse").symlink_to(tmp_path / "cible_absente")
    creer(tmp_path, "src/module.py")
    assert detecter(tmp_path)["python"] == "oui"


def test_dossier_illisible_ninterrompt_pas_la_detection(tmp_path: Path) -> None:
    """Un dossier sans droit de lecture ne doit ni casser le scan ni polluer les logs."""
    creer(tmp_path, "src/module.py")
    interdit = tmp_path / "interdit"
    interdit.mkdir()
    (interdit / "cache.py").write_text("", encoding="utf-8")
    interdit.chmod(0o000)
    try:
        assert detecter(tmp_path)["python"] == "oui"
    finally:
        interdit.chmod(0o755)
