"""Le workflow `secrets.yml` (« Secrets Baseline ») lit tout ce qu'une PR apporte.

Décision du Directeur général du 2026-11-05, réalisée par DEUX workflows imposés
par deux rulesets : `secrets.yml` (gitleaks seul, toutes les branches) et
`conformite.yml` (contrôles complets, branche par défaut). Choisir le mode d'après
`base_ref` dans un seul workflow se contourne en reciblant la pull request.

Le scan du diff ne doit dépendre de rien que le dépôt contrôle : ni
`.gitattributes` (`* -diff`, `binary`), ni octet NUL, ni fusion dans la branche
(décision D3 : aucune exclusion). Le script est exécuté pour de vrai sur un dépôt
jetable avec un faux `docker`, pour voir les commandes exactes construites et les
fichiers donnés à lire.
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
WORKFLOW = RACINE / ".github/workflows/secrets.yml"
CONFORMITE = RACINE / ".github/workflows/conformite.yml"

PATRON_EXCEPTIONS = re.compile(r'^\s*exceptions="([^"]*)"', re.MULTILINE)


def charger() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def job() -> dict[str, Any]:
    return charger()["jobs"]["secrets"]


def etape(ident: str) -> dict[str, Any]:
    for e in job()["steps"]:
        if e.get("id") == ident or e.get("name") == ident:
            return e
    raise AssertionError(f"étape introuvable : {ident}")


# --------------------------------------------------------------------------
# Ce que les rulesets exigent
# --------------------------------------------------------------------------


def test_le_job_et_le_check_s_appellent_secrets_baseline() -> None:
    assert charger()["name"] == "Secrets Baseline"
    assert job()["name"] == "Secrets Baseline"


def test_un_seul_job_et_le_meme_garde_que_conformite() -> None:
    assert list(charger()["jobs"]) == ["secrets"]
    assert job()["if"] == "github.repository != 'Baseline-quebec/.github'"


def test_aucune_permission_d_ecriture() -> None:
    assert charger()["permissions"] == {"contents": "read"}


def test_pas_de_controle_hors_secrets() -> None:
    for e in job()["steps"]:
        assert "uses" not in e or e["uses"].startswith("actions/checkout@"), e


def test_historique_complet_seulement_pour_une_pull_request() -> None:
    checkout = job()["steps"][0]
    assert checkout["uses"].startswith("actions/checkout@")
    profondeur = checkout["with"]["fetch-depth"]
    # Chaînes '0' et '1' : le nombre 0 est faux et ferait choisir 1 à `&& ... ||`.
    assert "github.event_name == 'pull_request' && '0' || '1'" in profondeur


def test_gitleaks_ne_tourne_pas_apres_un_checkout_rate() -> None:
    """Sans `always()` : un checkout raté ne doit jamais donner un job vert."""
    assert "if" not in etape("secrets")
    assert etape("Verdict")["if"] == "always()"


def test_les_exceptions_datees_sont_celles_de_conformite() -> None:
    """Une seule liste de vérité : les deux workflows ne doivent pas dériver."""
    ici = PATRON_EXCEPTIONS.findall(WORKFLOW.read_text(encoding="utf-8"))
    la = PATRON_EXCEPTIONS.findall(CONFORMITE.read_text(encoding="utf-8"))
    assert ici
    assert ici == la


# --------------------------------------------------------------------------
# Le script gitleaks, exécuté avec un faux docker
# --------------------------------------------------------------------------

# Le faux docker consigne, pour chaque appel, ses arguments puis la liste des
# fichiers du dossier monté en /src (le dépôt est élagué de son .git). Son code
# de sortie vient de FAKE_STATUTS (un par appel, séparés par des espaces).
FAUX_DOCKER = r"""#!/bin/bash
journal="$FAKE_JOURNAL"
n=$(( $(cat "$journal.n" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$journal.n"
src="${4%:/src:ro}"
{
  echo "@@APPEL"
  printf "%s\n" "$@"
  echo "@@FICHIERS"
  (cd "$src" && find . -path ./.git -prune -o -type f -print | sort)
  echo "@@FIN"
} >> "$journal"
statuts=(${FAKE_STATUTS:-0 0 0})
exit "${statuts[$((n - 1))]:-0}"
"""


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


def ecrire(depot: Path, fichiers: dict[str, bytes]) -> None:
    for nom, contenu in fichiers.items():
        (depot / nom).write_bytes(contenu)
    git(depot, "add", "-A")


def construire_depot(
    tmp_path: Path,
    fichiers_pr: dict[str, bytes] | None = None,
    fusion_dans_la_pr: bool = False,
) -> tuple[Path, str, str]:
    """Dépôt au commit de fusion que GitHub extrait pour une PR : (dépôt, base, tête).

    La cible (`develop`) a avancé après le départ de la branche, comme en vrai.
    Avec `fusion_dans_la_pr`, la branche contient une fusion « maléfique » : un
    fichier n'existe que dans le commit de fusion, dans aucun de ses parents.
    """
    depot = tmp_path / "depot"
    depot.mkdir()
    git(depot, "init", "-q", "-b", "develop")
    ecrire(depot, {"a.txt": b"a\n"})
    git(depot, "commit", "-q", "-m", "base")
    git(depot, "checkout", "-q", "-b", "feature")
    ecrire(depot, fichiers_pr or {"b.txt": b"b\n"})
    git(depot, "commit", "-q", "-m", "pr")
    if fusion_dans_la_pr:
        git(depot, "checkout", "-q", "-b", "cote", "develop")
        ecrire(depot, {"cote.txt": b"cote\n"})
        git(depot, "commit", "-q", "-m", "cote")
        git(depot, "checkout", "-q", "feature")
        git(depot, "merge", "-q", "--no-ff", "--no-commit", "cote")
        ecrire(depot, {"malefique.txt": b"secret\n"})
        git(depot, "commit", "-q", "-m", "fusion dans la pr")
    git(depot, "checkout", "-q", "develop")
    ecrire(depot, {"c.txt": b"c\n"})
    git(depot, "commit", "-q", "-m", "develop avance")
    git(depot, "checkout", "-q", "-b", "fusion")
    git(depot, "merge", "-q", "--no-ff", "-m", "fusion", "feature")
    return depot, git(depot, "rev-parse", "HEAD^1"), git(depot, "rev-parse", "HEAD^2")


@pytest.fixture
def depot_fusion(tmp_path: Path) -> tuple[Path, str, str]:
    return construire_depot(tmp_path)


class Appel:
    """Un appel du faux docker : ses arguments et les fichiers qu'il aurait lus."""

    def __init__(self, brut: str) -> None:
        args, fichiers = brut.split("@@FICHIERS\n")
        self.args = args.splitlines()
        self.texte = args
        self.fichiers = sorted(f[2:] for f in fichiers.splitlines() if f.startswith("./"))

    def commande(self) -> str:
        """Le verbe gitleaks (`dir` ou `git`) qui précède la source `/src`."""
        return self.args[self.args.index("/src") - 1]


def lancer_gitleaks(
    depot: Path,
    tmp_path: Path,
    evenement: str = "pull_request",
    statuts: str = "0 0",
    repertoire: str = "Baseline-quebec/exemple",
) -> tuple[subprocess.CompletedProcess[str], list[Appel], str]:
    """Exécute le `run:` de l'étape gitleaks ; rend le résultat, les appels faits
    au faux docker et le contenu de GITHUB_OUTPUT."""
    script = tmp_path / "etape.sh"
    script.write_text(etape("secrets")["run"], encoding="utf-8")
    faux = tmp_path / "bin"
    faux.mkdir()
    journal = tmp_path / "docker.journal"
    docker = faux / "docker"
    docker.write_text(FAUX_DOCKER)
    docker.chmod(0o755)
    sortie = tmp_path / "github_output"
    sortie.write_text("")
    env = {
        **os.environ,
        "PATH": f"{faux}:{os.environ['PATH']}",
        "RUNNER_TEMP": str(tmp_path / "temp"),
        "GITHUB_OUTPUT": str(sortie),
        "GITHUB_REPOSITORY": repertoire,
        "EVENEMENT": evenement,
        "CIBLE": "develop",
        "FAKE_JOURNAL": str(journal),
        "FAKE_STATUTS": statuts,
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
    brut = journal.read_text() if journal.exists() else ""
    appels = [Appel(b.split("@@FIN")[0]) for b in brut.split("@@APPEL\n")[1:]]
    return resultat, appels, sortie.read_text()


def log_opts(base: str, tete: str) -> str:
    return f"--log-opts=--text --diff-merges=first-parent {base}..{tete}"


def test_pr_vers_develop_lit_le_diff_net_puis_l_historique(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    depot, base, tete = depot_fusion
    resultat, appels, sortie = lancer_gitleaks(depot, tmp_path)
    assert resultat.returncode == 0, resultat.stderr
    assert len(appels) == 2
    net, historique = appels
    # Diff net : `dir` sur les seuls fichiers apportés par la PR (pas c.txt, qui
    # vient de la cible, ni a.txt).
    assert net.commande() == "dir"
    assert net.fichiers == ["b.txt"]
    # Historique : git log avec --text et les diffs de fusion, plage explicite.
    assert historique.commande() == "git"
    assert log_opts(base, tete) in historique.args
    assert "portee=diff" in sortie
    assert "nature=aucune" in sortie


def test_les_deux_lectures_gardent_les_options_de_la_decision_d3(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    _, appels, _ = lancer_gitleaks(depot_fusion[0], tmp_path)
    options = ("--redact", "--ignore-gitleaks-allow", "--gitleaks-ignore-path", "/dev/null")
    for appel in appels:
        for option in options:
            assert option in appel.args, option
        assert appel.args[appel.args.index("--exit-code") + 1] == "2"
        assert "GITLEAKS_CONFIG_TOML=[extend]\nuseDefault = true" in appel.texte
        assert any(a.startswith("ghcr.io/gitleaks/gitleaks@sha256:") for a in appel.args)


def test_gitattributes_de_la_pr_ne_masque_aucun_fichier(tmp_path: Path) -> None:
    """`* -diff` fait dire à `git log -p` « Binary files differ » : gitleaks saute
    alors le fichier. La liste vient de `git diff --name-only`, que cela n'atteint
    pas, et `--text` couvre l'historique."""
    depot, base, tete = construire_depot(
        tmp_path,
        {".gitattributes": b"* -diff\n*.cle binary\n", "secret.txt": b"x\n", "k.cle": b"y\n"},
    )
    resultat, appels, _ = lancer_gitleaks(depot, tmp_path)
    assert resultat.returncode == 0, resultat.stderr
    assert appels[0].fichiers == [".gitattributes", "k.cle", "secret.txt"]
    assert log_opts(base, tete) in appels[1].args


def test_fichier_binaire_avec_octet_nul_est_lu(tmp_path: Path) -> None:
    depot, _, _ = construire_depot(tmp_path, {"blob.dat": b"debut\x00AKIA...fin\n"})
    resultat, appels, _ = lancer_gitleaks(depot, tmp_path)
    assert resultat.returncode == 0, resultat.stderr
    assert appels[0].fichiers == ["blob.dat"]
    assert "--text" in appels[1].texte


def test_fusion_malefique_dans_la_branche_de_la_pr_est_lue(tmp_path: Path) -> None:
    """Un fichier qui n'existe que dans un commit de fusion de la branche n'a
    pas de diff dans `git log -p` ; le diff net le voit, et l'historique montre
    les fusions (`--diff-merges=first-parent`)."""
    depot, base, tete = construire_depot(tmp_path, fusion_dans_la_pr=True)
    resultat, appels, _ = lancer_gitleaks(depot, tmp_path)
    assert resultat.returncode == 0, resultat.stderr
    assert "malefique.txt" in appels[0].fichiers
    assert "b.txt" in appels[0].fichiers
    assert log_opts(base, tete) in appels[1].args


def test_le_gitleaksignore_de_la_pr_n_est_jamais_copie(tmp_path: Path) -> None:
    depot, _, _ = construire_depot(
        tmp_path, {".gitleaksignore": b"/src/b.txt:regle:1\n", "b.txt": b"b\n"}
    )
    resultat, appels, _ = lancer_gitleaks(depot, tmp_path)
    assert resultat.returncode == 0, resultat.stderr
    assert appels[0].fichiers == ["b.txt"]
    # Retiré pour le scan puis remis dans l'espace de travail.
    assert (depot / ".gitleaksignore").exists()


def test_les_fichiers_supprimes_ne_sont_pas_demandes_a_tar(tmp_path: Path) -> None:
    depot, _, _ = construire_depot(tmp_path)
    git(depot, "checkout", "-q", "feature")
    git(depot, "rm", "-q", "a.txt")
    git(depot, "commit", "-q", "-m", "supprime")
    git(depot, "checkout", "-q", "-B", "fusion2", "develop")
    git(depot, "merge", "-q", "--no-ff", "-m", "fusion", "feature")
    resultat, appels, sortie = lancer_gitleaks(depot, tmp_path)
    assert resultat.returncode == 0, resultat.stderr
    assert appels[0].fichiers == ["b.txt"]
    assert "portee=diff" in sortie


def test_pr_vers_la_branche_par_defaut_lit_l_arbre(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    resultat, appels, sortie = lancer_gitleaks(depot_fusion[0], tmp_path, "merge_group")
    assert resultat.returncode == 0, resultat.stderr
    assert len(appels) == 1
    assert appels[0].commande() == "dir"
    assert "--log-opts" not in appels[0].texte
    assert {"a.txt", "b.txt", "c.txt"} <= set(appels[0].fichiers)
    assert "portee=arbre" in sortie


def clone_tronque(depot: Path, tmp_path: Path) -> Path:
    clone = tmp_path / "clone"
    source = f"file://{depot}"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", "--branch", "fusion", source, str(clone)],
        check=True,
        capture_output=True,
        timeout=60,
    )
    return clone


def verifier_repli_sur_l_arbre(
    resultat: subprocess.CompletedProcess[str], appels: list[Appel], sortie: str
) -> None:
    assert resultat.returncode == 0, resultat.stderr
    assert len(appels) == 1
    assert appels[0].commande() == "dir"
    assert "--log-opts" not in appels[0].texte
    assert "portee=arbre" in sortie
    assert "::warning title=gitleaks::Diff de la pull request" in resultat.stdout


def test_historique_tronque_bascule_sur_l_arbre(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    clone = clone_tronque(depot_fusion[0], tmp_path)
    verifier_repli_sur_l_arbre(*lancer_gitleaks(clone, tmp_path))


def test_sans_commit_de_fusion_bascule_sur_l_arbre(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    depot = depot_fusion[0]
    git(depot, "checkout", "-q", "feature")  # un seul parent
    verifier_repli_sur_l_arbre(*lancer_gitleaks(depot, tmp_path))


def test_ancetre_commun_introuvable_bascule_sur_l_arbre(tmp_path: Path) -> None:
    """Deux historiques sans racine commune : `git merge-base` échoue."""
    depot = tmp_path / "depot"
    depot.mkdir()
    git(depot, "init", "-q", "-b", "develop")
    ecrire(depot, {"a.txt": b"a\n"})
    git(depot, "commit", "-q", "-m", "base")
    git(depot, "checkout", "-q", "--orphan", "autre")
    git(depot, "rm", "-rfq", ".")
    ecrire(depot, {"z.txt": b"z\n"})
    git(depot, "commit", "-q", "-m", "autre racine")
    git(depot, "checkout", "-q", "develop")
    git(depot, "merge", "-q", "--allow-unrelated-histories", "--no-ff", "-m", "fusion", "autre")
    verifier_repli_sur_l_arbre(*lancer_gitleaks(depot, tmp_path))


@pytest.mark.parametrize("evenement", ["pull_request", "merge_group", "workflow_dispatch"])
def test_un_secret_bloque_et_se_distingue_d_une_erreur_technique(
    depot_fusion: tuple[Path, str, str], tmp_path: Path, evenement: str
) -> None:
    # Code 2 = secret trouvé ; le second scan (diff) peut rester propre.
    resultat, _, sortie = lancer_gitleaks(depot_fusion[0], tmp_path, evenement, "2 0")
    assert resultat.returncode == 1
    assert "nature=secret" in sortie


@pytest.mark.parametrize("statuts", ["0 1", "1 0", "2 1", "1 2"])
def test_une_erreur_technique_bloque_et_l_emporte(
    depot_fusion: tuple[Path, str, str], tmp_path: Path, statuts: str
) -> None:
    resultat, _, sortie = lancer_gitleaks(depot_fusion[0], tmp_path, statuts=statuts)
    assert resultat.returncode == 1
    assert "nature=technique" in sortie
    assert "Erreur technique du scan" in resultat.stdout


def test_un_echec_du_second_scan_suffit_a_echouer(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    resultat, _, _ = lancer_gitleaks(depot_fusion[0], tmp_path, statuts="0 2")
    assert resultat.returncode == 1


@pytest.mark.parametrize("evenement", ["pull_request", "merge_group"])
def test_l_exception_datee_vaut_pour_un_secret_dans_chaque_mode(
    depot_fusion: tuple[Path, str, str], tmp_path: Path, evenement: str
) -> None:
    resultat, _, _ = lancer_gitleaks(
        depot_fusion[0], tmp_path, evenement, "2 0", "Baseline-quebec/decor-st-Canevas"
    )
    assert resultat.returncode == 0, resultat.stderr
    assert "Dépôt en exception" in resultat.stdout


def test_l_exception_datee_n_excuse_pas_une_erreur_technique(
    depot_fusion: tuple[Path, str, str], tmp_path: Path
) -> None:
    resultat, _, _ = lancer_gitleaks(
        depot_fusion[0], tmp_path, "pull_request", "1 0", "Baseline-quebec/decor-st-Canevas"
    )
    assert resultat.returncode == 1


def test_le_bloc_des_exceptions_ne_depend_d_aucun_mode() -> None:
    script = etape("secrets")["run"]
    assert 'exceptions="Baseline-quebec/decor-st-Canevas:20270412"' in script
    avant, apres = script.split("exceptions=", 1)
    assert 'lancer "$PWD"' in avant
    assert "EVENEMENT" not in apres


# --------------------------------------------------------------------------
# Le verdict, exécuté
# --------------------------------------------------------------------------


def lancer_verdict(tmp_path: Path, **variables: str) -> tuple[int, str, str]:
    script = tmp_path / "verdict.sh"
    script.write_text(etape("Verdict")["run"], encoding="utf-8")
    resume = tmp_path / "resume.md"
    resume.write_text("")
    env = {
        **os.environ,
        "SECRETS": "success",
        "PORTEE": "diff",
        "NATURE": "aucune",
        "EVENEMENT": "pull_request",
        "CIBLE": "develop",
        "GITHUB_STEP_SUMMARY": str(resume),
        **variables,
    }
    resultat = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, env=env, timeout=60
    )
    return resultat.returncode, resultat.stdout, resume.read_text()


def test_verdict_pr_propre(tmp_path: Path) -> None:
    code, sortie, resume = lancer_verdict(tmp_path)
    assert code == 0
    assert "PR vers develop : secrets" in resume
    assert "diff net et historique de la pull request" in resume
    ligne = "| Secrets en clair (gitleaks, bloquant) : diff net et historique"
    assert f"{ligne} de la pull request | success |" in resume
    assert "PR vers develop : secrets" in sortie


def test_verdict_secret_trouve(tmp_path: Path) -> None:
    code, _, resume = lancer_verdict(tmp_path, SECRETS="failure", NATURE="secret")
    assert code == 1
    assert "secret en clair trouvé par gitleaks" in resume
    assert "erreur technique" not in resume


def test_verdict_erreur_technique_distincte_du_secret(tmp_path: Path) -> None:
    code, _, resume = lancer_verdict(tmp_path, SECRETS="failure", NATURE="technique")
    assert code == 1
    assert "erreur technique du scan gitleaks" in resume
    assert "secret en clair trouvé" not in resume


def test_verdict_repli_sur_l_arbre_est_dit(tmp_path: Path) -> None:
    code, _, resume = lancer_verdict(tmp_path, PORTEE="arbre")
    assert code == 0
    assert "arbre complet (repli : diff impossible à établir)" in resume


def test_verdict_merge_group_lit_l_arbre(tmp_path: Path) -> None:
    code, _, resume = lancer_verdict(tmp_path, EVENEMENT="merge_group", PORTEE="arbre")
    assert code == 0
    assert "merge_group : secrets" in resume
    assert "arbre complet" in resume
    assert "repli" not in resume


def test_verdict_exception_datee_n_est_pas_un_vert_muet(tmp_path: Path) -> None:
    code, _, resume = lancer_verdict(tmp_path, NATURE="secret")
    assert code == 0
    assert "dépôt en exception datée : avertissement seulement" in resume


@pytest.mark.parametrize("resultat", ["skipped", "cancelled", ""])
def test_verdict_une_etape_non_passee_n_est_jamais_propre(tmp_path: Path, resultat: str) -> None:
    code, _, resume = lancer_verdict(tmp_path, SECRETS=resultat, PORTEE="", NATURE="")
    assert code == 1
    assert "success" not in resume
    assert "non exécuté" in resume or resultat == "cancelled"
