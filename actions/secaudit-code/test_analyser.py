"""Tests du lancement parallèle de semgrep, trivy et checkov.

Les vrais outils sont remplacés par des doubles placés en tête du PATH : `uv`
pour semgrep et checkov, `docker` pour trivy. Chaque double note ses arguments,
son répertoire courant et ses heures de début et de fin, puis écrit un rapport
comme le ferait l'outil. Le dépôt, lui, est un vrai dépôt git : c'est sur git
que repose le choix entre analyse incrémentale et analyse complète.

Ce qui est gardé :
- l'incrémental ne s'applique que si une base est fournie, et toute
  impossibilité retombe sur l'analyse complète, jamais sur un scan sauté ;
- l'incrémental tourne hors du checkout partagé, que semgrep remettrait sinon
  à l'état de la base pendant que trivy et checkov le lisent ;
- les trois outils tournent réellement en même temps.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent / "analyser.sh"

FAUX_UV = r"""#!/usr/bin/env bash
[ "${ECHEC_TOUT:-0}" = 1 ] && exit 3
debut=$(date +%s.%N)
outil=inconnu
case "$*" in
  *semgrep==*) outil=semgrep ;;
  *checkov==*) outil=checkov ;;
esac
sleep "${DELAI:-0}"
if [ "$outil" = semgrep ]; then
  case "$*" in
    *--baseline-commit*) [ "${ECHEC_INCREMENTAL:-0}" = 1 ] && exit 2 ;;
  esac
  sortie=""
  precedent=""
  for a in "$@"; do
    [ "$precedent" = "--output" ] && sortie="$a"
    precedent="$a"
  done
  echo '{"results": []}' > "$sortie"
fi
[ "$outil" = checkov ] && echo '{"results": {}}'
printf '%s\t%s\t%s\t%s\t%s\n' "$outil" "$debut" "$(date +%s.%N)" "$PWD" "$*" >> "$JOURNAL_FAUX"
"""

FAUX_DOCKER = r"""#!/usr/bin/env bash
[ "${ECHEC_TOUT:-0}" = 1 ] && exit 3
debut=$(date +%s.%N)
sleep "${DELAI:-0}"
precedent=""
for a in "$@"; do
  if [ "$precedent" = "-v" ] && [ "${a##*:}" = "/out" ]; then
    echo '{"Results": []}' > "${a%:/out}/trivy.json"
  fi
  precedent="$a"
done
printf '%s\t%s\t%s\t%s\t%s\n' trivy "$debut" "$(date +%s.%N)" "$PWD" "$*" >> "$JOURNAL_FAUX"
"""


def git(depot: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(depot), *arguments],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.fixture
def depot(tmp_path: Path) -> tuple[Path, str]:
    """Dépôt à deux commits ; rend sa racine et le commit de base."""
    racine = tmp_path / "depot"
    racine.mkdir()
    git(racine, "init", "--quiet")
    git(racine, "config", "user.email", "test@example.com")
    git(racine, "config", "user.name", "Test")
    (racine / "app.py").write_text("print('base')\n", encoding="utf-8")
    git(racine, "add", ".")
    git(racine, "commit", "--quiet", "-m", "base")
    base = git(racine, "rev-parse", "HEAD")
    (racine / "app.py").write_text("print('tete')\n", encoding="utf-8")
    git(racine, "commit", "--quiet", "-am", "tete")
    return racine, base


def lancer(
    racine: Path, tmp_path: Path, **env: str
) -> tuple[subprocess.CompletedProcess[str], list[dict[str, str]], Path]:
    """Lance le script avec les doubles ; rend le résultat, les appels et les rapports."""
    faux = tmp_path / "faux"
    faux.mkdir(exist_ok=True)
    for nom, contenu in (("uv", FAUX_UV), ("docker", FAUX_DOCKER)):
        chemin = faux / nom
        chemin.write_text(contenu, encoding="utf-8")
        chemin.chmod(0o755)
    rapports = tmp_path / "rapports"
    rapports.mkdir(exist_ok=True)
    journal = tmp_path / "appels.tsv"
    environnement = {
        **os.environ,
        "PATH": f"{faux}:{os.environ['PATH']}",
        "RAPPORTS": str(rapports),
        "JOURNAL_FAUX": str(journal),
        **env,
    }
    resultat = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=racine,
        env=environnement,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    appels = []
    if journal.exists():
        for ligne in journal.read_text(encoding="utf-8").splitlines():
            outil, debut, fin, cwd, arguments = ligne.split("\t")
            appels.append(
                {"outil": outil, "debut": debut, "fin": fin, "cwd": cwd, "args": arguments}
            )
    return resultat, appels, rapports


def appels_de(appels: list[dict[str, str]], outil: str) -> list[dict[str, str]]:
    return [a for a in appels if a["outil"] == outil]


def test_sans_base_semgrep_analyse_tout_le_checkout(depot, tmp_path: Path) -> None:
    racine, _ = depot
    resultat, appels, rapports = lancer(racine, tmp_path, BASE_SEMGREP="")
    assert resultat.returncode == 0, resultat.stderr
    (semgrep,) = appels_de(appels, "semgrep")
    assert "--baseline-commit" not in semgrep["args"]
    assert Path(semgrep["cwd"]) == racine
    assert json.loads((rapports / "semgrep.json").read_text()) == {"results": []}
    assert "semgrep : analyse complete" in resultat.stdout


def test_avec_base_semgrep_est_incremental_hors_du_checkout(depot, tmp_path: Path) -> None:
    """semgrep remet son arbre à l'état de la base : jamais celui que lisent trivy et checkov."""
    racine, base = depot
    resultat, appels, rapports = lancer(racine, tmp_path, BASE_SEMGREP=base)
    assert resultat.returncode == 0, resultat.stderr
    (semgrep,) = appels_de(appels, "semgrep")
    assert f"--baseline-commit {base}" in semgrep["args"]
    assert Path(semgrep["cwd"]) != racine
    assert not Path(semgrep["cwd"]).exists(), "l'arbre de travail temporaire n'a pas été retiré"
    assert len(git(racine, "worktree", "list").splitlines()) == 1
    assert (rapports / "semgrep.json").is_file()
    assert "analyse incrementale" in resultat.stdout


def test_une_base_inconnue_retombe_sur_l_analyse_complete(depot, tmp_path: Path) -> None:
    """Un raccourci impossible ne doit jamais devenir un scan sauté."""
    racine, _ = depot
    resultat, appels, _ = lancer(racine, tmp_path, BASE_SEMGREP="0" * 40)
    assert resultat.returncode == 0, resultat.stderr
    (semgrep,) = appels_de(appels, "semgrep")
    assert "--baseline-commit" not in semgrep["args"]
    assert Path(semgrep["cwd"]) == racine
    assert "::notice title=semgrep::" in resultat.stdout


def test_un_echec_de_l_incremental_relance_l_analyse_complete(depot, tmp_path: Path) -> None:
    racine, base = depot
    resultat, appels, rapports = lancer(racine, tmp_path, BASE_SEMGREP=base, ECHEC_INCREMENTAL="1")
    assert resultat.returncode == 0, resultat.stderr
    semgrep = appels_de(appels, "semgrep")
    assert len(semgrep) == 1, "le double ne journalise que l'analyse complète, qui a réussi"
    assert "--baseline-commit" not in semgrep[0]["args"]
    assert (rapports / "semgrep.json").is_file()
    assert len(git(racine, "worktree", "list").splitlines()) == 1


def test_une_base_qui_n_est_pas_un_ancetre_est_refusee(depot, tmp_path: Path) -> None:
    """Une base hors de l'historique de HEAD ferait comparer deux branches sans rapport."""
    racine, base = depot
    git(racine, "checkout", "--quiet", "--orphan", "autre")
    git(racine, "commit", "--quiet", "-m", "orphelin")
    resultat, appels, _ = lancer(racine, tmp_path, BASE_SEMGREP=base)
    (semgrep,) = appels_de(appels, "semgrep")
    assert "--baseline-commit" not in semgrep["args"]
    assert "::notice title=semgrep::" in resultat.stdout


def test_checkov_ne_tourne_que_sur_de_l_infrastructure(depot, tmp_path: Path) -> None:
    racine, _ = depot
    _, appels, rapports = lancer(racine, tmp_path, IAC="non")
    assert not appels_de(appels, "checkov")
    assert not (rapports / "checkov.json").exists()


def test_les_trois_outils_ecrivent_leur_rapport(depot, tmp_path: Path) -> None:
    racine, _ = depot
    resultat, appels, rapports = lancer(racine, tmp_path, IAC="oui")
    assert resultat.returncode == 0, resultat.stderr
    assert {a["outil"] for a in appels} == {"semgrep", "trivy", "checkov"}
    for outil in ("semgrep", "trivy", "checkov"):
        assert json.loads((rapports / f"{outil}.json").read_text()), outil
    journal = (rapports / "_outils.log").read_text()
    for outil in ("semgrep", "trivy", "checkov"):
        assert f"===== {outil} =====" in journal
        assert f"{outil} : " in resultat.stdout, "la durée de chaque outil doit être visible"


def test_les_trois_outils_tournent_en_meme_temps(depot, tmp_path: Path) -> None:
    """Chaque outil démarre avant que les autres aient fini : c'est tout le gain."""
    racine, _ = depot
    _, appels, _ = lancer(racine, tmp_path, IAC="oui", DELAI="1")
    assert len(appels) == 3
    dernier_debut = max(float(a["debut"]) for a in appels)
    premiere_fin = min(float(a["fin"]) for a in appels)
    assert dernier_debut < premiere_fin


def test_un_outil_en_echec_n_emporte_pas_l_etape(depot, tmp_path: Path) -> None:
    """Le rapport manquant sera signalé muet par rapport.py ; l'étape, elle, continue."""
    racine, _ = depot
    resultat, _, rapports = lancer(racine, tmp_path, IAC="oui", ECHEC_TOUT="1")
    assert resultat.returncode == 0, resultat.stderr
    assert not (rapports / "semgrep.json").exists()
    assert re.search(r"semgrep : \d+ s, statut 3", resultat.stdout)
    assert "statut" in (rapports / "_outils.log").read_text()
