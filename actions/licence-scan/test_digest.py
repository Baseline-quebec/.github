"""Tests de l'agrégation du rapport mensuel de licences."""

from __future__ import annotations

import json
from pathlib import Path

from digest import agreger, main


def ecrire(dossier: Path, nom: str, contenu: dict[str, object]) -> None:
    sous = dossier / nom
    sous.mkdir(parents=True, exist_ok=True)
    (sous / "rapport.json").write_text(json.dumps(contenu), encoding="utf-8")


def test_depot_propre_compte_mais_napparait_pas(tmp_path: Path) -> None:
    """Le total analysé distingue « rien à signaler » de « rien scanné »."""
    ecrire(tmp_path, "a", {"depot": "org/propre", "interdites": [], "a_surveiller": []})
    depots, analyses = agreger(tmp_path)
    assert depots == []
    assert analyses == 1


def test_licence_dupliquee_nest_listee_quune_fois(tmp_path: Path) -> None:
    """Trois paquets LGPL dans un dépôt ne font pas trois puces illisibles."""
    ecrire(
        tmp_path,
        "b",
        {
            "depot": "org/touche",
            "interdites": [],
            "a_surveiller": [
                {"paquet": "psycopg", "licence": "LGPL-3.0-only"},
                {"paquet": "psycopg-binary", "licence": "LGPL-3.0-only"},
                {"paquet": "autre", "licence": "GPL-2.0"},
            ],
        },
    )
    depots, _ = agreger(tmp_path)
    assert depots == [{"depot": "org/touche", "elements": ["GPL-2.0", "LGPL-3.0-only"]}]


def test_rapport_illisible_ninterrompt_pas_lagregation(tmp_path: Path) -> None:
    ecrire(tmp_path, "c", {"depot": "org/sain", "interdites": [], "a_surveiller": []})
    casse = tmp_path / "d"
    casse.mkdir()
    (casse / "rapport.json").write_text("{pas du json", encoding="utf-8")
    _, analyses = agreger(tmp_path)
    assert analyses == 1


def test_interdites_et_surveiller_sont_fusionnees(tmp_path: Path) -> None:
    ecrire(
        tmp_path,
        "e",
        {
            "depot": "org/mixte",
            "interdites": [{"paquet": "x", "licence": "BUSL-1.1"}],
            "a_surveiller": [{"paquet": "y", "licence": "AGPL-3.0"}],
        },
    )
    depots, _ = agreger(tmp_path)
    assert depots[0]["elements"] == ["AGPL-3.0", "BUSL-1.1"]


def test_main_ecrit_le_resume_lu_ensuite_par_sweep(tmp_path: Path) -> None:
    """Le contrat entre digest.py et sweep.py est ce fichier : il doit tenir."""
    rapports = tmp_path / "rapports"
    ecrire(rapports, "a", {"depot": "org/a", "a_surveiller": [{"licence": "LGPL-3.0"}]})
    ecrire(rapports, "b", {"depot": "org/propre", "interdites": [], "a_surveiller": []})

    sortie = tmp_path / "resume.json"
    assert main(["--dossier", str(rapports), "--sortie", str(sortie)]) == 0

    contenu = json.loads(sortie.read_text(encoding="utf-8"))
    assert contenu["total_analyses"] == 2
    assert contenu["depots"] == [{"depot": "org/a", "elements": ["LGPL-3.0"]}]
