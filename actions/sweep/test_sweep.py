"""Tests de la mécanique commune aux balayages d'organisation.

Ce module porte les deux moments où un balayage peut mentir en silence :
l'énumération qui rend une liste vide sans erreur, et l'envoi qui échoue sans
que personne ne l'apprenne. Les tests visent d'abord ces deux-là.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
import sweep
from sweep import (
    MAX_MATRICE,
    SEUIL_ALERTE_MATRICE,
    envoyer,
    lire_resume,
    lister_depots,
    main,
    windmill_configure,
)


class FauxResultat:
    """Ce que `subprocess.run` rend, réduit à ce que le code lit."""

    def __init__(self, code: int, sortie: str = "", erreur: str = "") -> None:
        self.returncode = code
        self.stdout = sortie
        self.stderr = erreur


@pytest.fixture(autouse=True)
def sans_windmill(monkeypatch: pytest.MonkeyPatch) -> None:
    """Aucun test ne doit dependre de la configuration Windmill de la machine."""
    monkeypatch.delenv("WINDMILL_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("WINDMILL_TOKEN", raising=False)


# --------------------------------------------------------------------------
# Énumération des dépôts
# --------------------------------------------------------------------------


def test_depots_sont_lus_ligne_par_ligne(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: FauxResultat(0, "org/a\norg/b\n\n  org/c  \n")
    )
    assert lister_depots(set()) == ["org/a", "org/b", "org/c"]


def test_exclusion_accepte_le_nom_court_et_le_nom_complet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FauxResultat(0, "org/a\norg/b\norg/c\n"))
    assert lister_depots({".github", "b"}) == ["org/a", "org/c"]
    assert lister_depots({"org/a"}) == ["org/b", "org/c"]


def test_echec_de_gh_rend_une_liste_vide(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FauxResultat(1, "", "HTTP 401"))
    assert lister_depots(set()) == []


def test_delai_depasse_ne_remonte_pas_de_trace_de_pile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """La pagination sur une centaine de depots peut deborder un jour de lenteur.

    Une exception non capturee donnerait une trace de pile a la place du message
    qui dit quoi faire, et le job echouerait sans diagnostic.
    """

    def leve(*a: object, **k: object) -> None:
        raise subprocess.TimeoutExpired(cmd="gh", timeout=60)

    monkeypatch.setattr(subprocess, "run", leve)
    assert lister_depots(set()) == []


def test_gh_absent_ne_remonte_pas_de_trace_de_pile(monkeypatch: pytest.MonkeyPatch) -> None:
    def leve(*a: object, **k: object) -> None:
        raise FileNotFoundError("gh")

    monkeypatch.setattr(subprocess, "run", leve)
    assert lister_depots(set()) == []


def test_liste_vide_fait_echouer_la_commande(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Sous SSO, un jeton non autorise rend une liste vide sans erreur.

    Terminer en succes ferait croire a une organisation sans depot, et le
    rapport annoncerait fierement zero probleme.
    """
    monkeypatch.setattr(sweep, "lister_depots", lambda exclus: [])
    assert main(["lister"]) == 1
    assert "::error" in capsys.readouterr().out


def test_liste_est_ecrite_dans_la_sortie_du_job(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sortie = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(sortie))
    monkeypatch.setattr(sweep, "lister_depots", lambda exclus: ["org/a", "org/b"])

    assert main(["lister", "--exclure", "x"]) == 0
    assert sortie.read_text(encoding="utf-8").strip() == 'depots=["org/a", "org/b"]'


def test_exclusion_est_decoupee_sur_les_virgules(monkeypatch: pytest.MonkeyPatch) -> None:
    recus: list[set[str]] = []
    monkeypatch.setattr(sweep, "lister_depots", lambda exclus: recus.append(exclus) or ["org/a"])
    main(["lister", "--exclure", " .github , tracking , "])
    assert recus == [{".github", "tracking"}]


def test_matrice_trop_grande_arrete_le_balayage(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """GitHub refuse une matrice de plus de 256 jobs.

    Franchir la limite ferait echouer le balayage entier, avec un message qui
    ne dit pas quoi faire. Le dire nous-memes laisse le temps de decouper.
    """
    trop = [f"org/depot{i}" for i in range(MAX_MATRICE + 1)]
    monkeypatch.setattr(sweep, "lister_depots", lambda exclus: trop)
    assert main(["lister"]) == 1
    assert "Matrice trop grande" in capsys.readouterr().out


def test_matrice_a_la_limite_exacte_passe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """256 est accepte, 257 non : la limite est inclusive."""
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "sortie"))
    pile = [f"org/depot{i}" for i in range(MAX_MATRICE)]
    monkeypatch.setattr(sweep, "lister_depots", lambda exclus: pile)
    assert main(["lister"]) == 0
    assert "Matrice trop grande" not in capsys.readouterr().out


def test_matrice_proche_de_la_limite_avertit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "sortie"))
    presque = [f"org/depot{i}" for i in range(SEUIL_ALERTE_MATRICE)]
    monkeypatch.setattr(sweep, "lister_depots", lambda exclus: presque)
    assert main(["lister"]) == 0
    assert "Matrice bientot pleine" in capsys.readouterr().out


def test_taille_courante_ne_declenche_aucune_alerte(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """L'organisation compte 120 depots actifs : le seuil ne doit pas crier tout de suite."""
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "sortie"))
    monkeypatch.setattr(sweep, "lister_depots", lambda exclus: [f"org/d{i}" for i in range(120)])
    assert main(["lister"]) == 0
    assert "::warning" not in capsys.readouterr().out


# --------------------------------------------------------------------------
# Lecture du résumé
# --------------------------------------------------------------------------


def test_resume_bien_forme_est_lu(tmp_path: Path) -> None:
    fichier = tmp_path / "resume.json"
    fichier.write_text(
        json.dumps({"depots": [{"depot": "org/a", "elements": ["x"]}], "total_analyses": 82}),
        encoding="utf-8",
    )
    depots, analyses = lire_resume(fichier)
    assert depots == [{"depot": "org/a", "elements": ["x"]}]
    assert analyses == 82


def test_resume_vide_est_valide(tmp_path: Path) -> None:
    """Zero depot a signaler sur 82 analyses est un resultat, pas une anomalie."""
    fichier = tmp_path / "resume.json"
    fichier.write_text(json.dumps({"depots": [], "total_analyses": 82}), encoding="utf-8")
    assert lire_resume(fichier) == ([], 82)


def test_resume_qui_nest_pas_un_objet_est_refuse(tmp_path: Path) -> None:
    """Un tableau JSON faisait remonter un AttributeError non capture."""
    fichier = tmp_path / "resume.json"
    fichier.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError, match="objet JSON"):
        lire_resume(fichier)


def test_depots_qui_nest_pas_une_liste_est_refuse(tmp_path: Path) -> None:
    """`list()` sur un dictionnaire rendrait ses cles, et un rapport absurde partirait."""
    fichier = tmp_path / "resume.json"
    fichier.write_text(json.dumps({"depots": {"org/a": 1}, "total_analyses": 3}), encoding="utf-8")
    with pytest.raises(ValueError, match="liste"):
        lire_resume(fichier)


def test_entrees_non_objets_sont_ecartees(tmp_path: Path) -> None:
    fichier = tmp_path / "resume.json"
    fichier.write_text(
        json.dumps({"depots": [{"depot": "org/a"}, "bruit", None], "total_analyses": 2}),
        encoding="utf-8",
    )
    depots, _ = lire_resume(fichier)
    assert depots == [{"depot": "org/a"}]


def test_resume_illisible_fait_echouer_la_commande(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Un « rien a signaler » mensonger est pire qu'un rapport manquant."""
    fichier = tmp_path / "resume.json"
    fichier.write_text("{pas du json", encoding="utf-8")
    assert main(["envoyer", "--type-rapport", "cve", "--fichier", str(fichier)]) == 1
    assert "Resume illisible" in capsys.readouterr().out


def test_resume_absent_fait_echouer_la_commande(tmp_path: Path) -> None:
    absent = str(tmp_path / "jamais_ecrit.json")
    assert main(["envoyer", "--type-rapport", "cve", "--fichier", absent]) == 1


# --------------------------------------------------------------------------
# Envoi
# --------------------------------------------------------------------------


def test_windmill_non_configure_saute_lenvoi(monkeypatch: pytest.MonkeyPatch) -> None:
    def interdit(*a: object, **k: object) -> None:
        raise AssertionError("aucun appel réseau ne doit partir sans configuration")

    monkeypatch.setattr(sweep.urllib.request, "urlopen", interdit)
    assert envoyer("cve", [], 0) is False


def test_envoi_poste_la_charge_attendue(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WINDMILL_WEBHOOK_URL", "https://windmill.example/w/1")
    monkeypatch.setenv("WINDMILL_TOKEN", "jeton")
    captures: list[Any] = []

    class FausseReponse:
        status = 200

        def __enter__(self) -> FausseReponse:
            return self

        def __exit__(self, *a: object) -> None:
            return None

    def faux_urlopen(requete: urllib.request.Request, timeout: float = 0) -> FausseReponse:
        captures.append(requete)
        return FausseReponse()

    monkeypatch.setattr(sweep.urllib.request, "urlopen", faux_urlopen)

    assert envoyer("cve", [{"depot": "org/a", "elements": ["x"]}], 82) is True

    requete = captures[0]
    charge = json.loads(requete.data)
    assert charge["type_rapport"] == "cve"
    assert charge["total_analyses"] == 82
    assert charge["depots"] == [{"depot": "org/a", "elements": ["x"]}]
    assert requete.headers["Authorization"] == "Bearer jeton"


def test_envoi_rate_fait_echouer_le_job(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Windmill configure mais injoignable : le rapport n'est arrive a personne.

    Terminer en succes rendrait cette perte invisible, alors que tout ce depot
    est construit sur l'idee qu'un canal silencieux est ambigu.
    """
    monkeypatch.setenv("WINDMILL_WEBHOOK_URL", "https://windmill.example/w/1")
    monkeypatch.setenv("WINDMILL_TOKEN", "jeton")

    def leve(*a: object, **k: object) -> None:
        raise urllib.error.URLError("injoignable")

    monkeypatch.setattr(sweep.urllib.request, "urlopen", leve)

    fichier = tmp_path / "resume.json"
    fichier.write_text(json.dumps({"depots": [], "total_analyses": 82}), encoding="utf-8")

    assert main(["envoyer", "--type-rapport", "cve", "--fichier", str(fichier)]) == 1
    assert "Rapport non envoye" in capsys.readouterr().out


def test_envoi_saute_faute_de_configuration_reste_un_succes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Sans secret Windmill le balayage tourne quand meme ; ce n'est pas une panne."""
    fichier = tmp_path / "resume.json"
    fichier.write_text(json.dumps({"depots": [], "total_analyses": 82}), encoding="utf-8")
    assert main(["envoyer", "--type-rapport", "licences", "--fichier", str(fichier)]) == 0
    assert "::error" not in capsys.readouterr().out


def test_envoi_reussi_termine_en_succes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WINDMILL_WEBHOOK_URL", "https://windmill.example/w/1")
    monkeypatch.setenv("WINDMILL_TOKEN", "jeton")
    monkeypatch.setattr(sweep, "envoyer", lambda *a: True)

    fichier = tmp_path / "resume.json"
    fichier.write_text(json.dumps({"depots": [], "total_analyses": 82}), encoding="utf-8")
    assert main(["envoyer", "--type-rapport", "cve", "--fichier", str(fichier)]) == 0


@pytest.mark.parametrize(
    ("url", "token", "attendu"),
    [
        ("https://w.example", "jeton", True),
        ("", "jeton", False),
        ("https://w.example", "", False),
        ("   ", "jeton", False),
    ],
)
def test_configuration_exige_les_deux_valeurs(
    monkeypatch: pytest.MonkeyPatch, url: str, token: str, attendu: bool
) -> None:
    monkeypatch.setenv("WINDMILL_WEBHOOK_URL", url)
    monkeypatch.setenv("WINDMILL_TOKEN", token)
    assert windmill_configure() is attendu
