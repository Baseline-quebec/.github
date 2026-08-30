"""Tests du vocabulaire de sévérité et du seuil de blocage partagés."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

import pytest
from politique import (
    CRITIQUE,
    ELEVEE,
    FAIBLE,
    INCONNUE,
    MOYENNE,
    Politique,
    normaliser_severite,
    severite_depuis_score,
)


@dataclass(frozen=True)
class Faux:
    """Le minimum qu'une politique a besoin de savoir d'un constat."""

    outil: str
    regle: str
    severite: str


@pytest.mark.parametrize(
    ("score", "attendu"),
    [
        (10.0, CRITIQUE),
        ("9.0", CRITIQUE),
        (8.9, ELEVEE),
        ("7.0", ELEVEE),
        (6.9, MOYENNE),
        ("4.0", MOYENNE),
        (3.9, FAIBLE),
        ("0.1", FAIBLE),
    ],
)
def test_seuils_cvss_suivent_la_grille_first(score: object, attendu: str) -> None:
    assert severite_depuis_score(score) == attendu


def test_score_absent_ou_nul_reste_inconnu() -> None:
    """Un zéro CVSS veut dire « pas de score », pas « faille bénigne »."""
    assert severite_depuis_score(0) == INCONNUE
    assert severite_depuis_score(None) == INCONNUE
    assert severite_depuis_score("") == INCONNUE
    assert severite_depuis_score("élevée") == INCONNUE


def test_vocabulaire_inconnu_nest_pas_rabaisse() -> None:
    assert normaliser_severite("apocalyptique") == INCONNUE
    assert normaliser_severite(None) == INCONNUE


def test_seuil_par_defaut_exclut_inconnue() -> None:
    """Le defaut du module doit valoir la politique reelle, pas s'en approcher.

    Ce contrat etait jusqu'ici verifie uniquement par les suites en aval : le
    module partage pouvait donc changer de defaut sans qu'aucun de ses propres
    tests ne bronche.
    """
    politique = Politique()
    assert politique.bloquantes == {CRITIQUE, ELEVEE}
    bloquants, autres = politique.trier([Faux("x", "y", INCONNUE)])
    assert bloquants == []
    assert len(autres) == 1


def test_exemption_echue_cesse_de_couvrir(tmp_path: Path) -> None:
    """La date d'expiration est le mecanisme, pas une decoration.

    Sans elle, une exemption prise un mardi pour debloquer une livraison
    devient une politique permanente que plus personne ne relit.
    """
    fichier = tmp_path / "politique.yaml"
    fichier.write_text(
        "bloquantes: [CRITIQUE]\n"
        "exemptions:\n"
        "  - regle: 'B1'\n"
        "    justification: x\n"
        "    expire: 2026-12-31\n",
        encoding="utf-8",
    )
    politique = Politique.charger(fichier)
    constat = Faux("bandit", "B1", CRITIQUE)

    avant, _ = politique.trier([constat], aujourdhui=dt.date(2026, 12, 31))
    jour_apres, _ = politique.trier([constat], aujourdhui=dt.date(2027, 1, 1))

    assert avant == [], "l'exemption couvre encore le jour de son echeance"
    assert len(jour_apres) == 1, "l'exemption echue doit redevenir bloquante"


def test_motif_dexemption_est_ancre_sur_tout_lidentifiant(tmp_path: Path) -> None:
    """`B1` ne doit pas exempter `B10` : une exemption trop large est invisible."""
    fichier = tmp_path / "politique.yaml"
    fichier.write_text(
        "bloquantes: [CRITIQUE]\n"
        "exemptions:\n"
        "  - regle: 'B1'\n"
        "    justification: x\n"
        "    expire: 2099-01-01\n",
        encoding="utf-8",
    )
    politique = Politique.charger(fichier)
    bloquants, _ = politique.trier(
        [Faux("bandit", "B10", CRITIQUE)], aujourdhui=dt.date(2026, 9, 1)
    )
    assert len(bloquants) == 1


def test_politique_vide_bloque_encore_le_critique(tmp_path: Path) -> None:
    """Un fichier tronqué ne doit pas se traduire par « tout passe »."""
    fichier = tmp_path / "politique.yaml"
    fichier.write_text("bloquantes: []\n", encoding="utf-8")
    politique = Politique.charger(fichier)
    bloquants, _ = politique.trier([Faux("x", "y", CRITIQUE)])
    assert len(bloquants) == 1


def test_politique_absente_de_champs_ne_casse_pas(tmp_path: Path) -> None:
    fichier = tmp_path / "politique.yaml"
    fichier.write_text("# rien\n", encoding="utf-8")
    politique = Politique.charger(fichier)
    assert politique.bloquantes == {CRITIQUE}
    assert politique.exemptions == []


def test_exemption_sans_regle_est_ignoree(tmp_path: Path) -> None:
    """Une entrée mal formée ne doit pas exempter silencieusement tout le monde."""
    fichier = tmp_path / "politique.yaml"
    fichier.write_text(
        "bloquantes: [CRITIQUE]\nexemptions:\n  - justification: oubli de regle\n",
        encoding="utf-8",
    )
    politique = Politique.charger(fichier)
    assert politique.exemptions == []
    bloquants, _ = politique.trier([Faux("x", "y", CRITIQUE)])
    assert len(bloquants) == 1


def test_exemption_sans_date_ne_expire_jamais_mais_reste_visible(tmp_path: Path) -> None:
    """Le chargeur l'accepte ; c'est le test de chaque politique qui l'interdit.

    Séparer les deux permet à une politique de dépanner en urgence sans que le
    mécanisme mente, tout en gardant l'interdiction visible dans la CI.
    """
    fichier = tmp_path / "politique.yaml"
    fichier.write_text(
        "bloquantes: [CRITIQUE]\nexemptions:\n  - regle: 'B1'\n    justification: x\n",
        encoding="utf-8",
    )
    politique = Politique.charger(fichier)
    assert politique.exemptions[0].expire is None
    bloquants, _ = politique.trier([Faux("x", "B1", CRITIQUE)], aujourdhui=dt.date(2099, 1, 1))
    assert bloquants == []


def test_exemption_generique_couvre_tous_les_outils(tmp_path: Path) -> None:
    fichier = tmp_path / "politique.yaml"
    fichier.write_text(
        "bloquantes: [CRITIQUE]\n"
        "exemptions:\n"
        "  - regle: 'B1'\n"
        "    justification: x\n"
        "    expire: 2099-01-01\n",
        encoding="utf-8",
    )
    politique = Politique.charger(fichier)
    bloquants, _ = politique.trier(
        [Faux("bandit", "B1", CRITIQUE), Faux("semgrep", "B1", CRITIQUE)],
        aujourdhui=dt.date(2026, 9, 1),
    )
    assert bloquants == []
