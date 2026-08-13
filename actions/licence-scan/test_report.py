"""Tests de la classification des licences.

Les cas couverts sont ceux où une erreur coûte cher : une licence interdite
classée acceptable (faux négatif silencieux, le pire), et une licence permissive
classée interdite (blocage injustifié qui fait perdre confiance dans l'outil).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from report import Politique, Verdict, analyser, est_inconnue, normaliser, rediger

POLITIQUE = Path(__file__).parent / "politique.yaml"


@pytest.fixture
def politique() -> Politique:
    return Politique.charger(POLITIQUE)


def rapport_trivy(paquets: dict[str, str]) -> dict[str, object]:
    return {
        "Results": [
            {
                "Target": "Python",
                "Class": "license",
                "Licenses": [{"PkgName": nom, "Name": lic} for nom, lic in paquets.items()],
            }
        ]
    }


def verdict_de(politique: Politique, paquet: str, licence: str) -> Verdict:
    constats = analyser(rapport_trivy({paquet: licence}), politique)
    assert len(constats) == 1
    return constats[0].verdict


@pytest.mark.parametrize(
    "licence",
    [
        "CC-BY-NC-4.0",
        "CC-BY-NC-SA-3.0",
        "PolyForm-Noncommercial-1.0.0",
        "Commons-Clause",
        "BUSL-1.1",
        "SSPL-1.0",
        "Elastic-2.0",
        "RSAL-2.0",
        "JSON",
        "Prosperity-3.0",
    ],
)
def test_licences_non_commerciales_bloquent(politique: Politique, licence: str) -> None:
    assert verdict_de(politique, "paquet", licence) is Verdict.INTERDITE


@pytest.mark.parametrize(
    "licence", ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "MPL-2.0", "CC0-1.0", "CC-BY-4.0"]
)
def test_licences_permissives_passent(politique: Politique, licence: str) -> None:
    assert verdict_de(politique, "paquet", licence) is Verdict.ACCEPTEE


def test_boost_nest_pas_confondu_avec_business_source(politique: Politique) -> None:
    """BSL-1.0 est la Boost Software License, permissive.

    BSL-1.1 est un alias courant de la Business Source License, restrictive.
    Une regex non ancrée sur la version confondrait les deux et bloquerait
    à tort tous les paquets Boost.
    """
    assert verdict_de(politique, "boost", "BSL-1.0") is Verdict.ACCEPTEE
    assert verdict_de(politique, "hashicorp", "BSL-1.1") is Verdict.INTERDITE


@pytest.mark.parametrize(
    "licence", ["AGPL-3.0", "GPL-2.0", "GPL-3.0-or-later", "LGPL-2.1", "EUPL-1.2", "CC-BY-SA-4.0"]
)
def test_copyleft_signale_sans_bloquer(politique: Politique, licence: str) -> None:
    assert verdict_de(politique, "paquet", licence) is Verdict.A_SURVEILLER


@pytest.mark.parametrize(
    ("brut", "attendu"),
    [
        ("GNU General Public License v3 (GPLv3)", "GPL-3.0"),
        ("GNU Affero General Public License v3", "AGPL-3.0"),
        ("GNU Lesser General Public License v2 (LGPLv2)", "LGPL-2.1"),
        ("Business Source License 1.1", "BUSL-1.1"),
        ("Server Side Public License", "SSPL-1.0"),
        ("Elastic License 2.0", "Elastic-2.0"),
        ("Apache Software License", "Apache-2.0"),
        ("MIT License", "MIT"),
    ],
)
def test_metadonnees_en_texte_libre_sont_normalisees(brut: str, attendu: str) -> None:
    """PEP 639 est récent : beaucoup de paquets PyPI déclarent encore leur
    licence en texte libre. Sans normalisation, ces valeurs échapperaient à
    tous les motifs et seraient classées « inconnue » au lieu d'être bloquées.
    """
    assert normaliser(brut) == [attendu]


def test_expression_composee_evaluee_terme_par_terme(politique: Politique) -> None:
    """Un paquet double-licencié MIT ou GPL doit remonter le terme GPL.

    Le choix du terme applicable est une décision humaine. L'outil signale le
    terme le plus contraignant plutôt que de trancher seul.
    """
    assert normaliser("(MIT OR GPL-3.0)") == ["MIT", "GPL-3.0"]
    constats = analyser(rapport_trivy({"dual": "(MIT OR GPL-3.0)"}), politique)
    verdicts = {c.verdict for c in constats}
    assert Verdict.A_SURVEILLER in verdicts


@pytest.mark.parametrize("marqueur", ["", "UNKNOWN", "none", "Other/Proprietary License"])
def test_licence_absente_est_detectee(marqueur: str) -> None:
    assert est_inconnue(marqueur)


def test_mode_licence_inconnue_est_respecte(tmp_path: Path) -> None:
    base = yaml.safe_load(POLITIQUE.read_text(encoding="utf-8"))

    for mode, attendu in [
        ("signaler", Verdict.INCONNUE),
        ("bloquer", Verdict.INTERDITE),
        ("taire", Verdict.ACCEPTEE),
    ]:
        base["licence_inconnue"] = mode
        chemin = tmp_path / f"politique-{mode}.yaml"
        chemin.write_text(yaml.safe_dump(base), encoding="utf-8")
        politique = Politique.charger(chemin)
        assert verdict_de(politique, "mystere", "UNKNOWN") is attendu


def test_mode_licence_inconnue_invalide_est_refuse(tmp_path: Path) -> None:
    chemin = tmp_path / "politique.yaml"
    chemin.write_text(yaml.safe_dump({"licence_inconnue": "peut-etre"}), encoding="utf-8")
    with pytest.raises(ValueError, match="licence_inconnue"):
        Politique.charger(chemin)


def test_exception_leve_le_blocage(tmp_path: Path) -> None:
    base = yaml.safe_load(POLITIQUE.read_text(encoding="utf-8"))
    base["exceptions"] = [
        {"paquet": "fancy-lib", "licence": "CC-BY-NC-4.0", "raison": "Usage interne seulement"}
    ]
    chemin = tmp_path / "politique.yaml"
    chemin.write_text(yaml.safe_dump(base), encoding="utf-8")
    politique = Politique.charger(chemin)

    assert verdict_de(politique, "fancy-lib", "CC-BY-NC-4.0") is Verdict.EXEMPTEE
    # L'exception est nominative : un autre paquet sous la même licence bloque.
    assert verdict_de(politique, "autre-lib", "CC-BY-NC-4.0") is Verdict.INTERDITE


def test_interdite_prime_sur_ignoree(tmp_path: Path) -> None:
    """Une licence présente dans les deux listes est une erreur de politique.

    Le comportement sûr est de bloquer : une politique mal configurée ne doit
    jamais produire un résultat vert silencieux.
    """
    base = yaml.safe_load(POLITIQUE.read_text(encoding="utf-8"))
    base["ignorees"]["motifs"].append("BUSL-1\\.1")
    chemin = tmp_path / "politique.yaml"
    chemin.write_text(yaml.safe_dump(base), encoding="utf-8")
    politique = Politique.charger(chemin)

    assert verdict_de(politique, "hashicorp", "BUSL-1.1") is Verdict.INTERDITE


def test_rapport_vide_explique_la_cause_probable(politique: Politique) -> None:
    """Zéro dépendance analysée est le mode d'échec le plus dangereux.

    Sans installation, Trivy ne trouve aucun fichier METADATA et retourne un
    résultat vide, qui ressemble à un succès. Le rapport doit dire pourquoi.
    """
    markdown = rediger([], "Baseline-quebec/vide")
    assert "Aucune dépendance analysée" in markdown
    assert "METADATA" in markdown


def test_rapport_liste_les_paquets_bloquants(politique: Politique) -> None:
    constats = analyser(
        rapport_trivy({"fancy-lib": "CC-BY-NC-4.0", "requests": "Apache-2.0"}), politique
    )
    markdown = rediger(constats, "Baseline-quebec/test")
    assert "fancy-lib" in markdown
    assert "Bloquant" in markdown
