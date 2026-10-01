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


@pytest.mark.parametrize("licence", ["AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"])
def test_agpl_bloque(politique: Politique, licence: str) -> None:
    """L'AGPL est bloquante chez Baseline, pas seulement signalée.

    Elle contamine dès qu'un service est exposé, ce qui est le cas de la
    plupart des livraisons. Cas concret ayant motivé la règle : PyMuPDF, dont
    l'usage commercial est interdit sans licence payante, à remplacer par
    pypdfium2.
    """
    assert verdict_de(politique, "pymupdf", licence) is Verdict.INTERDITE


def test_gpl_nest_pas_capture_par_le_motif_agpl(politique: Politique) -> None:
    """Les motifs sont ancrés : « AGPL-3.0 » ne doit pas matcher « GPL-3.0 ».

    Sans ancrage, rendre l'AGPL bloquante bloquerait aussi tout le GPL, qui
    reste un arbitrage humain selon le mode de livraison.
    """
    assert verdict_de(politique, "paquet", "GPL-3.0") is Verdict.A_SURVEILLER


def test_boost_nest_pas_confondu_avec_business_source(politique: Politique) -> None:
    """BSL-1.0 est la Boost Software License, permissive.

    BSL-1.1 est un alias courant de la Business Source License, restrictive.
    Une regex non ancrée sur la version confondrait les deux et bloquerait
    à tort tous les paquets Boost.
    """
    assert verdict_de(politique, "boost", "BSL-1.0") is Verdict.ACCEPTEE
    assert verdict_de(politique, "hashicorp", "BSL-1.1") is Verdict.INTERDITE


@pytest.mark.parametrize("licence", ["GPL-2.0", "GPL-3.0-or-later", "EUPL-1.2", "CC-BY-SA-4.0"])
def test_copyleft_signale_sans_bloquer(politique: Politique, licence: str) -> None:
    assert verdict_de(politique, "paquet", licence) is Verdict.A_SURVEILLER


@pytest.mark.parametrize("licence", ["LGPL-2.1", "LGPL-3.0-only", "LGPL-3.0-or-later"])
def test_lgpl_est_acceptee(politique: Politique, licence: str) -> None:
    """Importer une bibliothèque LGPL non modifiée est conforme, même livré."""
    assert verdict_de(politique, "psycopg", licence) is Verdict.ACCEPTEE


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


def verdicts_de(politique: Politique, licence: str) -> list[tuple[str, Verdict]]:
    constats = analyser(rapport_trivy({"paquet": licence}), politique)
    return [(c.licence, c.verdict) for c in constats]


def test_or_est_un_choix_et_retient_la_branche_favorable(politique: Politique) -> None:
    """Cas réel de node-forge : BSD-3-Clause ou GPL-2.0, au choix du licencié.

    Le signaler en GPL, comme le rapport du 2026-10-01 dans trois dépôts,
    revient à ignorer qu'on l'utilise sous BSD.
    """
    assert verdicts_de(politique, "(BSD-3-Clause OR GPL-2.0)") == [
        ("BSD-3-Clause", Verdict.ACCEPTEE)
    ]


def test_or_de_pyphen_tel_quextrait_passe(politique: Politique) -> None:
    licence = "GPL-2.0-or-later OR LGPL-2.0-or-later OR Mozilla Public License 1.1 (MPL 1.1)"
    assert {v for _, v in verdicts_de(politique, licence)} == {Verdict.ACCEPTEE}


def test_parenthese_apres_un_terme_fait_partie_du_nom(politique: Politique) -> None:
    """« GNU General Public License v3 (GPLv3) » n'est pas un groupe à évaluer."""
    licence = "GNU General Public License v3 (GPLv3) OR BUSL-1.1"
    assert verdicts_de(politique, licence) == [("GPL-3.0", Verdict.A_SURVEILLER)]


def test_and_impose_toutes_les_branches(politique: Politique) -> None:
    assert ("GPL-3.0", Verdict.A_SURVEILLER) in verdicts_de(politique, "MIT AND GPL-3.0")


def test_or_entre_interdite_et_copyleft_retient_le_copyleft(politique: Politique) -> None:
    assert verdicts_de(politique, "BUSL-1.1 OR GPL-3.0") == [("GPL-3.0", Verdict.A_SURVEILLER)]


def test_or_entre_deux_interdites_reste_bloquant(politique: Politique) -> None:
    verdicts = {v for _, v in verdicts_de(politique, "BUSL-1.1 OR SSPL-1.0")}
    assert verdicts == {Verdict.INTERDITE}


def test_and_lie_plus_fort_que_or(politique: Politique) -> None:
    """Précédence SPDX : « A OR B AND C » se lit « A OR (B AND C) »."""
    assert verdicts_de(politique, "MIT OR GPL-3.0 AND BUSL-1.1") == [("MIT", Verdict.ACCEPTEE)]
    verdicts = verdicts_de(politique, "(MIT OR GPL-3.0) AND BUSL-1.1")
    assert ("BUSL-1.1", Verdict.INTERDITE) in verdicts


def test_or_minuscule_du_texte_libre_nest_pas_un_choix(politique: Politique) -> None:
    """« GPLv2 or later » est un nom : en faire un choix laisserait passer « later »."""
    verdicts = {v for _, v in verdicts_de(politique, "GPLv2 or later")}
    assert Verdict.A_SURVEILLER in verdicts


def test_with_garde_la_licence_de_base(politique: Politique) -> None:
    assert verdicts_de(politique, "GPL-2.0-only WITH Classpath-exception-2.0") == [
        ("GPL-2.0-only", Verdict.A_SURVEILLER)
    ]


def test_expression_mal_formee_retombe_sur_tous_les_termes(politique: Politique) -> None:
    """En cas de doute, on signale : une parenthèse orpheline ne fait rien taire."""
    verdicts = {v for _, v in verdicts_de(politique, "(MIT OR GPL-3.0")}
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
