"""Tests de l'extraction des licences déclarées.

Les cas nommés proviennent de paquets réellement installés dans un dépôt
Baseline : ils figent des comportements observés, pas imaginés.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from extraire import (
    _lire_entetes,
    au_format_trivy,
    extraire_node,
    extraire_python,
    licence_depuis_entetes,
)


def ecrire_paquet_python(racine: Path, nom: str, version: str, metadata: str) -> None:
    dossier = (
        racine / ".venv" / "lib" / "python3.12" / "site-packages" / f"{nom}-{version}.dist-info"
    )
    dossier.mkdir(parents=True)
    (dossier / "METADATA").write_text(metadata, encoding="utf-8")


def ecrire_paquet_node(racine: Path, nom: str, contenu: dict[str, object]) -> None:
    dossier = racine / "node_modules" / nom
    dossier.mkdir(parents=True)
    (dossier / "package.json").write_text(json.dumps(contenu), encoding="utf-8")


def test_expression_pep639_prime_sur_le_champ_libre() -> None:
    """PEP 639 fournit une expression SPDX normalisée, donc fiable.

    Le champ License libre reste souvent une valeur héritée et périmée dans le
    même fichier, ce qui donnerait deux réponses contradictoires.
    """
    entetes = _lire_entetes("Name: exemple\nLicense-Expression: Apache-2.0\nLicense: BSD\n\ncorps")
    assert licence_depuis_entetes(entetes) == "Apache-2.0"


def test_champ_license_valant_unknown_bascule_sur_le_classifier() -> None:
    """Cas réel de ptyprocess 0.7.0.

    Le champ License vaut littéralement « UNKNOWN » alors que le classifier
    déclare ISC. Prendre le champ libre en premier produirait un faux
    « licence non déclarée » et du bruit dans le rapport.
    """
    entetes = _lire_entetes(
        "Name: ptyprocess\nLicense: UNKNOWN\n"
        "Classifier: License :: OSI Approved :: ISC License (ISCL)\n\ncorps"
    )
    assert licence_depuis_entetes(entetes) == "ISC"


def test_notice_de_copyright_nest_pas_une_licence() -> None:
    """Cas réel d'isodate 0.7.2.

    Le champ License contient une notice de copyright, qui n'indique en rien
    sous quelles conditions le paquet est distribué. Le remonter comme licence
    ferait passer une dépendance non déclarée pour une dépendance conforme.
    """
    entetes = _lire_entetes(
        "Name: isodate\nLicense: Copyright (c) 2021, Hugo van Kemenade and contributors\n\ncorps"
    )
    assert licence_depuis_entetes(entetes) == ""


def test_licence_absente_reste_absente() -> None:
    """Cas réel de cookiecutter 2.7.1 : uniquement des en-têtes License-File."""
    entetes = _lire_entetes("Name: cookiecutter\nLicense-File: LICENSE\n\ncorps")
    assert licence_depuis_entetes(entetes) == ""


def test_texte_de_licence_complet_nest_pas_pris_pour_un_nom() -> None:
    """Certains paquets collent le texte entier de leur licence dans le champ.

    Le remonter tel quel polluerait le rapport avec des kilo-octets et ne
    correspondrait à aucun motif de la politique.
    """
    texte = "Permission is hereby granted, free of charge, to any person obtaining a copy " * 5
    entetes = _lire_entetes(f"Name: verbeux\nLicense: {texte}\n\ncorps")
    assert licence_depuis_entetes(entetes) == ""


def test_classifier_dusage_restreint_est_remonte() -> None:
    """Une licence non commerciale ne peut se déclarer que par ce classifier.

    Il n'existe aucun identifiant SPDX pour « Free for non-commercial use »,
    donc sans cette correspondance le cas d'usage central du scan est manqué.
    """
    entetes = _lire_entetes(
        "Name: restreint\nClassifier: License :: Free for non-commercial use\n\ncorps"
    )
    assert licence_depuis_entetes(entetes) == "Non-Commercial"


def test_entetes_sarretent_a_la_premiere_ligne_vide() -> None:
    """La description longue suit les en-têtes et contient souvent le mot License.

    Sans cette coupure, un README mentionnant « License: MIT » ferait déclarer
    une licence à un paquet qui n'en déclare aucune.
    """
    entetes = _lire_entetes("Name: piege\n\nDescription longue\nLicense: MIT\n")
    assert licence_depuis_entetes(entetes) == ""


def test_seule_la_premiere_ligne_du_champ_compte() -> None:
    """Cas réel de tiktoken 0.13.0.

    Le champ License vaut « MIT License » puis embarque les vingt lignes du
    texte de la licence en continuation. Concaténer produirait un pavé qui ne
    correspond à aucun motif et ferait passer tiktoken pour non déclaré.
    """
    metadata = (
        "Name: tiktoken\n"
        "License: MIT License\n"
        "        \n"
        "        Copyright (c) 2022 OpenAI, Shantanu Jain\n"
        "        \n"
        "        Permission is hereby granted, free of charge, to any person.\n"
        "\n"
        "corps\n"
    )
    assert licence_depuis_entetes(_lire_entetes(metadata)) == "MIT License"


def test_ligne_dindentation_seule_ne_termine_pas_les_entetes() -> None:
    """Cas réel de numpy 1.26.4.

    Le texte complet de la BSD est collé dans le champ License, avec des
    paragraphes séparés par des lignes faites d'espaces. Les traiter comme une
    fin d'en-têtes fait manquer le classifier de licence situé bien plus bas, et
    numpy est alors rapporté comme dépendance sans licence déclarée.
    """
    metadata = (
        "Name: numpy\n"
        "License: Copyright (c) 2005-2023, NumPy Developers.\n"
        "        All rights reserved.\n"
        "        \n"
        "        Redistribution and use in source and binary forms are permitted.\n"
        "Classifier: License :: OSI Approved :: BSD License\n"
        "\n"
        "corps de la description\n"
    )
    assert licence_depuis_entetes(_lire_entetes(metadata)) == "BSD-3-Clause"


def test_extraction_python_lit_le_venv(tmp_path: Path) -> None:
    ecrire_paquet_python(tmp_path, "requests", "2.34.2", "Name: requests\nLicense: Apache-2.0\n\n")
    ecrire_paquet_python(
        tmp_path, "fancy", "1.0", "Name: fancy\nLicense-Expression: CC-BY-NC-4.0\n\n"
    )

    trouvailles = {t.paquet: t.licence for t in extraire_python(tmp_path)}
    assert trouvailles == {"requests": "Apache-2.0", "fancy": "CC-BY-NC-4.0"}


def test_extraction_node_lit_les_deux_formes(tmp_path: Path) -> None:
    """La forme historique `licenses` reste installée en dépendance transitive."""
    ecrire_paquet_node(tmp_path, "moderne", {"name": "moderne", "version": "1.0", "license": "MIT"})
    ecrire_paquet_node(
        tmp_path,
        "ancien",
        {"name": "ancien", "version": "0.1", "licenses": [{"type": "GPL-3.0"}]},
    )

    trouvailles = {t.paquet: t.licence for t in extraire_node(tmp_path)}
    assert trouvailles == {"moderne": "MIT", "ancien": "GPL-3.0"}


def test_package_json_interne_est_ignore(tmp_path: Path) -> None:
    """Un package.json dans src/ d'une dépendance n'est pas une dépendance.

    Le compter doublerait le décompte et attribuerait des licences fantômes.
    """
    ecrire_paquet_node(tmp_path, "paquet", {"name": "paquet", "version": "1.0", "license": "MIT"})
    interne = tmp_path / "node_modules" / "paquet" / "src"
    interne.mkdir()
    (interne / "package.json").write_text('{"name": "interne", "license": "GPL-3.0"}', "utf-8")

    assert [t.paquet for t in extraire_node(tmp_path)] == ["paquet"]


def test_paquet_scope_est_reconnu(tmp_path: Path) -> None:
    dossier = tmp_path / "node_modules" / "@baseline" / "outil"
    dossier.mkdir(parents=True)
    (dossier / "package.json").write_text(
        '{"name": "@baseline/outil", "version": "1.0", "license": "MIT"}', "utf-8"
    )

    assert [t.paquet for t in extraire_node(tmp_path)] == ["@baseline/outil"]


def test_metadata_illisible_ninterrompt_pas_le_scan(tmp_path: Path) -> None:
    """Un fichier corrompu ne doit pas faire échouer l'analyse des 237 autres."""
    ecrire_paquet_python(tmp_path, "sain", "1.0", "Name: sain\nLicense: MIT\n\n")
    casse = tmp_path / "node_modules" / "casse"
    casse.mkdir(parents=True)
    (casse / "package.json").write_text("{ceci n'est pas du json", encoding="utf-8")

    assert [t.paquet for t in extraire_python(tmp_path)] == ["sain"]
    assert extraire_node(tmp_path) == []


def test_format_de_sortie_est_consommable_par_report(tmp_path: Path) -> None:
    """La sortie doit rester dans la structure que report.py sait lire."""
    ecrire_paquet_python(tmp_path, "requests", "2.34.2", "Name: requests\nLicense: Apache-2.0\n\n")
    rapport = au_format_trivy(extraire_python(tmp_path))

    assert rapport["Results"][0]["Target"] == "Python"
    assert rapport["Results"][0]["Licenses"][0]["PkgName"] == "requests"
    assert rapport["Results"][0]["Licenses"][0]["Name"] == "Apache-2.0"


@pytest.mark.parametrize("remplissage", ["UNKNOWN", "none", "N/A", "unlicensed", "TODO"])
def test_valeurs_de_remplissage_sont_ignorees(remplissage: str) -> None:
    entetes = _lire_entetes(f"Name: exemple\nLicense: {remplissage}\n\ncorps")
    assert licence_depuis_entetes(entetes) == ""
