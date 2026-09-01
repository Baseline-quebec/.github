"""Fige les invariants de coût et de câblage de l'action de build docker.

Ces tests ne portent pas sur du Python mais sur du YAML, comme ceux de
`actions/sweep` : les défauts qu'ils figent ne sont pas dans du code, ils sont
dans ce qui est ou n'est pas passé à `docker/build-push-action`.

Les trois viennent de bugs réels, mesurés sur août 2026 dans les deux copies
que cette action remplace.

QEMU. `docker/setup-qemu-action` ne sert qu'à la construction croisée. Les deux
copies l'installaient inconditionnellement alors qu'aucun appelant ne demandait
plusieurs architectures : de 30 à 60 secondes par job, sur des centaines de
jobs docker par mois. Retirer le `if:` remettrait ce coût sans qu'aucun build
n'échoue, donc sans que personne ne le voie.

CACHE. Ne rien exporter sur les pull requests semblait économiser les 300
secondes d'écriture de `mode=max`. Le cache GHA étant cloisonné par branche,
cela faisait au contraire repartir chaque push de presque zéro : sur août, le
job `prod` de sfppn-maintenance-assistee (branche par défaut, cache chaud) met
5 minutes là où `dev` et `staging` (pull request, cache froid) en mettent 13 à
14, pour le même contexte de build et le même commit.

ENTRÉES MORTES. La copie de mpa-data-bridge déclarait une entrée
`docker-target` que l'étape de build ne lisait pas : les appelants passaient
`docker-target: ingestion-api` et obtenaient le dernier étage du Dockerfile.
Une entrée déclarée qui n'est lue nulle part est un mensonge silencieux sur ce
que l'action fait, et c'est la classe de bug la plus facile à réintroduire.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

ACTION = Path(__file__).resolve().parent / "action.yml"

# Entrées volontairement absentes du corps : elles pilotent le `if:` ou la
# valeur d'une autre entrée, et sont donc lues ailleurs que dans un `with:`.
# Aucune pour l'instant ; la liste existe pour que l'exception soit nommée le
# jour où il en faut une, plutôt que le test affaibli.
ENTREES_SANS_USAGE_DIRECT: set[str] = set()


def charger() -> dict[str, Any]:
    contenu = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    assert isinstance(contenu, dict), "action.yml ne se lit pas comme un objet YAML"
    return contenu


def etapes() -> list[dict[str, Any]]:
    return charger()["runs"]["steps"]


def etape_nommee(fragment: str) -> dict[str, Any]:
    for etape in etapes():
        if fragment.lower() in str(etape.get("uses", "")).lower():
            return etape
    pytest.fail(f"aucune étape n'utilise {fragment}")


def test_qemu_ne_s_installe_que_pour_du_multi_architecture():
    """Sans ce `if:`, de 30 à 60 secondes par job docker, pour rien."""
    qemu = etape_nommee("setup-qemu-action")
    condition = qemu.get("if")
    assert condition, (
        "setup-qemu-action sans `if:` : QEMU s'installe sur tous les builds, "
        "y compris mono-architecture, où il ne sert à rien"
    )
    assert "platforms" in condition, (
        f"la condition de QEMU ({condition!r}) ne regarde pas `platforms` : "
        "elle ne peut donc pas dire si une construction croisée est demandée"
    )


def test_le_cache_s_exporte_dans_les_deux_branches_du_ternaire():
    """Un `cache-to` vide fait repartir chaque push de presque zéro."""
    build = etape_nommee("build-push-action")
    cache_to = str(build["with"]["cache-to"])
    assert "mode=max" in cache_to, "la branche cache-export == 'true' doit exporter en mode=max"
    assert "mode=min" in cache_to, (
        "la branche par défaut doit exporter en mode=min, pas rien : le cache GHA "
        "est cloisonné par branche, donc une pull request qui n'exporte pas "
        "reconstruit tout à chaque push"
    )
    assert "|| ''" not in cache_to and '|| ""' not in cache_to, (
        f"cache-to ({cache_to!r}) retombe sur la chaîne vide, donc sur aucun cache"
    )
    assert "cache-from" in build["with"], "sans cache-from, l'export ne sert à rien"


def test_le_build_lit_le_contexte_et_l_etage_demandes():
    """`target` doit agir, contrairement au `docker-target` de mpa-data-bridge."""
    build = etape_nommee("build-push-action")["with"]
    for entree in ("context", "target", "platforms"):
        assert f"inputs.{entree}" in str(build.get(entree, "")), (
            f"l'étape de build ne lit pas `inputs.{entree}` : l'entrée est déclarée "
            "mais ignorée, exactement le bug de docker-target dans mpa-data-bridge"
        )


def test_aucune_entree_declaree_n_est_morte():
    """Une entrée jamais lue est un mensonge sur ce que l'action fait."""
    contenu = charger()
    corps = yaml.dump(contenu["runs"], allow_unicode=True)
    mortes = sorted(
        nom
        for nom in contenu["inputs"]
        if nom not in ENTREES_SANS_USAGE_DIRECT and f"inputs.{nom}" not in corps
    )
    assert not mortes, (
        f"entrées déclarées et jamais lues dans runs: {mortes}. "
        "Soit les câbler, soit les retirer, soit les nommer dans "
        "ENTREES_SANS_USAGE_DIRECT en disant pourquoi"
    )


def test_l_image_est_construite_une_seule_fois():
    """Plusieurs étapes de build, c'est la même image payée deux fois."""
    builds = [e for e in etapes() if "build-push-action" in str(e.get("uses", ""))]
    assert len(builds) == 1, (
        f"{len(builds)} étapes de build : pousser vers plusieurs registres se fait "
        "en listant les étiquettes dans `docker-images`, pas en reconstruisant"
    )
