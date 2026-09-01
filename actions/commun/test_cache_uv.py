"""Aucun `setup-uv` ne fait dependre sa cle de cache du depot scanne.

Meme famille de defaut que test_version_python.py, et meme cause : reunir les
quatre scans dans un SEUL job fait que chaque etape herite de ce que la
precedente a laisse sur le disque.

Constate le 2026-09-01 sur la pull request 477 de sfppn-maintenance-assistee.
L'etape « Auditer le code » a pris 448 secondes, dont **306,9 dans setup-uv**,
soit 68 %. Les six scanners reunis, semgrep, checkov, trivy, gitleaks, bandit et
hadolint, ne coutent que 141 secondes.

Le log montre ou part le temps. Par defaut, setup-uv cherche `**/pyproject.toml`,
`**/uv.lock`, `**/*requirements*.txt` et quatre autres motifs pour construire sa
cle :

    21:58:24  .../apps/backend/pyproject.toml
    21:58:24  .../apps/backend/uv.lock
    22:03:31  .../pyproject.toml
    22:03:31  Found 3 files to hash.
    22:03:31  No GitHub Actions cache found for key: setup-uv-2-x86_64-...

Cinq minutes entre le deuxieme et le troisieme fichier : l'etape precedente, le
scan de licences, venait d'installer les dependances Node, et le `**` a traverse
tout node_modules pour trouver trois fichiers. En jobs separes, secaudit-code
avait son propre runner et le probleme ne pouvait pas exister.

La derniere ligne est la vraie condamnation. Ces actions installent des versions
EPINGLEES avec `uv run --no-project --with semgrep==1.175.0`, donc une cle
derivee des verrous du depot scanne change a chaque bump de dependance de ce
depot et ne touche presque jamais. Cinq minutes de parcours pour un cache vide.

D'ou cette garde : une action qui n'installe que des outils epingles doit
declarer `cache-dependency-glob: ""`. La cle cesse alors de dependre du depot
scanne, donc les roues des outils epingles se reutilisent vraiment.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

RACINE = Path(__file__).resolve().parent.parent.parent

# Une action qui synchronise l'environnement du depot scanne (`uv sync`,
# `uv pip install`) a BESOIN d'une cle qui suive les verrous de ce depot : la
# cle par defaut y est correcte. licence-scan est dans ce cas.
SYNCHRONISE_LE_DEPOT = re.compile(r"uv (sync|pip install)")


def manifestes() -> list[Path]:
    return sorted(RACINE.glob("actions/*/action.yml"))


def etapes_setup_uv(manifeste: Path) -> list[dict]:
    contenu = yaml.safe_load(manifeste.read_text(encoding="utf-8"))
    etapes = ((contenu or {}).get("runs") or {}).get("steps") or []
    return [e for e in etapes if "setup-uv" in str(e.get("uses", ""))]


@pytest.mark.parametrize("manifeste", manifestes(), ids=lambda p: p.parent.name)
def test_le_cache_uv_ne_parcourt_pas_le_depot_scanne(manifeste: Path) -> None:
    texte = manifeste.read_text(encoding="utf-8")
    if SYNCHRONISE_LE_DEPOT.search(texte):
        pytest.skip(
            f"{manifeste.parent.name} synchronise l'environnement du depot scanne, "
            "sa cle doit suivre les verrous de ce depot"
        )

    for etape in etapes_setup_uv(manifeste):
        avec = etape.get("with") or {}
        assert "cache-dependency-glob" in avec, (
            f"{manifeste.relative_to(RACINE)} laisse setup-uv chercher "
            "`**/pyproject.toml` et six autres motifs dans le depot scanne. "
            "Cela a coute 306,9 s sur un monorepo avec node_modules, pour une cle "
            'qui ne touche jamais. Declarer `cache-dependency-glob: ""`.'
        )
        assert avec["cache-dependency-glob"] in ("", None), (
            f"{manifeste.relative_to(RACINE)} declare "
            f"cache-dependency-glob: {avec['cache-dependency-glob']!r}. Cette action "
            "n'installe que des outils epingles, donc la cle ne doit dependre "
            "d'aucun fichier du depot scanne."
        )


def test_au_moins_une_action_est_effectivement_gardee() -> None:
    """Sans ce garde, renommer setup-uv rendrait le test ci-dessus vide et vert."""
    gardees = [
        m.parent.name
        for m in manifestes()
        if etapes_setup_uv(m) and not SYNCHRONISE_LE_DEPOT.search(m.read_text(encoding="utf-8"))
    ]
    assert gardees, "aucune action n'appelle plus setup-uv : la garde ne verifie plus rien"
