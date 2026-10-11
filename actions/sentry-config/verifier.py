"""Vérifie que chaque initialisation de Sentry du dépôt porte le masquage imposé.

Décision du Directeur général du 2026-10-10 : Sentry est conservé à condition
que le masquage soit imposé dans tous les dépôts (NORM-TI-DEV-01, section 9).
L'organisation Sentry est aux États-Unis et reçoit les erreurs des applications
de clients ; une erreur emporte ce que le code avait en main quand il a échoué.

Ce qui échoue :

- Python : un appel `sentry_sdk.init(...)` qui ne passe pas EXPLICITEMENT
  `send_default_pii=False`, `include_local_variables=False` et un
  `before_send` autre que `None`. « Explicitement » est voulu : le défaut du
  SDK pour `include_local_variables` est `True`, c'est la fuite principale et
  elle est automatique. Un `**options` est suivi s'il désigne un dict littéral
  ou une fonction du même fichier qui en rend un.
- JS/TS : un `Sentry.init(...)` (ou un `init` importé de `@sentry/*`, ou
  `sentryCloudflareNitroPlugin(...)`) dont les options ne portent pas
  `sendDefaultPii: false` et un `beforeSend`, sauf si elles viennent de
  `baselineSentryOptions(...)`, la configuration de référence du gabarit
  `project-bootstrap-template`.

Ce que le vérificateur ne sait pas lire est un constat « non vérifiable », pas
un succès : un contrôle qui passe au vert faute de comprendre le code est un
contrôle qui ne contrôle rien. Les tests sont exclus : un client sans DSN ou à
transport de capture n'envoie rien.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "commun"))

from politique import ELEVEE, Politique

# Dossiers jamais lus : dépendances installées, sorties de build, tests. Le scan
# de licences installe node_modules AVANT cette étape dans le job de conformité,
# donc les élaguer n'est pas une optimisation, c'est ce qui garde l'étape courte.
DOSSIERS_IGNORES: Final = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "site-packages",
        "dist",
        "build",
        ".nuxt",
        ".output",
        ".next",
        ".svelte-kit",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "coverage",
        "vendor",
        "tests",
        "test",
        "__tests__",
        "e2e",
    }
)

EXTENSIONS_JS: Final = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".vue")

# Au-delà, c'est un fichier généré ou un bundle, pas du code qu'on écrit.
TAILLE_MAX: Final = 1_000_000

TEST_PY: Final = re.compile(r"^(test_.*|.*_test|conftest)\.py$")
TEST_JS: Final = re.compile(r"\.(test|spec)\.[cm]?[jt]sx?$")

# Nom de la fonction de référence du gabarit, côté JS. Ses options portent le
# masquage par construction, et le fichier qui la définit est vérifié à part.
REFERENCE_JS: Final = "baselineSentryOptions"


@dataclass(frozen=True)
class Constat:
    """Une initialisation de Sentry qui ne porte pas le masquage imposé."""

    depot: str
    chemin: str
    ligne: int
    code: str
    message: str

    @property
    def outil(self) -> str:
        """Toujours « sentry » : la politique partagée trie par outil."""
        return "sentry"

    @property
    def regle(self) -> str:
        """Ce qu'une exemption vise : le dépôt et le fichier, pas la ligne.

        Une ligne bouge à chaque modification du fichier ; une exemption ancrée
        sur elle cesserait de s'appliquer au premier commit sans que personne
        ne l'ait décidé.
        """
        return f"{self.depot}:{self.chemin}"

    @property
    def severite(self) -> str:
        """Un masquage absent bloque toujours : il n'y a pas de demi-fuite."""
        return ELEVEE


# --- Découverte des fichiers ---------------------------------------------------


def est_python(nom: str) -> bool:
    """Un fichier Python, ou un gabarit Jinja qui en produit un."""
    return nom.endswith(".py") or (nom.endswith(".jinja") and ".py" in nom)


def fichiers_candidats(racine: Path) -> list[Path]:
    """Les fichiers de code applicatif qui mentionnent Sentry."""
    trouves: list[Path] = []
    for dossier, sous_dossiers, fichiers in os.walk(racine):
        sous_dossiers[:] = sorted(d for d in sous_dossiers if d not in DOSSIERS_IGNORES)
        for nom in sorted(fichiers):
            if TEST_PY.match(nom) or TEST_JS.search(nom) or nom.endswith(".min.js"):
                continue
            if not (est_python(nom) or nom.endswith(EXTENSIONS_JS)):
                continue
            chemin = Path(dossier) / nom
            try:
                if chemin.stat().st_size > TAILLE_MAX:
                    continue
                texte = chemin.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "sentry" in texte.lower():
                trouves.append(chemin)
    return trouves


# --- Python ----------------------------------------------------------------------

EXIGENCES_PY: Final = ("send_default_pii", "include_local_variables", "before_send")


@dataclass(frozen=True)
class Reglages:
    """Les mots-clés d'un appel à init, tels qu'on a pu les lire."""

    valeurs: dict[str, ast.expr]
    opaque: bool  # un ** qu'on n'a pas su suivre


def _cles_dict(noeud: ast.expr) -> dict[str, ast.expr] | None:
    """Les clés d'un dict littéral ou d'un appel dict(...), None sinon."""
    if isinstance(noeud, ast.Dict):
        cles: dict[str, ast.expr] = {}
        for cle, valeur in zip(noeud.keys, noeud.values, strict=True):
            if cle is None:  # {**autre} : on ne suit pas plus loin
                return None
            if isinstance(cle, ast.Constant) and isinstance(cle.value, str):
                cles[cle.value] = valeur
        return cles
    if isinstance(noeud, ast.Call) and isinstance(noeud.func, ast.Name) and noeud.func.id == "dict":
        if noeud.args or any(k.arg is None for k in noeud.keywords):
            return None
        return {k.arg: k.value for k in noeud.keywords if k.arg is not None}
    return None


def _resoudre_deballage(noeud: ast.expr, module: ast.Module) -> dict[str, ast.expr] | None:
    """Suit un `**x` vers un dict littéral du même fichier.

    Deux formes suffisent au parc : `**nom` d'une variable affectée d'un dict
    littéral, et `**fabrique(...)` d'une fonction du module qui rend un dict
    littéral (baseline-automation). Une fonction qui rend des dicts différents
    selon la branche ne compte que les clés communes à tous ses `return` : un
    réglage présent dans une branche seulement est absent dans l'autre.
    """
    direct = _cles_dict(noeud)
    if direct is not None:
        return direct
    if isinstance(noeud, ast.Name):
        for instruction in ast.walk(module):
            if isinstance(instruction, ast.Assign) and any(
                isinstance(cible, ast.Name) and cible.id == noeud.id
                for cible in instruction.targets
            ):
                return _cles_dict(instruction.value)
            if (
                isinstance(instruction, ast.AnnAssign)
                and isinstance(instruction.target, ast.Name)
                and instruction.target.id == noeud.id
                and instruction.value is not None
            ):
                return _cles_dict(instruction.value)
        return None
    if isinstance(noeud, ast.Call) and isinstance(noeud.func, ast.Name):
        nom = noeud.func.id
        for fonction in ast.walk(module):
            if (
                isinstance(fonction, ast.FunctionDef | ast.AsyncFunctionDef)
                and fonction.name == nom
            ):
                retours = [
                    r.value for r in ast.walk(fonction) if isinstance(r, ast.Return) and r.value
                ]
                lus = [_cles_dict(r) for r in retours]
                if not lus or any(cles is None for cles in lus):
                    return None
                communes = set.intersection(*(set(cles) for cles in lus if cles is not None))
                premier = lus[0] or {}
                return {cle: premier[cle] for cle in communes}
    return None


def _reglages(appel: ast.Call, module: ast.Module) -> Reglages:
    valeurs: dict[str, ast.expr] = {}
    opaque = False
    for mot in appel.keywords:
        if mot.arg is not None:
            valeurs[mot.arg] = mot.value
            continue
        resolu = _resoudre_deballage(mot.value, module)
        if resolu is None:
            opaque = True
        else:
            valeurs.update(resolu)
    return Reglages(valeurs=valeurs, opaque=opaque)


def _noms_init(module: ast.Module) -> tuple[set[str], set[str]]:
    """Les alias du module sentry_sdk, et les noms locaux de sentry_sdk.init."""
    modules: set[str] = set()
    fonctions: set[str] = set()
    for noeud in ast.walk(module):
        if isinstance(noeud, ast.Import):
            for alias in noeud.names:
                if alias.name == "sentry_sdk":
                    modules.add(alias.asname or "sentry_sdk")
        elif isinstance(noeud, ast.ImportFrom) and noeud.module == "sentry_sdk":
            for alias in noeud.names:
                if alias.name == "init":
                    fonctions.add(alias.asname or "init")
    return modules, fonctions


def _est_init(appel: ast.Call, modules: set[str], fonctions: set[str]) -> bool:
    cible = appel.func
    if isinstance(cible, ast.Attribute) and cible.attr == "init":
        return isinstance(cible.value, ast.Name) and cible.value.id in modules
    return isinstance(cible, ast.Name) and cible.id in fonctions


def _est_faux(noeud: ast.expr) -> bool:
    return isinstance(noeud, ast.Constant) and noeud.value is False


def _juger_python(reglages: Reglages) -> list[tuple[str, str]]:
    """Les manquements d'un appel, en (code, message)."""
    manques: list[tuple[str, str]] = []
    valeurs = reglages.valeurs
    absents = [cle for cle in EXIGENCES_PY if cle not in valeurs]
    if absents and reglages.opaque:
        return [
            (
                "non-verifiable",
                f"sentry_sdk.init reçoit un **options que le vérificateur ne sait pas suivre, "
                f"et {', '.join(absents)} n'y est pas passé explicitement",
            )
        ]
    for cle in ("send_default_pii", "include_local_variables"):
        if cle not in valeurs:
            defaut = " (défaut du SDK : True)" if cle == "include_local_variables" else ""
            manques.append((f"{cle}-absent", f"{cle}=False n'est pas passé explicitement{defaut}"))
        elif not _est_faux(valeurs[cle]):
            texte = ast.unparse(valeurs[cle])
            manques.append(
                (f"{cle}-actif", f"{cle}={texte} : la valeur doit être False, littéralement")
            )
    before_send = valeurs.get("before_send")
    if before_send is None:
        manques.append(("before_send-absent", "aucun before_send : rien n'expurge l'événement"))
    elif isinstance(before_send, ast.Constant) and before_send.value is None:
        manques.append(("before_send-absent", "before_send=None : rien n'expurge l'événement"))
    return manques


# Repli textuel pour ce que `ast` ne lit pas : gabarits Jinja, fichiers invalides.
_INIT_PY_TEXTE: Final = re.compile(r"\bsentry_sdk\.init\s*\(")
_FAUX_PY: Final = {
    "send_default_pii": re.compile(
        r"\bsend_default_pii\s*=\s*False\b|[\"']send_default_pii[\"']\s*:\s*False\b"
    ),
    "include_local_variables": re.compile(
        r"\binclude_local_variables\s*=\s*False\b|[\"']include_local_variables[\"']\s*:\s*False\b"
    ),
}
_PRESENT_PY: Final = {
    "send_default_pii": re.compile(r"\bsend_default_pii\s*[=:]|[\"']send_default_pii[\"']"),
    "include_local_variables": re.compile(
        r"\binclude_local_variables\s*[=:]|[\"']include_local_variables[\"']"
    ),
}
_BEFORE_SEND_PY: Final = re.compile(
    r"\bbefore_send\s*=\s*(?!None\b)[\w(]|[\"']before_send[\"']\s*:\s*(?!None\b)[\w(]"
)


def _sans_commentaires_py(texte: str) -> str:
    return "\n".join(re.sub(r"(^|\s)#.*$", r"\1", ligne) for ligne in texte.splitlines())


def _juger_texte_python(arguments: str) -> list[tuple[str, str]]:
    manques: list[tuple[str, str]] = []
    for cle in ("send_default_pii", "include_local_variables"):
        if _FAUX_PY[cle].search(arguments):
            continue
        if _PRESENT_PY[cle].search(arguments):
            manques.append((f"{cle}-actif", f"{cle} n'y vaut pas False, littéralement"))
        elif "**" in arguments:
            return [
                ("non-verifiable", f"**options non suivi, et {cle} n'est pas passé explicitement")
            ]
        else:
            manques.append((f"{cle}-absent", f"{cle}=False n'est pas passé explicitement"))
    if not _BEFORE_SEND_PY.search(arguments):
        manques.append(("before_send-absent", "aucun before_send : rien n'expurge l'événement"))
    return manques


def verifier_python(texte: str, jinja: bool = False) -> list[tuple[int, str, str]]:
    """Les manquements des appels à sentry_sdk.init d'un source Python.

    Returns:
        Une liste de (ligne, code, message), vide si tout est conforme.
    """
    if not jinja:
        try:
            module = ast.parse(texte)
        except SyntaxError:
            module = None
        if module is not None:
            modules, fonctions = _noms_init(module)
            constats: list[tuple[int, str, str]] = []
            for noeud in ast.walk(module):
                if isinstance(noeud, ast.Call) and _est_init(noeud, modules, fonctions):
                    reglages = _reglages(noeud, module)
                    constats += [(noeud.lineno, c, m) for c, m in _juger_python(reglages)]
            return sorted(constats, key=lambda constat: constat[0])

    propre = _sans_commentaires_py(texte)
    constats = []
    for trouve in _INIT_PY_TEXTE.finditer(propre):
        arguments = _arguments(propre, trouve.end() - 1)
        ligne = propre.count("\n", 0, trouve.start()) + 1
        constats += [(ligne, c, m) for c, m in _juger_texte_python(arguments)]
    return constats


# --- JavaScript et TypeScript -------------------------------------------------


def sans_commentaires_js(texte: str) -> str:
    """Retire les commentaires en gardant les chaînes et les sauts de ligne.

    Les sauts de ligne sont conservés pour que les numéros de ligne des constats
    restent ceux du fichier. Les chaînes sont parcourues pour qu'une URL
    `https://...` ne soit pas prise pour un commentaire.
    """
    sortie: list[str] = []
    i, n = 0, len(texte)
    while i < n:
        c = texte[i]
        if c in "\"'`":
            j = i + 1
            while j < n and texte[j] != c:
                j += 2 if texte[j] == "\\" else 1
            sortie.append(texte[i : j + 1])
            i = j + 1
        elif texte.startswith("//", i):
            j = texte.find("\n", i)
            i = n if j < 0 else j
        elif texte.startswith("/*", i):
            j = texte.find("*/", i + 2)
            fin = n if j < 0 else j + 2
            sortie.append("\n" * texte.count("\n", i, fin))
            i = fin
        else:
            sortie.append(c)
            i += 1
    return "".join(sortie)


def _arguments(texte: str, ouvrante: int) -> str:
    """Le texte entre la parenthèse `ouvrante` et sa fermante."""
    profondeur = 0
    i = ouvrante
    while i < len(texte):
        c = texte[i]
        if c in "\"'`":
            j = i + 1
            while j < len(texte) and texte[j] != c:
                j += 2 if texte[j] == "\\" else 1
            i = j + 1
            continue
        if c in "([{":
            profondeur += 1
        elif c in ")]}":
            profondeur -= 1
            if profondeur == 0:
                return texte[ouvrante + 1 : i]
        i += 1
    return texte[ouvrante + 1 :]


def _premier_argument(arguments: str) -> str:
    """Le premier argument d'une liste, à la première virgule de niveau zéro."""
    profondeur = 0
    for i, c in enumerate(arguments):
        if c in "([{":
            profondeur += 1
        elif c in ")]}":
            profondeur -= 1
        elif c == "," and profondeur == 0:
            return arguments[:i].strip()
    return arguments.strip()


_SOURCE_SENTRY: Final = r"""['"]@sentry/[\w/-]+['"]"""
_NAMESPACE: Final = (
    re.compile(rf"import\s+\*\s+as\s+([\w$]+)\s+from\s+{_SOURCE_SENTRY}"),
    re.compile(
        rf"(?:const|let|var)\s+([\w$]+)\s*=\s*(?:await\s+)?import\s*\(\s*{_SOURCE_SENTRY}\s*\)"
    ),
    re.compile(rf"(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*{_SOURCE_SENTRY}\s*\)"),
)
_NOMMES: Final = re.compile(rf"import\s*(?:type\s+)?\{{([^}}]*)\}}\s*from\s*{_SOURCE_SENTRY}")
# Enveloppes qui prennent les options du SDK en premier argument, sans s'appeler init.
_ENVELOPPES: Final = ("sentryCloudflareNitroPlugin", "withSentry")

_PII_VRAI_JS: Final = re.compile(r"\bsendDefaultPii\s*:\s*true\b")
_PII_FAUX_JS: Final = re.compile(r"\bsendDefaultPii\s*:\s*false\b")
# `beforeSend: null` ou `undefined` ne compte pas, comme `before_send=None` en
# Python : rien n'expurge l'événement.
_BEFORE_SEND_JS: Final = re.compile(
    r"\bbeforeSend\s*(?::(?!\s*(?:null|undefined)\b)|\(|(?=\s*[,}]))"
)


def _appels_init_js(texte: str) -> list[int]:
    """Positions des parenthèses ouvrantes des appels d'initialisation."""
    espaces = {m.group(1) for motif in _NAMESPACE for m in motif.finditer(texte)}
    fonctions: set[str] = set()
    for bloc in _NOMMES.finditer(texte):
        for element in bloc.group(1).split(","):
            morceaux = element.strip().split(" as ")
            if morceaux[0].strip() == "init":
                fonctions.add(morceaux[-1].strip())
    fonctions.update(_ENVELOPPES)
    positions: list[int] = []
    for espace in espaces:
        motif = re.compile(rf"(?<![\w$.]){re.escape(espace)}\s*\.\s*(?:init|withSentry)\s*\(")
        positions += [m.end() - 1 for m in motif.finditer(texte)]
    for fonction in fonctions:
        motif = re.compile(rf"(?<![\w$.]){re.escape(fonction)}\s*\(")
        positions += [m.end() - 1 for m in motif.finditer(texte)]
    return sorted(set(positions))


def _corps_js(nom: str, texte: str) -> str | None:
    """Le corps d'une fonction ou la valeur d'une constante nommée `nom`."""
    motifs = (
        re.compile(rf"function\s+{re.escape(nom)}\s*(?:<[^>]*>)?\s*\("),
        re.compile(rf"(?:const|let|var)\s+{re.escape(nom)}\s*(?::[^=]+)?=\s*"),
    )
    for motif in motifs:
        trouve = motif.search(texte)
        if trouve is None:
            continue
        debut = trouve.end()
        accolade = texte.find("{", debut)
        if accolade < 0:
            return None
        if motif is motifs[0]:
            parenthese = trouve.end() - 1
            fin_parametres = parenthese + len(_arguments(texte, parenthese)) + 1
            accolade = texte.find("{", fin_parametres)
        return "{" + _arguments(texte, accolade) + "}"
    return None


def _import_local(nom: str, texte: str, fichier: Path) -> Path | None:
    """Le fichier d'où `nom` est importé, s'il est relatif et trouvable."""
    motif = re.compile(r"import\s*\{([^}]*)\}\s*from\s*['\"](\.{1,2}/[^'\"]+)['\"]")
    for bloc in motif.finditer(texte):
        noms = [e.strip().split(" as ")[-1].strip() for e in bloc.group(1).split(",")]
        if nom not in noms:
            continue
        base = (fichier.parent / bloc.group(2)).resolve()
        candidats = [
            base,
            *(base.with_name(base.name + ext) for ext in (".ts", ".js", ".mts", ".mjs")),
        ]
        candidats += [base / f"index{ext}" for ext in (".ts", ".js")]
        for candidat in candidats:
            if candidat.is_file():
                return candidat
    return None


def _juger_options_js(
    options: str, texte: str, fichier: Path | None, profondeur: int = 0
) -> list[tuple[str, str]]:
    """Juge le texte des options passées au SDK, en suivant un nom au besoin."""
    if _PII_VRAI_JS.search(options):
        return [("sendDefaultPii-actif", "sendDefaultPii: true")]
    if REFERENCE_JS in options:
        return []
    options = options.strip()
    # () => ({...}) ou () => nom(...) : on juge ce que la fonction rend.
    fleche = re.match(r"^(?:async\s*)?(?:\([^)]*\)|[\w$]+)\s*=>\s*", options)
    if fleche:
        options = options[fleche.end() :].strip()
        if options.startswith("(") and options.endswith(")"):
            options = options[1:-1].strip()
    if not options.startswith("{"):
        nom = re.match(r"^(?:await\s+)?([\w$]+)", options)
        if nom is None or profondeur >= 2:
            return [("non-verifiable", "options que le vérificateur ne sait pas lire")]
        corps = _corps_js(nom.group(1), texte)
        cible_texte, cible = texte, fichier
        if corps is None and fichier is not None:
            importe = _import_local(nom.group(1), texte, fichier)
            if importe is not None:
                cible_texte = sans_commentaires_js(
                    importe.read_text(encoding="utf-8", errors="replace")
                )
                cible = importe
                corps = _corps_js(nom.group(1), cible_texte)
        if corps is None:
            return [
                (
                    "non-verifiable",
                    f"options construites par {nom.group(1)}, introuvable dans le dépôt",
                )
            ]
        return _juger_options_js(corps, cible_texte, cible, profondeur + 1)
    manques: list[tuple[str, str]] = []
    if not _PII_FAUX_JS.search(options):
        manques.append(
            ("sendDefaultPii-absent", "sendDefaultPii: false n'est pas passé explicitement")
        )
    if not _BEFORE_SEND_JS.search(options):
        manques.append(("beforeSend-absent", "aucun beforeSend : rien n'expurge l'événement"))
    return manques


def verifier_js(texte: str, fichier: Path | None = None) -> list[tuple[int, str, str]]:
    """Les manquements des initialisations de Sentry d'un source JS ou TS.

    Returns:
        Une liste de (ligne, code, message), vide si tout est conforme.
    """
    propre = sans_commentaires_js(texte)
    constats: list[tuple[int, str, str]] = []
    for position in _appels_init_js(propre):
        options = _premier_argument(_arguments(propre, position))
        ligne = propre.count("\n", 0, position) + 1
        constats += [(ligne, c, m) for c, m in _juger_options_js(options, propre, fichier)]
    return constats


# --- Rapport -------------------------------------------------------------------


def analyser(racine: Path, depot: str) -> list[Constat]:
    """Tous les constats du dépôt, dans l'ordre des fichiers."""
    constats: list[Constat] = []
    for fichier in fichiers_candidats(racine):
        texte = fichier.read_text(encoding="utf-8", errors="replace")
        relatif = fichier.relative_to(racine).as_posix()
        if est_python(fichier.name):
            trouves = verifier_python(texte, jinja=fichier.name.endswith(".jinja"))
        else:
            trouves = verifier_js(texte, fichier)
        constats += [
            Constat(depot, relatif, ligne, code, message) for ligne, code, message in trouves
        ]
    return constats


def resumer(bloquants: list[Constat], exemptes: list[Constat]) -> str:
    """Le résumé Markdown du job."""
    lignes = ["## Configuration Sentry", ""]
    if not bloquants and not exemptes:
        lignes.append("Aucune initialisation de Sentry sans masquage.")
        return "\n".join(lignes) + "\n"
    if bloquants:
        lignes += [
            f"{len(bloquants)} initialisation(s) de Sentry sans le masquage imposé "
            "(NORM-TI-DEV-01, section 9).",
            "",
            "| Fichier | Ligne | Manquement |",
            "|---|---|---|",
        ]
        lignes += [f"| `{c.chemin}` | {c.ligne} | {c.message} |" for c in bloquants]
        lignes += [
            "",
            "Remède : la configuration de référence du gabarit `project-bootstrap-template`, "
            "`observability/sentry/` et `docs/sentry.md`.",
        ]
    if exemptes:
        lignes += [
            "",
            f"{len(exemptes)} constat(s) couvert(s) par une exemption de politique.yaml.",
        ]
    return "\n".join(lignes) + "\n"


def ecrire_sortie(nom: str, valeur: str) -> None:
    """Écrit une sortie d'étape GitHub, si le fichier existe."""
    chemin = os.environ.get("GITHUB_OUTPUT")
    if chemin:
        with Path(chemin).open("a", encoding="utf-8") as sortie:
            sortie.write(f"{nom}={valeur}\n")


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée de l'action."""
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("--racine", type=Path, default=Path())
    analyseur.add_argument("--politique", type=Path, required=True)
    analyseur.add_argument("--depot", default=os.environ.get("GITHUB_REPOSITORY", "local"))
    analyseur.add_argument("--sans-blocage", action="store_true")
    arguments = analyseur.parse_args(argv)

    # Une racine absente n'est pas un dépôt sans Sentry : le contrôle passerait
    # au vert sans avoir rien lu.
    if not arguments.racine.is_dir():
        print(f"::error title=Configuration Sentry::racine introuvable : {arguments.racine}")
        return 1

    constats = analyser(arguments.racine, arguments.depot)
    politique = Politique.charger(arguments.politique)
    bloquants, exemptes = politique.trier(constats)

    resume = resumer(bloquants, exemptes)
    print(resume)
    fichier_resume = os.environ.get("GITHUB_STEP_SUMMARY")
    if fichier_resume:
        with Path(fichier_resume).open("a", encoding="utf-8") as sortie:
            sortie.write(resume)

    ecrire_sortie("bloquants", str(len(bloquants)))
    for constat in bloquants:
        print(
            f"::error file={constat.chemin},line={constat.ligne},title=Sentry sans masquage::"
            f"{constat.message} (NORM-TI-DEV-01 ; voir docs/sentry.md du gabarit "
            "project-bootstrap-template)"
        )

    if bloquants and not arguments.sans_blocage:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
