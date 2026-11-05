"""Tests de la définition partagée du ruleset de conformité.

Ce fichier est censé être la source de vérité du périmètre imposé à
l'organisation : ce qui est scanné, et ce qui ne l'est pas. Il a déjà dérivé du
ruleset réel une fois — `Marketing` et `Ventes` en étaient exclus en production
sans que le script les nomme, ce qui aurait fait reconstruire un périmètre plus
large que le vrai après un incident.

Les tests portent donc sur la forme exacte de la charge utile envoyée à GitHub,
pas sur des détails de style : une clé mal nommée est acceptée en silence par
l'API, qui ignore ce qu'elle ne connaît pas.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

COMMUN = Path(__file__).parent / "ruleset-commun.sh"
SCRIPTS = Path(__file__).parent
RACINE = SCRIPTS.parent


def appeler(fonction: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Source le fichier commun et rend le JSON produit par une de ses fonctions."""
    resultat = subprocess.run(
        ["bash", "-c", f'source "{COMMUN}" && {fonction}'],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return json.loads(resultat.stdout)


def variable(nom: str) -> list[str]:
    """Rend le contenu d'un tableau bash déclaré dans le fichier commun."""
    resultat = subprocess.run(
        ["bash", "-c", f'source "{COMMUN}" && printf "%s\\n" "${{{nom}[@]}}"'],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return [ligne for ligne in resultat.stdout.splitlines() if ligne]


# --------------------------------------------------------------------------
# Périmètre
# --------------------------------------------------------------------------


def test_exclusions_connues_sont_declarees() -> None:
    """Le périmètre déclaré doit être celui du ruleset réel.

    tracking-llm-discontinued porte le registre des modèles dépréciés : le
    scanner y produirait une issue par modèle, 182 en une exécution. Marketing
    et Ventes sont des dépôts de travail, essentiellement du HTML de sites et
    de présentations. bswh-baylee et serko-northsky sont hors maintenance
    Baseline depuis le 2026-09-01 : personne n'y traite les checks imposés sur
    les pull requests. baseline-automation et baseline-tresorier sont exclus du
    ruleset réel. cogniflo gère sa propre conformité (INTERNE67-2430).
    """
    assert set(variable("EXCLUS")) == {
        "tracking-llm-discontinued",
        "Marketing",
        "Ventes",
        "bswh-baylee",
        "serko-northsky",
        "baseline-automation",
        "baseline-tresorier",
        "cogniflo",
    }
    assert len(variable("EXCLUS")) == 8


def test_un_seul_ruleset_aux_noms_exacts() -> None:
    """Le nom sert de clef de recherche a maj et activer : un renommage
    silencieux ferait croire que le ruleset n'existe pas."""
    assert appeler("charge_ruleset")["name"] == "Conformité Baseline"


def test_le_ruleset_vise_la_branche_par_defaut_et_develop() -> None:
    """Le 2026-11-05, la restriction a la branche par defaut a ete annulee le
    meme jour pour ne pas impacter les autres depots (INTERNE67-2430). Jamais
    `~ALL` : la regle « Require workflows » bloque les pushs directs sur les
    branches ciblees (doc GitHub)."""
    assert sorted(variable("BRANCHES")) == ["refs/heads/develop", "~DEFAULT_BRANCH"]
    include = appeler("conditions_ruleset")["ref_name"]["include"]
    assert sorted(include) == ["refs/heads/develop", "~DEFAULT_BRANCH"]
    assert "~ALL" not in include


def test_la_creation_de_branche_n_est_pas_bloquee() -> None:
    """`do_not_enforce_on_create` : valide pour la regle `workflows` de l'API."""
    regle = appeler("regles_workflows")[0]
    assert regle["parameters"]["do_not_enforce_on_create"] is True


def test_le_ruleset_couvre_tous_les_depots_sauf_les_exclusions() -> None:
    conditions = appeler("conditions_ruleset")
    assert conditions["repository_name"]["include"] == ["~ALL"]
    assert sorted(conditions["repository_name"]["exclude"]) == sorted(variable("EXCLUS"))


def test_chaque_branche_declaree_arrive_dans_les_conditions() -> None:
    """Meme garde que pour EXCLUS : une branche nommee dans BRANCHES et absente
    des conditions ferait croire un scan actif la ou il n'y en a pas."""
    conditions = appeler("conditions_ruleset")
    assert sorted(conditions["ref_name"]["include"]) == sorted(variable("BRANCHES"))


def test_plus_aucune_trace_de_secrets_baseline() -> None:
    """Decision du 2026-11-05 : « Secrets Baseline » est retire (les secrets sont
    arretes au pre-commit)."""
    assert not (RACINE / ".github/workflows/secrets.yml").exists()
    contenu = COMMUN.read_text(encoding="utf-8")
    assert "Secrets Baseline" not in contenu
    assert "WORKFLOWS_SECRETS" not in contenu
    assert "BRANCHES_SECRETS" not in contenu


# --------------------------------------------------------------------------
# Workflow imposé
# --------------------------------------------------------------------------


def test_le_workflow_impose_est_conformite_et_lui_seul() -> None:
    """Un job : conformite.yml porte les controles complets."""
    regles = appeler("regles_workflows")
    chemins = [w["path"] for w in regles[0]["parameters"]["workflows"]]
    assert chemins == [".github/workflows/conformite.yml"]


def test_les_quatre_controles_sont_toujours_la() -> None:
    """La garde qui comptait quatre FICHIERS compte maintenant quatre ETAPES.

    Reunir les jobs devait faire economiser des minutes, pas perdre un
    controle en chemin. C'est ici, dans les etapes du workflow impose, que se
    lit ce qui est reellement execute.
    """
    impose = variable("WORKFLOWS")[0]
    contenu = (RACINE / impose).read_text(encoding="utf-8")

    attendus = {
        "CVE des dependances": "actions/cve-scan@",
        "modeles LLM deprecies": "tracking-llm-discontinued@",
        "licences": "actions/licence-scan@",
        "securite du code": "actions/secaudit-code@",
    }
    for nom, action in attendus.items():
        assert action in contenu, f"le controle « {nom} » n'est plus execute par {impose}"


def test_chaque_etape_rend_son_verdict_meme_apres_un_echec() -> None:
    """Sans `if: always()`, le premier echec masque les autres verdicts.

    Et sans etape de verdict final, le job prendrait la couleur de sa DERNIERE
    etape : un echec en cours de route passerait alors inapercu.
    """
    contenu = (RACINE / variable("WORKFLOWS")[0]).read_text(encoding="utf-8")
    assert contenu.count("if: always()") >= 5, (
        "chaque etape de scan, plus l'etape de verdict, doit porter `if: always()`"
    )
    assert "name: Verdict" in contenu, (
        "sans etape de verdict, le job prend la couleur de sa derniere etape"
    )


def test_chaque_workflow_impose_existe_dans_le_depot() -> None:
    """Un chemin fautif fait échouer le check sur toutes les PR de l'organisation.

    Le seul symptôme est un workflow « introuvable », sans indication du
    chemin attendu.
    """
    for chemin in variable("WORKFLOWS"):
        assert (RACINE / chemin).is_file(), f"{chemin} est imposé mais absent du dépôt"


def test_le_nom_du_check_est_celui_du_ruleset() -> None:
    """Le nom du workflow et celui de son unique job doivent rester ceux que le
    ruleset exige. Lu en texte : ce projet de tests n'a pas de lecteur YAML."""
    nom = "Conformité Baseline"
    contenu = (RACINE / variable("WORKFLOWS")[0]).read_text(encoding="utf-8")
    assert f"\nname: {nom}\n" in contenu
    assert f"\n    name: {nom}\n" in contenu
    assert contenu.count("\n    name: ") == 1


def test_regle_a_la_forme_attendue_par_lapi() -> None:
    """L'API ignore silencieusement les clés qu'elle ne connaît pas.

    Une faute de frappe sur `repository_id` ne produirait donc aucune erreur,
    seulement un ruleset qui n'impose rien.
    """
    regles = appeler("regles_workflows")
    assert len(regles) == 1
    assert regles[0]["type"] == "workflows"
    for workflow in regles[0]["parameters"]["workflows"]:
        assert set(workflow) == {"repository_id", "path", "ref"}
        assert isinstance(workflow["repository_id"], int)
        assert workflow["ref"] == "refs/tags/v2"


def test_toutes_les_regles_pointent_le_meme_depot_source() -> None:
    regles = appeler("regles_workflows")
    identifiants = {w["repository_id"] for w in regles[0]["parameters"]["workflows"]}
    assert len(identifiants) == 1


# --------------------------------------------------------------------------
# Charge utile de création
# --------------------------------------------------------------------------


def test_charge_de_creation_est_complete() -> None:
    charge = appeler("charge_ruleset")
    assert set(charge) == {"name", "target", "enforcement", "conditions", "rules"}
    assert charge["target"] == "branch"


@pytest.mark.parametrize("mode", ["evaluate", "active"])
def test_mode_dapplication_est_celui_demande(mode: str) -> None:
    assert appeler(f"charge_ruleset {mode}")["enforcement"] == mode


def test_creation_par_defaut_est_en_evaluate() -> None:
    """La création par défaut ne doit jamais activer un ruleset sans qu'on le veuille."""
    assert appeler("charge_ruleset")["enforcement"] == "evaluate"


def test_charge_de_creation_porte_le_meme_perimetre_que_les_conditions() -> None:
    """Création et mise à jour doivent parler du même périmètre.

    Deux définitions divergeraient au premier ajustement, et le ruleset
    reconstruit après un incident ne serait plus celui qu'on croyait.
    """
    charge = appeler("charge_ruleset")
    assert charge["conditions"] == appeler("conditions_ruleset")
    assert charge["rules"] == appeler("regles_workflows")


# --------------------------------------------------------------------------
# Scripts
# --------------------------------------------------------------------------

SCRIPTS_RULESET = ["creer-ruleset.sh", "maj-ruleset.sh", "activer-ruleset.sh"]


def lancer(
    script: str, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPTS / script), *args],
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
        timeout=60,
    )


def avec_faux_gh(tmp_path: Path, **env: str) -> dict[str, str]:
    faux = tmp_path / "bin"
    faux.mkdir()
    gh = faux / "gh"
    gh.write_text(FAUX_GH)
    gh.chmod(0o755)
    return {
        "PATH": f"{faux}:{os.environ['PATH']}",
        "FAKE_PUT": str(tmp_path / "put"),
        "FAKE_APPELE": str(tmp_path / "gh.appele"),
        **env,
    }


FAUX_GH = """#!/bin/bash
echo "$*" >> "$FAKE_APPELE"
case "$*" in
  *"contents/"*) exit 0 ;;
  "api orgs/Baseline-quebec/rulesets --paginate --jq"*) echo 42 ;;
  "api orgs/Baseline-quebec/rulesets/42") cat "$FAKE_VIVANT" ;;
  "api -X PUT"*) echo "$*" >> "$FAKE_PUT"; echo "{}" ;;
  *) echo "appel inattendu : $*" >&2; exit 9 ;;
esac
"""


def test_creer_a_blanc_affiche_la_charge_du_ruleset() -> None:
    resultat = lancer("creer-ruleset.sh", env={"DRY_RUN": "1"})
    assert resultat.returncode == 0, resultat.stderr
    assert json.loads(resultat.stdout) == appeler("charge_ruleset")


def test_creer_actif_a_la_demande() -> None:
    env = {"DRY_RUN": "1", "ENFORCEMENT": "active"}
    resultat = lancer("creer-ruleset.sh", env=env)
    assert json.loads(resultat.stdout)["enforcement"] == "active"


@pytest.mark.parametrize("argument", ["secrets", "conformite"])
@pytest.mark.parametrize("script", ["creer-ruleset.sh", "maj-ruleset.sh"])
def test_un_argument_inattendu_est_fatal_avant_tout_appel_gh(
    script: str, argument: str, tmp_path: Path
) -> None:
    """L'ancienne cle (`secrets`, `conformite`) ou une faute de frappe s'arrete
    avant tout `gh api`."""
    env = avec_faux_gh(tmp_path)
    resultat = lancer(script, argument, env=env)
    assert resultat.returncode == 2
    assert not (tmp_path / "gh.appele").exists(), "gh a ete appele"


def vivant_conformite(
    branches_vivantes: list[str] | None = None, exclus: list[str] | None = None
) -> dict[str, Any]:
    """Le ruleset tel que l'API le rendrait. Par defaut conforme a la
    declaration ; les arguments fabriquent une derive."""
    branches_vivantes = variable("BRANCHES") if branches_vivantes is None else branches_vivantes
    exclus = variable("EXCLUS") if exclus is None else exclus
    return {
        "id": 42,
        "conditions": {
            "ref_name": {"include": branches_vivantes, "exclude": []},
            "repository_name": {"include": ["~ALL"], "exclude": exclus},
        },
        "rules": appeler("regles_workflows"),
    }


def lancer_maj(
    tmp_path: Path, vivant: dict[str, Any], **env: str
) -> subprocess.CompletedProcess[str]:
    fichier = tmp_path / "vivant.json"
    fichier.write_text(json.dumps(vivant))
    return lancer(
        "maj-ruleset.sh",
        env=avec_faux_gh(tmp_path, FAKE_VIVANT=str(fichier), DRY_RUN="1", **env),
    )


def corps_du_put(resultat: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return json.loads(resultat.stdout[resultat.stdout.index("{") :])


def test_maj_ajoute_develop_sur_demande_et_garde_les_exclusions_vivantes(tmp_path: Path) -> None:
    exclus = [*variable("EXCLUS"), "depot-exclu-a-la-main"]
    vivant = vivant_conformite(["~DEFAULT_BRANCH"], exclus)
    resultat = lancer_maj(tmp_path, vivant, AVEC_CONDITIONS="1")
    assert resultat.returncode == 0, resultat.stderr
    corps = corps_du_put(resultat)
    assert sorted(corps["conditions"]["ref_name"]["include"]) == sorted(variable("BRANCHES"))
    # Les exclusions reelles survivent, meme celle que le depot ne declare pas.
    assert "depot-exclu-a-la-main" in corps["conditions"]["repository_name"]["exclude"]
    assert "enforcement" not in corps
    # Les regles sont deja conformes : elles ne sont pas renvoyees (un PUT de
    # `rules` remplace tout le tableau).
    assert "rules" not in corps


def test_maj_sans_drapeau_signale_la_derive_sans_rien_envoyer(tmp_path: Path) -> None:
    vivant = vivant_conformite(["~DEFAULT_BRANCH"])
    resultat = lancer_maj(tmp_path, vivant)
    assert resultat.returncode == 0, resultat.stderr
    assert "Derive de branches" in resultat.stdout
    assert "AVEC_CONDITIONS=1" in resultat.stdout
    assert "Rien a changer." in resultat.stdout


def test_maj_est_idempotente(tmp_path: Path) -> None:
    resultat = lancer_maj(tmp_path, vivant_conformite(), AVEC_CONDITIONS="1", AVEC_EXCLUSIONS="1")
    assert resultat.returncode == 0, resultat.stderr
    assert "Rien a changer." in resultat.stdout


ANCIENNES_EXCLUSIONS = [
    "tracking-llm-discontinued",
    "Marketing",
    "Ventes",
    "bswh-baylee",
    "serko-northsky",
    "baseline-automation",
    "baseline-tresorier",
]


def test_maj_n_ecrit_jamais_les_exclusions_par_defaut(tmp_path: Path) -> None:
    """Tant que cogniflo n'est pas exclu du ruleset reel, la derive est signalee
    (voulu), mais jamais ecrite sans AVEC_EXCLUSIONS=1."""
    vivant = vivant_conformite(exclus=ANCIENNES_EXCLUSIONS)
    resultat = lancer_maj(tmp_path, vivant, AVEC_CONDITIONS="1")
    assert resultat.returncode == 0, resultat.stderr
    assert "Derive de perimetre" in resultat.stdout
    assert "AVEC_EXCLUSIONS=1" in resultat.stdout
    assert "Rien a changer." in resultat.stdout


def test_maj_avec_exclusions_remplace_les_exclusions_par_exclus(tmp_path: Path) -> None:
    vivant = vivant_conformite(exclus=ANCIENNES_EXCLUSIONS)
    resultat = lancer_maj(tmp_path, vivant, AVEC_CONDITIONS="1", AVEC_EXCLUSIONS="1")
    assert resultat.returncode == 0, resultat.stderr
    corps = corps_du_put(resultat)
    exclues = corps["conditions"]["repository_name"]["exclude"]
    assert sorted(exclues) == sorted(variable("EXCLUS"))
    assert "cogniflo" in exclues
    # Rien d'autre ne change : branches vivantes, regles deja conformes, mode.
    assert sorted(corps["conditions"]["ref_name"]["include"]) == sorted(variable("BRANCHES"))
    assert corps["conditions"]["repository_name"]["include"] == ["~ALL"]
    assert "rules" not in corps
    assert "enforcement" not in corps


def test_maj_exclusions_a_blanc_n_appelle_pas_put(tmp_path: Path) -> None:
    vivant = vivant_conformite(exclus=ANCIENNES_EXCLUSIONS)
    resultat = lancer_maj(tmp_path, vivant, AVEC_CONDITIONS="1", AVEC_EXCLUSIONS="1")
    assert resultat.returncode == 0, resultat.stderr
    assert not (tmp_path / "put").exists()


def test_maj_exclusions_sans_conditions_est_fatal_avant_tout_appel_gh(tmp_path: Path) -> None:
    resultat = lancer_maj(tmp_path, vivant_conformite(), AVEC_EXCLUSIONS="1")
    assert resultat.returncode == 2
    assert "AVEC_CONDITIONS=1" in resultat.stderr
    assert not (tmp_path / "gh.appele").exists(), "gh a ete appele"


AUTRE_REGLE = {"type": "pull_request", "parameters": {"required_approving_review_count": 1}}


def test_maj_des_regles_conserve_les_autres_regles_et_parametres(tmp_path: Path) -> None:
    """Un PUT de `rules` remplace tout le tableau : les autres regles vivantes et
    les parametres inconnus de la regle `workflows` doivent survivre."""
    vivant = vivant_conformite()
    vieux = {"repository_id": 1, "path": ".github/workflows/vieux.yml", "ref": "x"}
    vivant["rules"] = [
        AUTRE_REGLE,
        {"type": "workflows", "parameters": {"workflows": [vieux], "parametre_inconnu": 7}},
    ]
    resultat = lancer_maj(tmp_path, vivant)
    assert resultat.returncode == 0, resultat.stderr
    corps = corps_du_put(resultat)
    assert "conditions" not in corps
    assert corps["rules"][0] == AUTRE_REGLE
    regle = corps["rules"][1]["parameters"]
    assert regle["parametre_inconnu"] == 7
    assert regle["do_not_enforce_on_create"] is True
    assert [w["path"] for w in regle["workflows"]] == variable("WORKFLOWS")


def test_maj_remet_do_not_enforce_on_create_perdu(tmp_path: Path) -> None:
    vivant = vivant_conformite()
    del vivant["rules"][0]["parameters"]["do_not_enforce_on_create"]
    vivant["rules"].append(AUTRE_REGLE)
    resultat = lancer_maj(tmp_path, vivant)
    assert resultat.returncode == 0, resultat.stderr
    corps = corps_du_put(resultat)
    assert corps["rules"][0]["parameters"]["do_not_enforce_on_create"] is True
    assert AUTRE_REGLE in corps["rules"]


def test_maj_ajoute_la_regle_workflows_si_elle_manquait(tmp_path: Path) -> None:
    vivant = vivant_conformite()
    vivant["rules"] = [AUTRE_REGLE]
    corps = corps_du_put(lancer_maj(tmp_path, vivant))
    assert corps["rules"][0] == AUTRE_REGLE
    assert corps["rules"][1]["type"] == "workflows"


def lancer_activer(tmp_path: Path, *args: str) -> tuple[subprocess.CompletedProcess[str], Path]:
    resultat = lancer("activer-ruleset.sh", *args, env=avec_faux_gh(tmp_path))
    return resultat, tmp_path / "put"


def test_activer_retour_arriere_en_disabled(tmp_path: Path) -> None:
    resultat, put = lancer_activer(tmp_path, "disabled")
    assert resultat.returncode == 0, resultat.stderr
    assert "enforcement=disabled" in put.read_text()


def test_activer_par_defaut_met_en_active(tmp_path: Path) -> None:
    resultat, put = lancer_activer(tmp_path)
    assert resultat.returncode == 0, resultat.stderr
    assert "enforcement=active" in put.read_text()


@pytest.mark.parametrize("args", [("bidon",), ("active", "secrets"), ("secrets",), ("conformite",)])
def test_activer_refuse_un_argument_inconnu_avant_tout_appel(
    tmp_path: Path, args: tuple[str, ...]
) -> None:
    resultat, put = lancer_activer(tmp_path, *args)
    assert resultat.returncode == 2
    assert not put.exists()
    assert not (tmp_path / "gh.appele").exists(), "gh a ete appele"


@pytest.mark.parametrize("script", SCRIPTS_RULESET)
def test_les_listes_de_rulesets_sont_paginees(script: str) -> None:
    """Au-dela de 30 rulesets, la premiere page ne montre pas tout : un ruleset
    existant paraitrait absent."""
    contenu = (SCRIPTS / script).read_text(encoding="utf-8")
    assert 'gh api "orgs/${ORG}/rulesets" --paginate' in contenu
