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
CLES = ("conformite", "secrets")


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
    les pull requests.
    """
    assert set(variable("EXCLUS")) == {
        "tracking-llm-discontinued",
        "Marketing",
        "Ventes",
        "bswh-baylee",
        "serko-northsky",
    }


def branches(cle: str) -> list[str]:
    return variable(f"BRANCHES_{cle.upper()}")


def workflows(cle: str) -> list[str]:
    return variable(f"WORKFLOWS_{cle.upper()}")


def test_deux_rulesets_aux_noms_exacts() -> None:
    """Les noms servent de clef de recherche a maj et activer : un renommage
    silencieux ferait croire qu'un ruleset n'existe pas."""
    assert appeler("charge_ruleset conformite")["name"] == "Conformité Baseline"
    assert appeler("charge_ruleset secrets")["name"] == "Secrets Baseline"


def test_le_ruleset_de_conformite_ne_vise_que_la_branche_par_defaut() -> None:
    """`develop` est couvert par « Secrets Baseline » : les controles complets
    ne sont plus rejoues a chaque pull request vers une branche d'integration."""
    assert branches("conformite") == ["~DEFAULT_BRANCH"]
    include = appeler("conditions_ruleset conformite")["ref_name"]["include"]
    assert include == ["~DEFAULT_BRANCH"]
    assert "refs/heads/develop" not in include


def test_le_ruleset_des_secrets_vise_develop_et_jamais_toutes_les_branches() -> None:
    """La regle « Require workflows » bloque les pushs directs sur les branches
    ciblees (doc GitHub) : sur `~ALL` elle bloquerait tout push de branche de
    feature, dependabot, « Update branch » et « Resolve conflicts »."""
    assert branches("secrets") == ["refs/heads/develop"]
    include = appeler("conditions_ruleset secrets")["ref_name"]["include"]
    assert include == ["refs/heads/develop"]
    assert "~ALL" not in include


@pytest.mark.parametrize("cle", CLES)
def test_la_creation_de_branche_n_est_pas_bloquee(cle: str) -> None:
    """`do_not_enforce_on_create` : valide pour la regle `workflows` de l'API."""
    regle = appeler(f"regles_workflows {cle}")[0]
    assert regle["parameters"]["do_not_enforce_on_create"] is True


@pytest.mark.parametrize("cle", CLES)
def test_les_deux_rulesets_couvrent_tous_les_depots_sauf_les_memes_exclusions(
    cle: str,
) -> None:
    conditions = appeler(f"conditions_ruleset {cle}")
    assert conditions["repository_name"]["include"] == ["~ALL"]
    assert sorted(conditions["repository_name"]["exclude"]) == sorted(variable("EXCLUS"))


@pytest.mark.parametrize("cle", CLES)
def test_chaque_branche_declaree_arrive_dans_les_conditions(cle: str) -> None:
    """Meme garde que pour EXCLUS : une branche nommee dans BRANCHES et absente
    des conditions ferait croire un scan actif la ou il n'y en a pas."""
    conditions = appeler(f"conditions_ruleset {cle}")
    assert sorted(conditions["ref_name"]["include"]) == sorted(branches(cle))


def test_une_cle_inconnue_est_une_erreur() -> None:
    resultat = subprocess.run(
        ["bash", "-c", f'source "{COMMUN}" && charge_ruleset inconnu'],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert resultat.returncode != 0
    assert "Ruleset inconnu" in resultat.stderr


# --------------------------------------------------------------------------
# Workflows imposés
# --------------------------------------------------------------------------


def chemins_imposes(cle: str) -> list[str]:
    regles = appeler(f"regles_workflows {cle}")
    return [w["path"] for w in regles[0]["parameters"]["workflows"]]


def test_chaque_ruleset_impose_son_workflow_et_lui_seul() -> None:
    """Un job par workflow : conformite.yml porte les controles complets,
    secrets.yml le scan des secrets seul."""
    assert chemins_imposes("conformite") == [".github/workflows/conformite.yml"]
    assert chemins_imposes("secrets") == [".github/workflows/secrets.yml"]


def test_les_quatre_controles_sont_toujours_la() -> None:
    """La garde qui comptait quatre FICHIERS compte maintenant quatre ETAPES.

    Reunir les jobs devait faire economiser des minutes, pas perdre un
    controle en chemin. C'est ici, dans les etapes du workflow impose, que se
    lit ce qui est reellement execute.
    """
    impose = workflows("conformite")[0]
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
    contenu = (RACINE / workflows("conformite")[0]).read_text(encoding="utf-8")
    assert contenu.count("if: always()") >= 5, (
        "chaque etape de scan, plus l'etape de verdict, doit porter `if: always()`"
    )
    assert "name: Verdict" in contenu, (
        "sans etape de verdict, le job prend la couleur de sa derniere etape"
    )


@pytest.mark.parametrize("cle", CLES)
def test_chaque_workflow_impose_existe_dans_le_depot(cle: str) -> None:
    """Un chemin fautif fait échouer le check sur toutes les PR de l'organisation.

    Le seul symptôme est un workflow « introuvable », sans indication du
    chemin attendu.
    """
    for chemin in workflows(cle):
        assert (RACINE / chemin).is_file(), f"{chemin} est imposé mais absent du dépôt"


def test_le_nom_du_check_est_celui_du_ruleset() -> None:
    """Le nom du workflow et celui de son unique job doivent rester ceux que le
    ruleset exige. Lu en texte : ce projet de tests n'a pas de lecteur YAML."""
    noms = {"conformite": "Conformité Baseline", "secrets": "Secrets Baseline"}
    for cle, nom in noms.items():
        contenu = (RACINE / workflows(cle)[0]).read_text(encoding="utf-8")
        assert f"\nname: {nom}\n" in contenu
        assert f"\n    name: {nom}\n" in contenu
        assert contenu.count("\n    name: ") == 1


@pytest.mark.parametrize("cle", CLES)
def test_regle_a_la_forme_attendue_par_lapi(cle: str) -> None:
    """L'API ignore silencieusement les clés qu'elle ne connaît pas.

    Une faute de frappe sur `repository_id` ne produirait donc aucune erreur,
    seulement un ruleset qui n'impose rien.
    """
    regles = appeler(f"regles_workflows {cle}")
    assert len(regles) == 1
    assert regles[0]["type"] == "workflows"
    for workflow in regles[0]["parameters"]["workflows"]:
        assert set(workflow) == {"repository_id", "path", "ref"}
        assert isinstance(workflow["repository_id"], int)
        assert workflow["ref"] == "refs/tags/v2"


def test_les_deux_rulesets_pointent_le_meme_depot_source() -> None:
    identifiants = {
        w["repository_id"]
        for cle in CLES
        for w in appeler(f"regles_workflows {cle}")[0]["parameters"]["workflows"]
    }
    assert len(identifiants) == 1


# --------------------------------------------------------------------------
# Charge utile de création
# --------------------------------------------------------------------------


@pytest.mark.parametrize("cle", CLES)
def test_charge_de_creation_est_complete(cle: str) -> None:
    charge = appeler(f"charge_ruleset {cle}")
    assert set(charge) == {"name", "target", "enforcement", "conditions", "rules"}
    assert charge["target"] == "branch"


@pytest.mark.parametrize("mode", ["evaluate", "active"])
def test_mode_dapplication_est_celui_demande(mode: str) -> None:
    assert appeler(f"charge_ruleset secrets {mode}")["enforcement"] == mode


@pytest.mark.parametrize("cle", CLES)
def test_creation_par_defaut_est_en_evaluate(cle: str) -> None:
    """La création par défaut ne doit jamais activer un ruleset sans qu'on le veuille."""
    assert appeler(f"charge_ruleset {cle}")["enforcement"] == "evaluate"


@pytest.mark.parametrize("cle", CLES)
def test_charge_de_creation_porte_perimetre_et_regles_de_son_ruleset(cle: str) -> None:
    """Création et mise à jour doivent parler du même périmètre.

    Deux définitions divergeraient au premier ajustement, et le ruleset
    reconstruit après un incident ne serait plus celui qu'on croyait.
    """
    charge = appeler(f"charge_ruleset {cle}")
    assert charge["conditions"] == appeler(f"conditions_ruleset {cle}")
    assert charge["rules"] == appeler(f"regles_workflows {cle}")


def test_les_deux_charges_different_par_le_nom_les_branches_et_le_workflow() -> None:
    conformite = appeler("charge_ruleset conformite")
    secrets = appeler("charge_ruleset secrets")
    assert conformite["name"] != secrets["name"]
    assert conformite["conditions"]["ref_name"] != secrets["conditions"]["ref_name"]
    assert conformite["rules"] != secrets["rules"]
    perimetre_c = conformite["conditions"]["repository_name"]
    assert perimetre_c == secrets["conditions"]["repository_name"]


# --------------------------------------------------------------------------
# Scripts
# --------------------------------------------------------------------------


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


@pytest.mark.parametrize("script", ["creer-ruleset.sh", "maj-ruleset.sh", "activer-ruleset.sh"])
def test_les_scripts_exigent_un_ruleset_nomme(script: str) -> None:
    """Sans cle, aucun script ne devine le ruleset a toucher."""
    resultat = lancer(script)
    assert resultat.returncode == 2
    assert "conformite|secrets" in resultat.stderr


def test_creer_a_blanc_affiche_la_charge_du_ruleset_demande() -> None:
    resultat = lancer("creer-ruleset.sh", "secrets", env={"DRY_RUN": "1"})
    assert resultat.returncode == 0, resultat.stderr
    assert json.loads(resultat.stdout) == appeler("charge_ruleset secrets")


def test_creer_actif_a_la_demande() -> None:
    env = {"DRY_RUN": "1", "ENFORCEMENT": "active"}
    resultat = lancer("creer-ruleset.sh", "secrets", env=env)
    assert json.loads(resultat.stdout)["enforcement"] == "active"


FAUX_GH = """#!/bin/bash
case "$*" in
  *"contents/"*) exit 0 ;;
  "api orgs/Baseline-quebec/rulesets --paginate --jq"*) echo 42 ;;
  "api orgs/Baseline-quebec/rulesets/42") cat "$FAKE_VIVANT" ;;
  "api -X PUT"*) echo "$*" >> "$FAKE_PUT"; echo "{}" ;;
  *) echo "appel inattendu : $*" >&2; exit 9 ;;
esac
"""


def vivant_conformite(branches_vivantes: list[str]) -> dict[str, Any]:
    """Un ruleset de conformité tel que l'API le rendrait, avec une exclusion de
    plus que la déclaration pour vérifier qu'elle survit."""
    exclus = [*variable("EXCLUS"), "depot-exclu-a-la-main"]
    return {
        "id": 42,
        "conditions": {
            "ref_name": {"include": branches_vivantes, "exclude": []},
            "repository_name": {"include": ["~ALL"], "exclude": exclus},
        },
        "rules": appeler("regles_workflows conformite"),
    }


def lancer_maj(
    tmp_path: Path, vivant: dict[str, Any], **env: str
) -> subprocess.CompletedProcess[str]:
    faux = tmp_path / "bin"
    faux.mkdir()
    gh = faux / "gh"
    gh.write_text(FAUX_GH)
    gh.chmod(0o755)
    fichier = tmp_path / "vivant.json"
    fichier.write_text(json.dumps(vivant))
    return lancer(
        "maj-ruleset.sh",
        "conformite",
        env={
            "PATH": f"{faux}:{os.environ['PATH']}",
            "FAKE_VIVANT": str(fichier),
            "FAKE_PUT": str(tmp_path / "put"),
            "DRY_RUN": "1",
            **env,
        },
    )


def test_maj_restreint_conformite_a_la_branche_par_defaut_sur_demande(tmp_path: Path) -> None:
    vivant = vivant_conformite(["~DEFAULT_BRANCH", "refs/heads/develop"])
    resultat = lancer_maj(tmp_path, vivant, AVEC_CONDITIONS="1")
    assert resultat.returncode == 0, resultat.stderr
    corps = json.loads(resultat.stdout[resultat.stdout.index("{") :])
    assert corps["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    # Les exclusions reelles survivent, meme celle que le depot ne declare pas.
    assert "depot-exclu-a-la-main" in corps["conditions"]["repository_name"]["exclude"]
    assert "enforcement" not in corps
    # Les regles sont deja conformes : elles ne sont pas renvoyees (un PUT de
    # `rules` remplace tout le tableau).
    assert "rules" not in corps


def test_maj_sans_drapeau_signale_la_derive_sans_rien_envoyer(tmp_path: Path) -> None:
    vivant = vivant_conformite(["~DEFAULT_BRANCH", "refs/heads/develop"])
    resultat = lancer_maj(tmp_path, vivant)
    assert resultat.returncode == 0, resultat.stderr
    assert "Derive de branches" in resultat.stdout
    assert "AVEC_CONDITIONS=1" in resultat.stdout
    assert "Rien a changer." in resultat.stdout


def test_maj_est_idempotente(tmp_path: Path) -> None:
    vivant = vivant_conformite(["~DEFAULT_BRANCH"])
    resultat = lancer_maj(tmp_path, vivant, AVEC_CONDITIONS="1")
    assert resultat.returncode == 0, resultat.stderr
    assert "Rien a changer." in resultat.stdout


@pytest.mark.parametrize("fonction", ["regles_workflows", "conditions_ruleset", "charge_ruleset"])
def test_une_cle_inconnue_fait_sortir_chaque_fonction_publique(fonction: str) -> None:
    """Une erreur dans `$(...)` resterait confinee : chaque fonction valide la
    cle en tete et sort en erreur."""
    resultat = subprocess.run(
        ["bash", "-c", f'source "{COMMUN}" && {fonction} inconnu'],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert resultat.returncode != 0
    assert resultat.stdout == ""


@pytest.mark.parametrize("script", ["creer-ruleset.sh", "maj-ruleset.sh", "activer-ruleset.sh"])
def test_une_cle_inconnue_n_appelle_jamais_gh(script: str, tmp_path: Path) -> None:
    """Une cle mal tapee dans un script qui ecrit dans l'organisation s'arrete
    avant tout appel `gh api`."""
    faux = tmp_path / "bin"
    faux.mkdir()
    marque = tmp_path / "gh.appele"
    gh = faux / "gh"
    gh.write_text(f'#!/bin/bash\necho "$@" >> "{marque}"\nexit 0\n')
    gh.chmod(0o755)
    resultat = lancer(script, "inconnu", env={"PATH": f"{faux}:{os.environ['PATH']}"})
    assert resultat.returncode != 0
    assert "Ruleset inconnu" in resultat.stderr
    assert not marque.exists(), "gh a ete appele malgre une cle inconnue"


AUTRE_REGLE = {"type": "pull_request", "parameters": {"required_approving_review_count": 1}}


def test_maj_des_regles_conserve_les_autres_regles_et_parametres(tmp_path: Path) -> None:
    """Un PUT de `rules` remplace tout le tableau : les autres regles vivantes et
    les parametres inconnus de la regle `workflows` doivent survivre."""
    vivant = vivant_conformite(["~DEFAULT_BRANCH"])
    vieux = {"repository_id": 1, "path": ".github/workflows/vieux.yml", "ref": "x"}
    vivant["rules"] = [
        AUTRE_REGLE,
        {"type": "workflows", "parameters": {"workflows": [vieux], "parametre_inconnu": 7}},
    ]
    resultat = lancer_maj(tmp_path, vivant)
    assert resultat.returncode == 0, resultat.stderr
    corps = json.loads(resultat.stdout[resultat.stdout.index("{") :])
    assert "conditions" not in corps
    assert corps["rules"][0] == AUTRE_REGLE
    workflows_regle = corps["rules"][1]["parameters"]
    assert workflows_regle["parametre_inconnu"] == 7
    assert workflows_regle["do_not_enforce_on_create"] is True
    assert [w["path"] for w in workflows_regle["workflows"]] == workflows("conformite")


def test_maj_remet_do_not_enforce_on_create_perdu(tmp_path: Path) -> None:
    vivant = vivant_conformite(["~DEFAULT_BRANCH"])
    parametres = vivant["rules"][0]["parameters"]
    del parametres["do_not_enforce_on_create"]
    vivant["rules"].append(AUTRE_REGLE)
    resultat = lancer_maj(tmp_path, vivant)
    assert resultat.returncode == 0, resultat.stderr
    corps = json.loads(resultat.stdout[resultat.stdout.index("{") :])
    assert corps["rules"][0]["parameters"]["do_not_enforce_on_create"] is True
    assert AUTRE_REGLE in corps["rules"]


def test_maj_ajoute_la_regle_workflows_si_elle_manquait(tmp_path: Path) -> None:
    vivant = vivant_conformite(["~DEFAULT_BRANCH"])
    vivant["rules"] = [AUTRE_REGLE]
    resultat = lancer_maj(tmp_path, vivant)
    corps = json.loads(resultat.stdout[resultat.stdout.index("{") :])
    assert corps["rules"][0] == AUTRE_REGLE
    assert corps["rules"][1]["type"] == "workflows"


def lancer_activer(tmp_path: Path, *args: str) -> tuple[subprocess.CompletedProcess[str], Path]:
    faux = tmp_path / "bin"
    faux.mkdir()
    gh = faux / "gh"
    gh.write_text(FAUX_GH)
    gh.chmod(0o755)
    put = tmp_path / "put"
    resultat = lancer(
        "activer-ruleset.sh",
        *args,
        env={"PATH": f"{faux}:{os.environ['PATH']}", "FAKE_PUT": str(put)},
    )
    return resultat, put


def test_activer_retour_arriere_en_disabled(tmp_path: Path) -> None:
    resultat, put = lancer_activer(tmp_path, "secrets", "disabled")
    assert resultat.returncode == 0, resultat.stderr
    assert "enforcement=disabled" in put.read_text()


def test_activer_par_defaut_met_en_active(tmp_path: Path) -> None:
    resultat, put = lancer_activer(tmp_path, "secrets")
    assert resultat.returncode == 0, resultat.stderr
    assert "enforcement=active" in put.read_text()


def test_activer_refuse_un_mode_inconnu_avant_tout_appel(tmp_path: Path) -> None:
    resultat, put = lancer_activer(tmp_path, "secrets", "bidon")
    assert resultat.returncode == 2
    assert not put.exists()


@pytest.mark.parametrize("script", ["creer-ruleset.sh", "maj-ruleset.sh", "activer-ruleset.sh"])
def test_les_listes_de_rulesets_sont_paginees(script: str) -> None:
    """Au-dela de 30 rulesets, la premiere page ne montre pas tout : un ruleset
    existant paraitrait absent."""
    contenu = (SCRIPTS / script).read_text(encoding="utf-8")
    assert 'gh api "orgs/${ORG}/rulesets" --paginate' in contenu
