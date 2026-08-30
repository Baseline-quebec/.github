"""Tests de la normalisation des constats et de la politique de blocage."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from rapport import (
    CRITIQUE,
    ELEVEE,
    FAIBLE,
    INCONNUE,
    MOYENNE,
    Constat,
    Politique,
    collecter,
    lire_bandit,
    lire_checkov,
    lire_gitleaks,
    lire_hadolint,
    lire_semgrep,
    lire_trivy,
    normaliser_severite,
    resumer,
)

RACINE_POLITIQUE = Path(__file__).parent / "politique.yaml"


def ecrire(dossier: Path, outil: str, contenu: object) -> None:
    (dossier / f"{outil}.json").write_text(json.dumps(contenu), encoding="utf-8")


# --------------------------------------------------------------------------
# Traduction des sévérités
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("brute", "attendu"),
    [
        ("CRITICAL", CRITIQUE),
        ("High", ELEVEE),
        ("error", ELEVEE),
        ("MODERATE", MOYENNE),
        ("warning", MOYENNE),
        ("low", FAIBLE),
        ("style", FAIBLE),
    ],
)
def test_vocabulaires_des_outils_sont_traduits(brute: str, attendu: str) -> None:
    assert normaliser_severite(brute) == attendu


def test_severite_inconnue_nest_pas_rabaissee_en_faible() -> None:
    """Une sévérité non comprise doit rester visible, pas passer pour bénigne.

    C'est la garantie qui empêche un changement de vocabulaire chez un outil de
    faire disparaître silencieusement ses constats sous le seuil.
    """
    assert normaliser_severite("catastrophique") == INCONNUE
    assert normaliser_severite(None) == INCONNUE
    assert normaliser_severite(42) == INCONNUE


# --------------------------------------------------------------------------
# Lecteurs par outil
# --------------------------------------------------------------------------


def test_gitleaks_est_toujours_critique() -> None:
    constats = lire_gitleaks(
        [{"RuleID": "aws-key", "File": "app.py", "StartLine": 12, "Description": "AWS key"}]
    )
    assert [(c.severite, c.regle, c.ligne) for c in constats] == [(CRITIQUE, "aws-key", 12)]


def test_semgrep_lit_la_severite_dans_extra() -> None:
    constats = lire_semgrep(
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval",
                    "path": "src/a.py",
                    "start": {"line": 7},
                    "extra": {"severity": "ERROR", "message": "eval détecté"},
                }
            ]
        }
    )
    assert constats[0].severite == ELEVEE
    assert constats[0].fichier == "src/a.py"
    assert constats[0].ligne == 7


def test_bandit_retrograde_une_severite_haute_de_confiance_basse() -> None:
    """Le gate doit rester crédible : un HIGH/LOW de bandit est trop souvent faux."""
    constats = lire_bandit(
        {
            "results": [
                {
                    "test_id": "B105",
                    "issue_severity": "HIGH",
                    "issue_confidence": "LOW",
                    "filename": "a.py",
                    "line_number": 3,
                    "issue_text": "possible mot de passe",
                }
            ]
        }
    )
    assert constats[0].severite == MOYENNE


def test_bandit_garde_une_severite_haute_de_confiance_haute() -> None:
    constats = lire_bandit(
        {
            "results": [
                {
                    "test_id": "B602",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "filename": "a.py",
                    "line_number": 3,
                    "issue_text": "subprocess shell=True",
                }
            ]
        }
    )
    assert constats[0].severite == ELEVEE


def test_trivy_ignore_les_vulnerabilites_de_dependances() -> None:
    """Les CVE sont la charge de cve-scan ; les compter deux fois donnerait deux verdicts."""
    constats = lire_trivy(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1", "Severity": "CRITICAL"}],
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Severity": "HIGH",
                            "Title": "root user",
                            "CauseMetadata": {"StartLine": 4},
                        }
                    ],
                }
            ]
        }
    )
    assert [c.regle for c in constats] == ["DS002"]


def test_trivy_traite_un_secret_comme_critique() -> None:
    constats = lire_trivy(
        {
            "Results": [
                {
                    "Target": "conf.env",
                    "Secrets": [{"RuleID": "github-pat", "StartLine": 2, "Title": "GitHub PAT"}],
                }
            ]
        }
    )
    assert constats[0].severite == CRITIQUE


def test_checkov_sans_severite_vaut_moyenne() -> None:
    """La sévérité de checkov est une fonction payante : son absence est la norme."""
    constats = lire_checkov(
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "S3 public",
                        "file_path": "main.tf",
                        "file_line_range": [10, 20],
                    }
                ]
            }
        }
    )
    assert constats[0].severite == MOYENNE
    assert constats[0].ligne == 10


def test_checkov_accepte_la_forme_liste_par_cadriciel() -> None:
    """checkov sort un objet seul ou une liste selon le nombre de cadriciels détectés."""
    charge = [
        {"results": {"failed_checks": [{"check_id": "CKV_1", "file_path": "a.tf"}]}},
        {"results": {"failed_checks": [{"check_id": "CKV_2", "file_path": "b.yaml"}]}},
    ]
    assert [c.regle for c in lire_checkov(charge)] == ["CKV_1", "CKV_2"]


def test_hadolint_traduit_ses_niveaux() -> None:
    constats = lire_hadolint(
        [{"code": "DL3008", "level": "warning", "file": "Dockerfile", "line": 5, "message": "pin"}]
    )
    assert constats[0].severite == MOYENNE


@pytest.mark.parametrize(
    "lecteur",
    [lire_gitleaks, lire_semgrep, lire_bandit, lire_trivy, lire_checkov, lire_hadolint],
)
def test_aucun_lecteur_ne_casse_sur_une_charge_aberrante(lecteur) -> None:
    """Un format inattendu doit donner zéro constat, jamais une exception.

    Une exception ici ferait échouer le job entier et masquerait les constats
    des cinq autres outils.
    """
    for charge in (None, "texte", 3, [], {}, {"results": "pas une liste"}, [1, 2]):
        assert lecteur(charge) == []


# --------------------------------------------------------------------------
# Collecte
# --------------------------------------------------------------------------


def test_outil_sans_rapport_est_signale_muet(tmp_path: Path) -> None:
    """Un scanner cassé ressemble à un dépôt propre : il faut le dire."""
    ecrire(tmp_path, "gitleaks", [])
    constats, muets = collecter(tmp_path)
    assert constats == []
    assert "gitleaks" not in muets
    assert "semgrep" in muets


def test_rapport_illisible_est_muet_et_ninterrompt_pas(tmp_path: Path) -> None:
    (tmp_path / "semgrep.json").write_text("{pas du json", encoding="utf-8")
    ecrire(tmp_path, "gitleaks", [{"RuleID": "x", "File": "a", "StartLine": 1}])
    constats, muets = collecter(tmp_path)
    assert len(constats) == 1
    assert "semgrep" in muets


def test_outil_non_applicable_nest_pas_signale_muet(tmp_path: Path) -> None:
    """Un dépôt sans Dockerfile n'a pas un hadolint cassé, il n'a pas de Dockerfile.

    Les confondre ferait crier au scanner muet sur presque tous les dépôts, et
    un avertissement qui se déclenche toujours cesse d'être lu.
    """
    ecrire(tmp_path, "gitleaks", [])
    _, muets = collecter(tmp_path, {"bandit", "checkov", "hadolint"})
    assert muets == ["semgrep", "trivy"]


def test_outil_non_applicable_avec_rapport_est_quand_meme_ignore(tmp_path: Path) -> None:
    """La détection fait foi : ce qu'on n'a pas voulu lancer n'est pas lu."""
    ecrire(tmp_path, "hadolint", [{"code": "DL1", "level": "error", "line": 1}])
    constats, muets = collecter(tmp_path, {"hadolint"})
    assert constats == []
    assert "hadolint" not in muets


def test_rapport_vide_est_muet(tmp_path: Path) -> None:
    """Un fichier de zéro octet est un outil qui n'a rien écrit, pas un scan propre."""
    (tmp_path / "trivy.json").write_text("", encoding="utf-8")
    _, muets = collecter(tmp_path)
    assert "trivy" in muets


def test_constats_sont_tries_par_gravite(tmp_path: Path) -> None:
    ecrire(tmp_path, "hadolint", [{"code": "DL1", "level": "info", "line": 1}])
    ecrire(tmp_path, "gitleaks", [{"RuleID": "clef", "File": "a.py", "StartLine": 1}])
    constats, _ = collecter(tmp_path)
    assert [c.severite for c in constats] == [CRITIQUE, FAIBLE]


# --------------------------------------------------------------------------
# Politique
# --------------------------------------------------------------------------


def constat(severite: str = ELEVEE, outil: str = "bandit", regle: str = "B101") -> Constat:
    return Constat(outil, regle, severite, "a.py", 1, "message")


def test_seuil_par_defaut_bloque_critique_et_elevee() -> None:
    politique = Politique()
    bloquants, autres = politique.trier([constat(CRITIQUE), constat(MOYENNE), constat(ELEVEE)])
    assert len(bloquants) == 2
    assert len(autres) == 1


def test_inconnue_ne_bloque_pas_mais_reste_listee() -> None:
    """Un changement de vocabulaire chez un outil ne doit pas geler l'organisation."""
    bloquants, autres = Politique().trier([constat(INCONNUE)])
    assert bloquants == []
    assert len(autres) == 1


def test_exemption_valide_desamorce_le_constat() -> None:
    politique = Politique.charger(RACINE_POLITIQUE)
    bloquants, autres = politique.trier(
        [constat(ELEVEE, "bandit", "B101")], aujourdhui=dt.date(2026, 9, 1)
    )
    assert bloquants == []
    assert len(autres) == 1


def test_exemption_echue_redevient_bloquante() -> None:
    """La date d'expiration est le mécanisme, pas une décoration."""
    politique = Politique.charger(RACINE_POLITIQUE)
    bloquants, _ = politique.trier(
        [constat(ELEVEE, "bandit", "B101")], aujourdhui=dt.date(2027, 2, 1)
    )
    assert len(bloquants) == 1


def test_exemption_ne_deborde_pas_sur_un_autre_outil() -> None:
    politique = Politique.charger(RACINE_POLITIQUE)
    bloquants, _ = politique.trier(
        [constat(ELEVEE, "semgrep", "B101")], aujourdhui=dt.date(2026, 9, 1)
    )
    assert len(bloquants) == 1


def test_motif_dexemption_est_ancre_sur_tout_lidentifiant() -> None:
    """`B101` ne doit pas exempter `B1010` : une exemption trop large est invisible."""
    politique = Politique.charger(RACINE_POLITIQUE)
    bloquants, _ = politique.trier(
        [constat(ELEVEE, "bandit", "B1010")], aujourdhui=dt.date(2026, 9, 1)
    )
    assert len(bloquants) == 1


def test_politique_vide_bloque_encore_le_critique(tmp_path: Path) -> None:
    """Un fichier de politique vidé par erreur ne doit pas tout laisser passer."""
    vide = tmp_path / "politique.yaml"
    vide.write_text("bloquantes: []\n", encoding="utf-8")
    bloquants, _ = Politique.charger(vide).trier([constat(CRITIQUE)])
    assert len(bloquants) == 1


def test_politique_du_depot_reste_chargeable() -> None:
    """Une regex invalide ici casserait le scan de tous les dépôts d'un coup."""
    politique = Politique.charger(RACINE_POLITIQUE)
    assert politique.bloquantes
    assert all(e.expire is not None for e in politique.exemptions), (
        "Toute exemption doit porter une date d'expiration"
    )


# --------------------------------------------------------------------------
# Résumé
# --------------------------------------------------------------------------


def test_resume_signale_les_outils_muets() -> None:
    texte = resumer([], [], ["semgrep", "trivy"])
    assert "semgrep, trivy" in texte
    assert "pas une preuve de conformité" in texte


def test_resume_tronque_mais_annonce_le_reste() -> None:
    constats = [constat(MOYENNE) for _ in range(60)]
    texte = resumer([], constats, [])
    assert "10 constat(s) supplémentaires" in texte
