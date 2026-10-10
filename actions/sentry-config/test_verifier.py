"""Tests du contrôle de configuration Sentry.

Chaque cas reproduit une forme réellement rencontrée dans le parc au
2026-10-10 : l'appel nu des chatbots (`traces_sample_rate` et rien d'autre),
le `**sentry_init_kwargs(dsn)` de baseline-automation, le plugin Nitro de
cogniflo qui va chercher ses options dans un autre fichier, l'import dynamique
de mpa-site-web, le gabarit Jinja de baseline-app-template. Un cas vrai et un
cas faux pour chacun : un vérificateur qui ne rougit jamais passe ses tests
aussi bien qu'un vérificateur juste.
"""

from __future__ import annotations

import datetime as dt
import textwrap
from pathlib import Path

import pytest
from verifier import analyser, main, sans_commentaires_js, verifier_js, verifier_python

ICI = Path(__file__).parent

CONFORME_PY = """
import sentry_sdk

def configure(dsn: str) -> None:
    sentry_sdk.init(
        dsn=dsn,
        send_default_pii=False,
        include_local_variables=False,
        before_send=scrub_event,
    )
"""


def codes_py(source: str, jinja: bool = False) -> list[str]:
    return [code for _, code, _ in verifier_python(textwrap.dedent(source), jinja=jinja)]


def codes_js(source: str, fichier: Path | None = None) -> list[str]:
    return [code for _, code, _ in verifier_js(textwrap.dedent(source), fichier)]


# --- Python : ce qui passe -----------------------------------------------------


def test_python_conforme() -> None:
    assert codes_py(CONFORME_PY) == []


def test_python_la_reference_du_gabarit_passe() -> None:
    """init_sentry() du gabarit déballe des options libres APRÈS les réglages.

    Les trois réglages sont explicites : Python refuse un mot-clé passé deux
    fois, donc le `**` ne peut pas les écraser, et le vérificateur ne doit pas
    le déclarer « non vérifiable ».
    """
    source = """
    import sentry_sdk
    from typing import Any, cast

    def init_sentry(dsn, *, environment, release, **options: object) -> bool:
        sentry_sdk.init(
            dsn=dsn,
            environment=environment,
            send_default_pii=False,
            include_local_variables=False,
            max_request_body_size="never",
            before_send=scrub_event,
            before_send_transaction=scrub_event,
            **cast("dict[str, Any]", options),
        )
        return True
    """
    assert codes_py(source) == []


def test_python_dict_rendu_par_une_fonction_du_module() -> None:
    """La forme de baseline-automation : sentry_sdk.init(**sentry_init_kwargs(dsn))."""
    source = """
    import sentry_sdk

    def sentry_init_kwargs(dsn):
        return {
            "dsn": dsn,
            "send_default_pii": False,
            "include_local_variables": False,
            "before_send": scrub_event,
        }

    def demarrer(dsn):
        sentry_sdk.init(**sentry_init_kwargs(dsn))
    """
    assert codes_py(source) == []


def test_python_dict_dans_une_variable() -> None:
    source = """
    import sentry_sdk
    OPTIONS = dict(send_default_pii=False, include_local_variables=False, before_send=f)
    sentry_sdk.init(dsn="x", **OPTIONS)
    """
    assert codes_py(source) == []


def test_python_un_init_qui_n_est_pas_celui_de_sentry_est_ignore() -> None:
    source = """
    import sentry_sdk  # importé, mais l'appel visé est un autre init
    import logging_lib
    logging_lib.init(send_default_pii=True)
    """
    assert codes_py(source) == []


def test_python_une_mention_en_commentaire_ou_docstring_est_ignoree() -> None:
    source = '''
    """Appelle sentry_sdk.init(dsn) au démarrage."""
    import sentry_sdk
    # sentry_sdk.init(send_default_pii=True)
    '''
    assert codes_py(source) == []


# --- Python : ce qui échoue ----------------------------------------------------


def test_python_appel_nu_des_chatbots() -> None:
    """La forme majoritaire du parc : seulement dsn, release, environnement, taux."""
    source = """
    import sentry_sdk
    sentry_sdk.init(dsn=dsn, traces_sample_rate=0.1, release="x@1", environment=env)
    """
    assert codes_py(source) == [
        "send_default_pii-absent",
        "include_local_variables-absent",
        "before_send-absent",
    ]


def test_python_send_default_pii_vrai() -> None:
    source = CONFORME_PY.replace("send_default_pii=False", "send_default_pii=True")
    assert codes_py(source) == ["send_default_pii-actif"]


def test_python_variables_locales_actives() -> None:
    """La branche d'aideline qui envoyait les variables locales."""
    source = CONFORME_PY.replace("include_local_variables=False", "include_local_variables=True")
    assert codes_py(source) == ["include_local_variables-actif"]


def test_python_variables_locales_absentes() -> None:
    """Le défaut du SDK est True : l'absence est une fuite, pas un oubli bénin."""
    source = CONFORME_PY.replace("include_local_variables=False,", "")
    assert codes_py(source) == ["include_local_variables-absent"]


def test_python_valeur_non_litterale() -> None:
    """Un réglage lu dans la configuration peut valoir True en production."""
    source = CONFORME_PY.replace("send_default_pii=False", "send_default_pii=settings.pii")
    assert codes_py(source) == ["send_default_pii-actif"]


@pytest.mark.parametrize("remplacement", ["", "before_send=None,"])
def test_python_before_send_absent_ou_nul(remplacement: str) -> None:
    source = CONFORME_PY.replace("before_send=scrub_event,", remplacement)
    assert codes_py(source) == ["before_send-absent"]


@pytest.mark.parametrize(
    "importation, appel",
    [
        ("import sentry_sdk as s", "s.init"),
        ("from sentry_sdk import init", "init"),
        ("from sentry_sdk import init as demarrer_sentry", "demarrer_sentry"),
    ],
)
def test_python_les_alias_sont_suivis(importation: str, appel: str) -> None:
    source = f"{importation}\n{appel}(dsn='x', send_default_pii=True)\n"
    assert "send_default_pii-actif" in codes_py(source)


def test_python_deballage_introuvable_est_non_verifiable() -> None:
    source = """
    import sentry_sdk
    from config import OPTIONS
    sentry_sdk.init(**OPTIONS)
    """
    assert codes_py(source) == ["non-verifiable"]


def test_python_une_branche_sans_reglage_suffit_a_echouer() -> None:
    source = """
    import sentry_sdk

    def options(prod):
        if prod:
            return {"send_default_pii": False, "include_local_variables": False, "before_send": f}
        return {"send_default_pii": False, "before_send": f}

    sentry_sdk.init(**options(True))
    """
    assert codes_py(source) == ["include_local_variables-absent"]


def test_python_le_dict_rendu_est_juge_comme_un_appel_direct() -> None:
    source = """
    import sentry_sdk

    def kwargs(dsn):
        return {"dsn": dsn, "send_default_pii": False, "before_send": f}

    sentry_sdk.init(**kwargs("x"))
    """
    assert codes_py(source) == ["include_local_variables-absent"]


# --- Gabarits Jinja et fichiers illisibles par ast -----------------------------

JINJA = """
{%- if with_sentry %}
    if settings.sentry_dsn:
        import sentry_sdk

        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            environment=settings.sentry_environment,{{ extra }}
            traces_sample_rate=settings.sentry_traces_sample_rate,
        )
{%- endif %}
"""


def test_jinja_non_conforme() -> None:
    assert codes_py(JINJA.replace("{{ extra }}", ""), jinja=True) == [
        "send_default_pii-absent",
        "include_local_variables-absent",
        "before_send-absent",
    ]


def test_jinja_conforme() -> None:
    reglages = "\n            send_default_pii=False,\n            include_local_variables=False,"
    reglages += "\n            before_send=scrub_event,"
    assert codes_py(JINJA.replace("{{ extra }}", reglages), jinja=True) == []


def test_jinja_un_commentaire_ne_compte_pas() -> None:
    source = JINJA.replace(
        "{{ extra }}", "  # send_default_pii=False include_local_variables=False"
    )
    assert "send_default_pii-absent" in codes_py(source, jinja=True)


def test_python_invalide_retombe_sur_le_texte() -> None:
    source = "import sentry_sdk\nsentry_sdk.init(dsn=x, send_default_pii=True\n"
    assert "send_default_pii-actif" in codes_py(source)


# --- JavaScript et TypeScript : ce qui passe ----------------------------------


def test_js_conforme() -> None:
    source = """
    import * as Sentry from '@sentry/vue'
    Sentry.init({ app, dsn, sendDefaultPii: false, beforeSend: scrubEvent })
    """
    assert codes_js(source) == []


@pytest.mark.parametrize("before_send", ["beforeSend,", "beforeSend(event) { return event },"])
def test_js_before_send_abrege_ou_methode(before_send: str) -> None:
    source = f"""
    import * as Sentry from '@sentry/node'
    Sentry.init({{ dsn, sendDefaultPii: false, {before_send} }})
    """
    assert codes_js(source) == []


def test_js_la_reference_du_gabarit_passe() -> None:
    source = """
    import * as Sentry from '@sentry/vue'
    import { baselineSentryOptions } from '~/utils/baseline-sentry'
    Sentry.init(baselineSentryOptions({ app, dsn, environment: 'prod' }))
    """
    assert codes_js(source) == []


def test_js_import_dynamique_de_mpa_site_web() -> None:
    source = """
    const Sentry = await import(
        /* webpackChunkName: "sentry" */ '@sentry/browser'
    );
    Sentry.init( {
        dsn: config.dsn,
        sendDefaultPii: false,
        beforeSend: expurger,
    } );
    """
    assert codes_js(source) == []


def test_js_un_init_etranger_est_ignore() -> None:
    source = """
    import * as Sentry from '@sentry/vue'
    analytics.init({ sendDefaultPii: true })
    """
    assert codes_js(source) == []


def test_js_une_url_n_est_pas_un_commentaire() -> None:
    source = "const u = 'https://x.ca' // vrai commentaire sendDefaultPii: false\nlet a = 1"
    assert sans_commentaires_js(source) == "const u = 'https://x.ca' \nlet a = 1"


# --- JavaScript et TypeScript : ce qui échoue ---------------------------------


def test_js_plugin_nuxt_sans_reglage() -> None:
    """La forme de mieuxcompris-pv : ni sendDefaultPii, ni beforeSend."""
    source = """
    import * as Sentry from '@sentry/vue'
    Sentry.init({
      app: nuxtApp.vueApp,
      dsn,
      integrations: [Sentry.browserTracingIntegration({ router })],
      tracesSampleRate: 0.1,
    })
    """
    assert codes_js(source) == ["sendDefaultPii-absent", "beforeSend-absent"]


def test_js_pii_sans_before_send() -> None:
    """La forme de sib-assistant : PII coupées, mais rien n'expurge le reste."""
    source = """
    import * as Sentry from '@sentry/vue'
    Sentry.init({ dsn, tracesSampleRate: 0, sendDefaultPii: false })
    """
    assert codes_js(source) == ["beforeSend-absent"]


def test_js_pii_vraies() -> None:
    source = """
    import * as Sentry from '@sentry/browser'
    Sentry.init({ dsn, sendDefaultPii: true, beforeSend: f })
    """
    assert codes_js(source) == ["sendDefaultPii-actif"]


def test_js_la_reference_ne_couvre_pas_une_pii_forcee() -> None:
    source = """
    import * as Sentry from '@sentry/vue'
    Sentry.init({ ...baselineSentryOptions({ dsn, environment }), sendDefaultPii: true })
    """
    assert codes_js(source) == ["sendDefaultPii-actif"]


def test_js_un_commentaire_ne_compte_pas() -> None:
    source = """
    import * as Sentry from '@sentry/vue'
    Sentry.init({
      dsn,
      // sendDefaultPii: false, beforeSend: scrub
    })
    """
    assert codes_js(source) == ["sendDefaultPii-absent", "beforeSend-absent"]


def test_js_init_importe_par_nom() -> None:
    source = """
    import { init as startSentry } from '@sentry/node'
    startSentry({ dsn })
    """
    assert codes_js(source) == ["sendDefaultPii-absent", "beforeSend-absent"]


def test_js_options_dans_une_variable_inconnue() -> None:
    source = """
    import * as Sentry from '@sentry/node'
    import { options } from 'config-package'
    Sentry.init(options)
    """
    assert codes_js(source) == ["non-verifiable"]


def test_js_options_d_une_fonction_du_meme_fichier() -> None:
    source = """
    import * as Sentry from '@sentry/node'
    function options() {
      return { dsn, sendDefaultPii: false, beforeSend: scrub }
    }
    Sentry.init(options())
    """
    assert codes_js(source) == []


def plugin_cogniflo(racine: Path, options: str) -> Path:
    """Le plugin Nitro de cogniflo, qui lit ses options dans un autre fichier."""
    plugin = racine / "server/plugins/sentry.server.ts"
    config = racine / "server/infra/sentry/sentry-config.ts"
    plugin.parent.mkdir(parents=True)
    config.parent.mkdir(parents=True)
    plugin.write_text(
        'import { sentryCloudflareNitroPlugin } from "@sentry/nuxt/module/plugins";\n'
        'import { buildSentryOptions } from "../infra/sentry/sentry-config";\n'
        "export default defineNitroPlugin(\n"
        "  sentryCloudflareNitroPlugin(() => buildSentryOptions()),\n"
        ");\n",
        encoding="utf-8",
    )
    config.write_text(
        'import type { CloudflareOptions } from "@sentry/cloudflare";\n'
        "export function buildSentryOptions(env = process.env): CloudflareOptions {\n"
        f"  return {{ dsn: env.SENTRY_DSN, tracesSampleRate: 0.1, {options} }};\n"
        "}\n",
        encoding="utf-8",
    )
    return plugin


def test_js_options_suivies_dans_un_autre_fichier_non_conformes(tmp_path: Path) -> None:
    plugin = plugin_cogniflo(tmp_path, "beforeSend(event, hint) { return event },")
    assert codes_js(plugin.read_text(encoding="utf-8"), plugin) == ["sendDefaultPii-absent"]


def test_js_options_suivies_dans_un_autre_fichier_conformes(tmp_path: Path) -> None:
    plugin = plugin_cogniflo(tmp_path, "sendDefaultPii: false, beforeSend: scrubEvent,")
    assert codes_js(plugin.read_text(encoding="utf-8"), plugin) == []


# --- Le dépôt entier ------------------------------------------------------------


def ecrire(racine: Path, chemin: str, contenu: str) -> None:
    fichier = racine / chemin
    fichier.parent.mkdir(parents=True, exist_ok=True)
    fichier.write_text(textwrap.dedent(contenu), encoding="utf-8")


NU = "import sentry_sdk\nsentry_sdk.init(dsn='x')\n"


def test_les_tests_et_les_dependances_sont_exclus(tmp_path: Path) -> None:
    ecrire(tmp_path, "tests/conftest.py", NU)
    ecrire(tmp_path, "src/test_app.py", NU)
    ecrire(tmp_path, ".venv/lib/sentry_sdk/client.py", NU)
    ecrire(tmp_path, "node_modules/@sentry/core/index.js", "Sentry.init({})")
    ecrire(tmp_path, "app/plugin.test.ts", "import * as Sentry from '@sentry/vue'\nSentry.init({})")
    assert analyser(tmp_path, "Baseline-quebec/x") == []


def test_le_constat_porte_fichier_et_ligne(tmp_path: Path) -> None:
    ecrire(tmp_path, "src/app/sentry.py", "\n\n" + NU)
    constats = analyser(tmp_path, "Baseline-quebec/x")
    assert {(c.chemin, c.ligne) for c in constats} == {("src/app/sentry.py", 4)}
    assert constats[0].regle == "Baseline-quebec/x:src/app/sentry.py"


def politique(tmp_path: Path, exemptions: str = "") -> Path:
    chemin = tmp_path / "politique.yaml"
    chemin.write_text(f"bloquantes: [ELEVEE]\nexemptions:\n{exemptions}", encoding="utf-8")
    return chemin


def test_main_bloque_puis_observe(tmp_path: Path) -> None:
    depot = tmp_path / "depot"
    ecrire(depot, "src/sentry.py", NU)
    options = ["--racine", str(depot), "--politique", str(politique(tmp_path)), "--depot", "B/x"]
    assert main(options) == 1
    assert main([*options, "--sans-blocage"]) == 0


def test_main_vert_sur_un_depot_conforme(tmp_path: Path) -> None:
    depot = tmp_path / "depot"
    ecrire(depot, "src/sentry.py", CONFORME_PY)
    ecrire(depot, "README.md", "sentry_sdk.init(dsn) sans réglage, dans la documentation")
    assert main(["--racine", str(depot), "--politique", str(politique(tmp_path))]) == 0


def test_main_racine_absente_n_est_pas_un_succes(tmp_path: Path) -> None:
    assert (
        main(["--racine", str(tmp_path / "absent"), "--politique", str(politique(tmp_path))]) == 1
    )


def test_une_exemption_datee_couvre_le_fichier_et_expire(tmp_path: Path) -> None:
    depot = tmp_path / "depot"
    ecrire(depot, "src/legacy.py", NU)
    demain = dt.date.today() + dt.timedelta(days=1)
    hier = dt.date.today() - dt.timedelta(days=1)
    ligne = '  - outil: sentry\n    regle: "B/x:src/legacy\\\\.py"\n    justification: test\n'
    valide = politique(tmp_path, ligne + f"    expire: {demain.isoformat()}\n")
    assert main(["--racine", str(depot), "--politique", str(valide), "--depot", "B/x"]) == 0
    echue = politique(tmp_path, ligne + f"    expire: {hier.isoformat()}\n")
    assert main(["--racine", str(depot), "--politique", str(echue), "--depot", "B/x"]) == 1


def test_le_resume_est_ecrit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    depot = tmp_path / "depot"
    ecrire(depot, "src/sentry.py", NU)
    resume = tmp_path / "resume.md"
    sorties = tmp_path / "sorties"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(resume))
    monkeypatch.setenv("GITHUB_OUTPUT", str(sorties))
    main(["--racine", str(depot), "--politique", str(politique(tmp_path)), "--sans-blocage"])
    assert "`src/sentry.py`" in resume.read_text(encoding="utf-8")
    assert "bloquants=3" in sorties.read_text(encoding="utf-8")


def test_la_politique_livree_bloque() -> None:
    """Une politique vidée par erreur ne doit pas laisser tout passer."""
    import sys

    sys.path.insert(0, str(ICI.parent / "commun"))
    from politique import ELEVEE, Politique

    assert ELEVEE in Politique.charger(ICI / "politique.yaml").bloquantes
