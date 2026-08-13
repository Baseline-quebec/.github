# Ressources CI partagées de Baseline

Ce dépôt héberge les workflows imposés à l'ensemble des dépôts de
l'organisation `Baseline-quebec` par des rulesets. Aucun de ces fichiers n'est
destiné à être copié dans un dépôt : le principe est justement qu'il n'y ait
**aucun fichier dupliqué** et donc aucune dérive entre dépôts.

## Ce qui est imposé

| Contrôle | Fichier | Déclenchement | Portée |
|---|---|---|---|
| Conformité des licences | `.github/workflows/licence-scan.yml` | Pull request, merge queue | Tous les dépôts ciblés |
| Modèles LLM dépréciés | `.github/workflows/llm-scan.yml` | Pull request, merge queue | Tous les dépôts ciblés |

La détection de dérive des modèles LLM, c'est-à-dire un modèle qui devient
déprécié alors que le code n'a pas bougé, reste couverte par le cron mensuel de
[`tracking-llm-discontinued`](https://github.com/Baseline-quebec/tracking-llm-discontinued).

## Rapport mensuel dans Slack

`licence-digest.yml` tourne le 1er de chaque mois et poste dans **team-dev**
(`C07PLSJB1J9`) : deux ou trois lignes, puis une puce par dépôt portant une
dépendance à arbitrer. Le rapport des modèles dépréciés part le même jour dans
son propre canal, depuis `tracking-llm-discontinued`.

Chaque dépôt est scanné par un job de matrice qui réutilise **exactement la même
action** que les pull requests. Le rapport mensuel et le blocage en PR ne
peuvent donc pas diverger : une seule politique, un seul extracteur.

Le formatage du message vit dans `baseline-automation`, script Windmill
`f/windmill/scripts/Admin/rapport_conformite/send_slack_report`, là où se
trouvent déjà le jeton Slack et les conventions de rapport de l'équipe. Ce dépôt
n'envoie que le résultat structuré.

Le message part **même quand rien n'est trouvé** : un canal silencieux est
ambigu, on ne sait pas si le balayage a tourné ou s'il est cassé.

Prérequis : le secret `ORG_SWEEP_TOKEN` pour lister et cloner les dépôts, la
variable `WINDMILL_RAPPORT_CONFORMITE_URL` et le secret `WINDMILL_TOKEN` pour
l'envoi. Sans les deux derniers, le balayage tourne et le rapport est
simplement sauté.

## Pourquoi un ruleset plutôt que le cookiecutter

Le cookiecutter ne couvre que les nouveaux dépôts et ne rattrape jamais les
82 dépôts existants. Un ruleset organisationnel s'applique immédiatement à
tous, y compris aux dépôts créés demain, sans dépendre de la discipline de qui
que ce soit. Changer la politique se fait ici, à un seul endroit, et les dépôts
suivent au déplacement du tag `v1`.

### La limite à connaître

La règle GitHub *Require workflows to pass before merging* n'écoute que
`pull_request` et `merge_group`, et ces déclencheurs ne sont pas configurables.
**Un push direct vers `main` n'est donc jamais analysé.**

Chez Baseline, ce trou est déjà fermé : un ruleset organisationnel existant
exige une pull request pour toute modification de la branche par défaut, ce qui
a été constaté en tentant de pousser directement sur ce dépôt. Toute
modification passe donc forcément par une pull request, et donc par le scan.
Reste à vérifier, une fois le scope `admin:org` disponible, que ce ruleset cible
bien l'ensemble des dépôts et pas un sous-ensemble.

## Politique de licences

La politique vit dans [`actions/licence-scan/politique.yaml`](actions/licence-scan/politique.yaml),
seule source de vérité. `extraire.py` lit la licence déclarée par chaque
dépendance installée, `report.py` la classe contre la politique.

| Catégorie | Effet | Exemples |
|---|---|---|
| `interdites` | Bloque la fusion | CC-BY-NC, PolyForm, Commons Clause, BUSL-1.1, SSPL, Elastic-2.0, RSAL |
| `a_surveiller` | Signale sans bloquer | AGPL, GPL, LGPL, EUPL, CC-BY-SA |
| `ignorees` | Silencieux | MIT, Apache-2.0, BSD, ISC, MPL-2.0 |
| `licence_inconnue` | Signale sans bloquer | Métadonnée absente ou illisible |

### Demander une exception

Ajouter une entrée dans `exceptions` de `politique.yaml`, par pull request :

```yaml
exceptions:
  - paquet: "chardet"
    licence: "LGPL-2.1"
    raison: "Dépendance transitive de requests, usage interne seulement"
    revoir_le: "2027-01-31"
```

Une exception sans justification ni date de révision doit être refusée en revue.
L'exception est nominative : elle ne débloque que le paquet nommé, pas toutes
les dépendances sous la même licence.

## Pourquoi pas Trivy

Trivy était le choix initial. Il a été écarté après vérification sur un dépôt
réel de 238 paquets : ses analyseurs `uv.lock`, `poetry.lock` et
`requirements.txt` ne portent **aucune** information de licence, il ne lit pas
les fichiers `.dist-info/METADATA`, et son mode `--license-full` ne produit que
des correspondances de texte sans attribution par paquet, 1140 entrées dont
« Copyright ». Un scan Trivy sur un projet Python retourne donc zéro licence,
c'est-à-dire exactement le résultat qu'on obtiendrait s'il n'y avait rien à
signaler.

`extraire.py` lit les métadonnées à la source, sans dépendance externe :
`.dist-info/METADATA` et `.egg-info/PKG-INFO` pour Python, `package.json` sous
`node_modules` pour Node.

## Pièges qui font passer un scan pour vert

**L'installation est obligatoire.** La licence n'existe que dans les
métadonnées des paquets **installés**. Ni `uv.lock` ni `poetry.lock` ne la
portent. L'action installe donc les dépendances avant de lire, et le rapport
dit explicitement quand il n'a rien trouvé plutôt que d'afficher un zéro
rassurant.

**`BSL-1.0` n'est pas `BSL-1.1`.** La première est la Boost Software License,
permissive. La seconde est un alias courant de la Business Source License,
restrictive. Les motifs de la politique sont ancrés pour ne jamais les
confondre ; un test le vérifie.

**Les métadonnées Python sont sales, et chaque forme de saleté ment
différemment.** Les trois cas suivants sont figés par des tests construits sur
des paquets réellement installés chez Baseline :

| Paquet | Ce qu'il déclare | Piège |
|---|---|---|
| `ptyprocess` | `License: UNKNOWN` + classifier ISC | Lire le champ libre en premier produit un faux « non déclarée » |
| `numpy` | Texte BSD complet, paragraphes séparés par des lignes d'espaces | Une ligne d'espaces n'est pas une ligne vide : la traiter comme la fin des en-têtes fait manquer le classifier situé 970 lignes plus bas |
| `tiktoken` | `License: MIT License` puis le texte MIT en continuation | Concaténer les continuations transforme une déclaration nette en pavé illisible |

Mesuré sur quatre dépôts Baseline : 683 dépendances analysées, zéro faux
positif, 5 licences réellement non déclarées, et deux vraies détections
copyleft (`psycopg` en LGPL-3.0, `codespell` en GPL-2.0).

## Gestionnaires reconnus

Python : `uv.lock`, `poetry.lock`, `requirements.txt`.
Node : `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`.

Un dépôt sans aucun de ces fichiers produit un rapport vide et un job vert.

## Mise en service

Le déploiement se fait en deux temps, mais **pas** de la façon qu'on attendrait.

### Le dépôt du scanner est exclu

`tracking-llm-discontinued` est exclu du ruleset, et ce n'est pas cosmétique :
son registre contient l'identifiant de chaque modèle déprécié connu. Y lancer le
scanner de modèles revient à lui faire scanner sa propre liste, ce qui produit
une issue par modèle. Constaté en production, 182 issues en une seule exécution.

### Ce dépôt doit rester public

Un workflow imposé par ruleset **ne se déclenche pas** si son dépôt source est
privé, même avec l'accès Actions du dépôt réglé sur `organization`. Vérifié :
avec ce dépôt en privé, aucune exécution n'apparaissait dans les dépôts ciblés,
sans le moindre message d'erreur nulle part. Le passage en public a suffi à
tout débloquer.

Ne pas repasser ce dépôt en privé. Il ne contient aucun secret, uniquement de la
politique de conformité.

### Le mode Evaluate n'exécute pas les workflows

Vérifié sur l'organisation : avec le ruleset en application `Evaluate`, aucun
workflow ne se déclenche. Les insights ne recensent que des évaluations sur
push, aucune sur pull request, et aucune exécution n'apparaît dans les dépôts
ciblés. `Evaluate` journalise la règle, il ne lance rien.

Le ruleset doit donc être en application **`Active`** pour que le scan tourne du
tout. Le niveau d'application ne vit pas dans le ruleset, il vit dans l'entrée
`mode` de l'action :

| `mode` | Comportement |
|---|---|
| `observation` (défaut) | Le rapport est produit, le job réussit toujours. Une licence interdite, une installation cassée ou une extraction impossible deviennent des avertissements. Rien ne peut bloquer une pull request. |
| `bloquant` | Une licence interdite fait échouer le job, et donc bloque la fusion. |

C'est ce qui rend le déploiement sûr : le ruleset est Active dès le départ pour
que le scan s'exécute, mais l'action en `observation` est incapable de bloquer
quoi que ce soit tant qu'on n'a pas mesuré le bruit réel.

```bash
gh auth refresh -h github.com -s admin:org   # une seule fois, plus l'autorisation SSO

./scripts/creer-ruleset.sh          # crée le ruleset
./scripts/activer-ruleset.sh        # Active : le scan s'exécute, sans bloquer
# ... mesurer un mois, curer politique.yaml ...
# puis passer l'action en mode: bloquant dans licence-scan.yml et redéplacer v1
```

## Développement

```bash
cd actions/licence-scan
uv run --no-project --with pyyaml --with pytest python -m pytest test_report.py -q
```
