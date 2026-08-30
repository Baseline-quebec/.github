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
| Sécurité du code | `.github/workflows/secaudit-code.yml` | Pull request, merge queue | Tous les dépôts ciblés |
| Vulnérabilités des dépendances | `.github/workflows/cve-scan.yml` | Pull request, merge queue | Tous les dépôts ciblés |

La détection de dérive des modèles LLM, c'est-à-dire un modèle qui devient
déprécié alors que le code n'a pas bougé, reste couverte par le cron mensuel de
[`tracking-llm-discontinued`](https://github.com/Baseline-quebec/tracking-llm-discontinued).

Les deux contrôles de sécurité sont en **mode observation** : ils produisent
leur rapport et n'empêchent aucune fusion. Passer au mode bloquant se fait dans
le workflow correspondant, une fois le volume réel de constats mesuré sur les
dépôts existants. Le niveau d'application vit dans l'entrée `mode` du workflow
et non dans le ruleset : en application *Evaluate*, GitHub journalise la règle
sans jamais lancer le workflow, donc sans produire le moindre rapport.

### Audit de sécurité du code

`actions/secaudit-code` cherche les secrets en clair (gitleaks, trivy), les
motifs de code dangereux (semgrep, bandit) et les erreurs de configuration
d'infrastructure (checkov, hadolint, trivy). C'est le profil `code` de l'ancien
dépôt `baseline-secaudit`, ramené à ce qui peut tourner sur une pull request.

Ce qui n'a pas été repris : le profil `live` (nmap, testssl, nuclei, ZAP) et
l'import dans DefectDojo. Ces outils visent une application **déployée**, ce
qu'une pull request n'a pas, et supposent une autorisation de scan sur la cible.
Le dépôt `baseline-secaudit` est archivé et reste clonable pour cet usage
ponctuel.

Chaque outil se termine par `|| true` : un scanner qui plante n'emporte pas les
cinq autres. Son silence est signalé comme tel dans le rapport, jamais compté
comme une absence de constat ; un scanner cassé ressemble exactement à un dépôt
propre.

### Vulnérabilités des dépendances

`actions/cve-scan` confronte les fichiers de verrouillage à la base OSV et
rapporte, pour chaque avis, la version qui le corrige. Il remplace le dépôt
`baseline-dep-scanner`, qui cherchait des motifs dans le texte des manifestes :
osv-scanner lit les versions **résolues**, donc il voit les dépendances
transitives, et il n'a besoin d'installer rien du tout. C'est ce qui le rend
utilisable sur un dépôt dont les dépendances ne s'installent plus, c'est-à-dire
précisément celui qui risque de porter une CVE ancienne.

Les vulnérabilités de dépendances sont volontairement absentes de
`secaudit-code` (`trivy --scanners misconfig,secret`) : les compter aux deux
endroits ferait apparaître la même CVE dans deux rapports, avec deux verdicts
possibles selon l'outil qui l'a vue.

## Rapports périodiques dans Slack

`licence-digest.yml` tourne le 1er de chaque mois et poste dans **team-dev**
(`C07PLSJB1J9`) : deux ou trois lignes, puis une puce par dépôt portant une
dépendance à arbitrer. Le rapport des modèles dépréciés part le même jour dans
son propre canal, depuis `tracking-llm-discontinued`.

`cve-digest.yml` fait de même pour les vulnérabilités, mais **chaque lundi**.
La cadence diffère parce que la question diffère : une licence change quand
quelqu'un modifie une dépendance, une CVE apparaît toute seule. Attendre le 1er
du mois, c'est accepter jusqu'à trente jours entre la publication d'un avis
critique et le moment où on l'apprend. Seules les vulnérabilités au-dessus du
seuil remontent dans Slack, avec la version corrective : un message qui liste
tout ne se lit plus, donc ne sert plus.

Chaque dépôt est scanné par un job de matrice qui réutilise **exactement la même
action** que les pull requests. Le rapport périodique et le blocage en PR ne
peuvent donc pas diverger : une seule politique, un seul extracteur.

L'énumération des dépôts et l'envoi à Windmill sont communs aux deux balayages
et vivent dans `actions/sweep/sweep.py`. Chaque balayage ne garde que son
agrégation, dans le dossier de son action, avec ses tests. Les deux moitiés se
parlent par un fichier JSON sur le disque plutôt que par un import : chaque
script est appelé en ligne de commande depuis une étape de workflow distincte.

Le formatage du message vit dans `baseline-automation`, script Windmill
`f/windmill/scripts/Admin/rapport_conformite/send_slack_report`, là où se
trouvent déjà le jeton Slack et les conventions de rapport de l'équipe. Ce dépôt
n'envoie que le résultat structuré.

Le message part **même quand rien n'est trouvé** : un canal silencieux est
ambigu, on ne sait pas si le balayage a tourné ou s'il est cassé.

### Prérequis

Une **GitHub App** installée sur l'organisation, dont l'identifiant et la clé
privée sont les secrets `ORG_SWEEP_APP_ID` et `ORG_SWEEP_APP_KEY`. Permissions
requises, côté dépôt uniquement :

| Permission | Niveau | Pourquoi |
|---|---|---|
| Contents | Lecture | Cloner chaque dépôt pour lire ses dépendances |
| Metadata | Lecture | Accordée automatiquement, non désactivable |

Le rapport de licences n'ouvre aucune issue, donc il n'a pas besoin de la
permission Issues. C'est le balayage des modèles dépréciés, dans
`tracking-llm-discontinued`, qui l'exige.

Une App plutôt qu'un jeton personnel : le rapport ne dépend d'aucune personne,
ne casse pas quand quelqu'un quitte l'équipe, et n'a pas d'expiration annuelle.

La liste des dépôts vient de `/installation/repositories` et non de
`gh repo list` : un jeton d'installation ne peut pas énumérer une organisation
via GraphQL. L'endpoint retourne exactement ce que l'App a le droit de toucher.

Pour l'envoi, la variable `WINDMILL_RAPPORT_CONFORMITE_URL` et le secret
`WINDMILL_TOKEN`. Sans eux, le balayage tourne et le rapport est simplement
sauté.

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
| `interdites` | Bloque la fusion | CC-BY-NC, PolyForm, Commons Clause, BUSL-1.1, SSPL, Elastic-2.0, RSAL, **AGPL** |
| `a_surveiller` | Signale sans bloquer | GPL, LGPL, EUPL, CC-BY-SA |
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

## Politiques de sécurité

Chaque contrôle de sécurité a son propre `politique.yaml`, seule source de
vérité de son seuil : les sévérités qui bloquent et les exemptions n'ont aucune
raison d'être les mêmes pour un secret en clair et pour une CVE transitive.

| Politique | Fichier | Bloque |
|---|---|---|
| Sécurité du code | [`actions/secaudit-code/politique.yaml`](actions/secaudit-code/politique.yaml) | CRITIQUE, ELEVEE |
| Vulnérabilités | [`actions/cve-scan/politique.yaml`](actions/cve-scan/politique.yaml) | CRITIQUE, ELEVEE |

Le vocabulaire de sévérité et le mécanisme de seuil sont partagés dans
[`actions/commun/politique.py`](actions/commun/politique.py) : deux copies
dériveraient au premier ajustement.

**`INCONNUE` ne bloque jamais.** Un outil qui change son vocabulaire de
sévérité entre deux versions verrouillerait sinon les pull requests de toute
l'organisation du jour au lendemain. Ces constats restent au rapport, et un pic
d'`INCONNUE` signale une régression de parsing à corriger, pas un dépôt sain.

**Une sévérité non comprise n'est pas une sévérité basse.** La traduction vers
`INCONNUE` plutôt que `FAIBLE` est délibérée : c'est la seule façon d'empêcher
qu'un constat sérieux disparaisse sous le seuil par accident de vocabulaire.

### Demander une exemption

Ajouter une entrée dans `exemptions`, par pull request :

```yaml
exemptions:
  - outil: bandit
    regle: "B101"
    justification: >
      Pourquoi c'est acceptable chez nous, pas ce que fait la règle.
    expire: 2027-01-31
```

`expire` est obligatoire et la CI le vérifie : une exemption échue redevient
bloquante d'elle-même. Sans cette date, une exemption prise un mardi pour
débloquer une livraison devient une politique permanente que plus personne ne
relit. Le motif est ancré sur la totalité de l'identifiant, donc `B101`
n'exempte pas `B1010` ; un test le vérifie.

Pour une CVE, vérifier d'abord qu'il n'existe pas simplement une version
corrective à installer : le rapport la donne.

## Pourquoi pas Trivy pour les licences

Trivy était le choix initial pour le scan de licences. Il a été écarté après vérification sur un dépôt
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

Trivy reste utilisé dans `secaudit-code`, mais pour ce qu'il fait bien :
les erreurs de configuration et les secrets, jamais les licences ni les
vulnérabilités de dépendances.

## Pièges qui font passer un scan pour vert

**L'installation est obligatoire.** La licence n'existe que dans les
métadonnées des paquets **installés**. Ni `uv.lock` ni `poetry.lock` ne la
portent. L'action installe donc les dépendances avant de lire, et le rapport
dit explicitement quand il n'a rien trouvé plutôt que d'afficher un zéro
rassurant.

**L'AGPL est bloquante, le GPL ne l'est pas.** Décision d'équipe : l'AGPL
contamine dès qu'un service est exposé, ce qui est le cas de la plupart des
livraisons Baseline. Cas concret ayant motivé la règle, PyMuPDF, dont l'usage
commercial exige une licence payante, à remplacer par `pypdfium2`. Le GPL et le
LGPL restent un arbitrage humain selon le mode de livraison. Les motifs sont
ancrés pour que la règle AGPL n'attrape pas le GPL au passage ; un test le
vérifie.

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
# puis passer l'action en mode: bloquant dans son workflow et redéplacer v1
```

### Ajouter un contrôle à un ruleset déjà créé

Ne pas relancer `creer-ruleset.sh`, qui échouerait sur un doublon de nom. La
liste des workflows imposés vit dans `scripts/ruleset-commun.sh`, partagée
entre création et mise à jour pour qu'un contrôle ajouté d'un côté ne manque
jamais de l'autre.

**L'ordre compte.** Le ruleset référence les workflows par le tag `v1` : le
mettre à jour avant d'avoir déplacé le tag le ferait pointer vers un fichier
inexistant, et le check échouerait sur toutes les pull requests de
l'organisation. `maj-ruleset.sh` refuse de s'exécuter dans ce cas.

```bash
# 1. fusionner la pull request qui ajoute le workflow
git checkout main && git pull
git tag -f v1 && git push -f origin v1   # 2. deplacer le tag
./scripts/maj-ruleset.sh                 # 3. imposer le nouveau controle
```

## Développement

Les scripts sont appelés en ligne de commande depuis une étape de workflow,
jamais importés comme un paquet. Les tests se lancent donc depuis le dossier de
l'action, ce qui reproduit la façon dont le script est réellement chargé.

```bash
for dossier in actions/commun actions/licence-scan actions/secaudit-code actions/cve-scan; do
  (cd "$dossier" && uv run --no-project --with pyyaml --with pytest python -m pytest -q)
done

uv run --no-project --with ruff ruff check actions/
uv run --no-project --with ruff ruff format --check actions/
```
