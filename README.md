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
seule source de vérité. Trivy sert uniquement à extraire la licence de chaque
dépendance ; la classification est faite par `report.py`, pas par les catégories
de Trivy, qui ne connaissent ni BUSL, ni SSPL, ni PolyForm.

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

## Deux pièges qui font passer un scan pour vert

**L'installation est obligatoire.** Trivy lit la licence dans les fichiers
`METADATA` des paquets **installés**, pas dans `uv.lock` ni `poetry.lock`. Un
dépôt scanné sans installation retourne zéro licence, ce qui ressemble à un
succès. L'action installe donc les dépendances avant de scanner, et le rapport
dit explicitement quand il n'a rien trouvé à analyser.

**`BSL-1.0` n'est pas `BSL-1.1`.** La première est la Boost Software License,
permissive. La seconde est un alias courant de la Business Source License,
restrictive. Les motifs de la politique sont ancrés pour ne jamais les
confondre ; un test le vérifie.

## Gestionnaires reconnus

Python : `uv.lock`, `poetry.lock`, `requirements.txt`.
Node : `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`.

Un dépôt sans aucun de ces fichiers produit un rapport vide et un job vert.

## Mise en service

Le déploiement se fait en deux temps volontairement séparés.

1. **Mode observation.** L'action tourne avec `mode: observation` et le ruleset
   est en application `Evaluate`. Rien n'est bloqué, tout est journalisé. Sert à
   mesurer le volume réel de violations sur les 82 dépôts et à curer les faux
   positifs avant d'imposer quoi que ce soit.
2. **Mode bloquant.** Une fois le bruit maîtrisé, passer l'action en
   `mode: bloquant` et le ruleset en `Active`.

```bash
gh auth refresh -h github.com -s admin:org   # une seule fois

./scripts/creer-ruleset.sh          # étape 1 : evaluate, rien n'est bloqué
./scripts/activer-ruleset.sh        # étape 2 : blocage réel
```

## Développement

```bash
cd actions/licence-scan
uv run --no-project --with pyyaml --with pytest python -m pytest test_report.py -q
```
