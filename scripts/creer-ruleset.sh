#!/usr/bin/env bash
#
# Crée le ruleset organisationnel qui impose les workflows de conformité à tous
# les dépôts de Baseline-quebec.
#
# Prérequis : un jeton avec le scope admin:org.
#   gh auth refresh -h github.com -s admin:org
#
# Le ruleset est créé en mode « evaluate », puis doit être passé en « active »
# avec ./scripts/activer-ruleset.sh. Contre-intuitif mais vérifié : en mode
# evaluate, GitHub journalise la règle SANS jamais exécuter les workflows, donc
# le scan ne tourne pas du tout. Ce qui protège le déploiement n'est pas le mode
# du ruleset, c'est l'entrée `mode: observation` de l'action, qui rend le job
# incapable d'échouer.
#
# Usage :
#   ./scripts/creer-ruleset.sh              # crée en mode evaluate
#   DRY_RUN=1 ./scripts/creer-ruleset.sh    # affiche la charge utile sans créer

set -euo pipefail

ORG="Baseline-quebec"
DEPOT_SOURCE_ID="1333554887" # Baseline-quebec/.github
REF="refs/tags/v1"
NOM_RULESET="Conformité Baseline"

charge_utile=$(
  cat <<JSON
{
  "name": "${NOM_RULESET}",
  "target": "branch",
  "enforcement": "evaluate",
  "conditions": {
    "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] },
    "repository_name": { "include": ["~ALL"], "exclude": [] }
  },
  "rules": [
    {
      "type": "workflows",
      "parameters": {
        "workflows": [
          {
            "repository_id": ${DEPOT_SOURCE_ID},
            "path": ".github/workflows/licence-scan.yml",
            "ref": "${REF}"
          },
          {
            "repository_id": ${DEPOT_SOURCE_ID},
            "path": ".github/workflows/llm-scan.yml",
            "ref": "${REF}"
          }
        ]
      }
    }
  ]
}
JSON
)

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "$charge_utile"
  exit 0
fi

echo "Création du ruleset « ${NOM_RULESET} » sur ${ORG} en mode evaluate..."
echo "$charge_utile" | gh api -X POST "orgs/${ORG}/rulesets" --input - --jq '{id, name, enforcement}'

echo
echo "Fait. Attention : en mode evaluate le scan ne s'execute PAS du tout."
echo "Lancer ./scripts/activer-ruleset.sh pour qu'il tourne. L'action reste"
echo "en mode observation, donc rien ne peut bloquer une pull request."
echo "Vérifier les exécutions dans quelques jours :"
echo "  gh api orgs/${ORG}/rulesets --jq '.[] | {id, name, enforcement}'"
echo
echo "Rappel : la règle « workflows » n'écoute que pull_request et merge_group."
echo "Un push direct vers la branche par défaut n'est jamais analysé. Pour"
echo "couvrir ce cas, ajouter la règle pull_request au même ruleset :"
echo "  (deja couvert chez Baseline par un ruleset org existant)"
