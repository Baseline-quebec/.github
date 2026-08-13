#!/usr/bin/env bash
#
# Ajoute la règle « exiger une pull request » au ruleset de conformité.
#
# Pourquoi c'est nécessaire : la règle GitHub qui impose un workflow n'écoute
# que pull_request et merge_group, et ces déclencheurs ne sont pas
# configurables. Un push direct vers la branche par défaut échappe donc
# complètement au scan de licences. Interdire le push direct est la seule façon
# de fermer ce trou.
#
# Effet de bord assumé : plus personne ne peut committer directement sur la
# branche par défaut, sauf les acteurs listés en dérogation.
#
# Prérequis : scope admin:org.

set -euo pipefail

ORG="Baseline-quebec"
NOM_RULESET="Conformité Baseline"

identifiant=$(gh api "orgs/${ORG}/rulesets" --jq ".[] | select(.name == \"${NOM_RULESET}\") | .id")

if [ -z "$identifiant" ]; then
  echo "Ruleset « ${NOM_RULESET} » introuvable. Lancer d'abord ./scripts/creer-ruleset.sh" >&2
  exit 1
fi

# On récupère les règles existantes pour ajouter la nouvelle sans écraser
# l'imposition des workflows.
regles=$(gh api "orgs/${ORG}/rulesets/${identifiant}" --jq '.rules')
nouvelles=$(
  echo "$regles" | jq '. + [{
    "type": "pull_request",
    "parameters": {
      "required_approving_review_count": 0,
      "dismiss_stale_reviews_on_push": false,
      "require_code_owner_review": false,
      "require_last_push_approval": false,
      "required_review_thread_resolution": false,
      "automatic_copilot_code_review_enabled": false,
      "allowed_merge_methods": ["merge", "squash", "rebase"]
    }
  }]'
)

echo "Ajout de la règle pull_request au ruleset ${identifiant}..."
jq -n --argjson rules "$nouvelles" '{rules: $rules}' |
  gh api -X PUT "orgs/${ORG}/rulesets/${identifiant}" --input - --jq '{id, name, enforcement}'

echo
echo "Fait. Le push direct vers la branche par défaut est maintenant interdit"
echo "sur les dépôts ciblés, et toute modification passe par une pull request"
echo "donc par le scan de licences."
