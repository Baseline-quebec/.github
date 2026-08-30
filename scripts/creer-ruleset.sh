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
# Pour ajouter un controle a un ruleset DEJA cree, ne pas relancer ce script :
# il echouerait sur un doublon de nom. Utiliser ./scripts/maj-ruleset.sh.
#
# Usage :
#   ./scripts/creer-ruleset.sh              # crée en mode evaluate
#   DRY_RUN=1 ./scripts/creer-ruleset.sh    # affiche la charge utile sans créer

set -euo pipefail

# shellcheck source=scripts/ruleset-commun.sh
source "$(dirname "${BASH_SOURCE[0]}")/ruleset-commun.sh"

charge_utile=$(charge_ruleset evaluate)

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "$charge_utile" | jq '.'
  exit 0
fi

echo "Création du ruleset « ${NOM_RULESET} » sur ${ORG} en mode evaluate..."
echo "$charge_utile" | gh api -X POST "orgs/${ORG}/rulesets" --input - --jq '{id, name, enforcement}'

echo
echo "Fait. Attention : en mode evaluate le scan ne s'execute PAS du tout."
echo "Lancer ./scripts/activer-ruleset.sh pour qu'il tourne. Les actions restent"
echo "en mode observation, donc rien ne peut bloquer une pull request."
echo "Vérifier les exécutions dans quelques jours :"
echo "  gh api orgs/${ORG}/rulesets --jq '.[] | {id, name, enforcement}'"
echo
echo "Rappel : la règle « workflows » n'écoute que pull_request et merge_group."
echo "Un push direct vers la branche par défaut n'est jamais analysé. Pour"
echo "couvrir ce cas, ajouter la règle pull_request au même ruleset :"
echo "  (deja couvert chez Baseline par un ruleset org existant)"
