#!/usr/bin/env bash
#
# Fait passer un ruleset de conformité au mode d'application demandé : « active »
# par défaut (depuis « evaluate »), ou « disabled » pour un retour arrière,
# ou « evaluate ».
#
# C'est ce qui MET EN SERVICE le scan, pas ce qui le rend bloquant : en mode
# evaluate GitHub journalise la règle sans exécuter les workflows, donc rien ne
# tourne. Le blocage, lui, dépend de l'entrée `mode` de l'action, qui vaut
# `observation` par défaut, ou de l'étape elle-même.
#
# Prérequis : scope admin:org.
#
# Usage :
#   ./scripts/activer-ruleset.sh             # active
#   ./scripts/activer-ruleset.sh disabled    # retour arrière

set -euo pipefail

# shellcheck source=scripts/ruleset-commun.sh
source "$(dirname "${BASH_SOURCE[0]}")/ruleset-commun.sh"

nom="$NOM_RULESET"
mode="${1:-active}"
if [ "$#" -gt 1 ]; then
  echo "Usage : $0 [active|evaluate|disabled]" >&2
  exit 2
fi
case "$mode" in
  active | evaluate | disabled) ;;
  *)
    echo "Mode inconnu : « $mode » (attendu : active, evaluate ou disabled)" >&2
    exit 2
    ;;
esac

identifiant=$(gh api "orgs/${ORG}/rulesets" --paginate --jq ".[] | select(.name == \"${nom}\") | .id")

if [ -z "$identifiant" ]; then
  echo "Ruleset « ${nom} » introuvable. Lancer d'abord ./scripts/creer-ruleset.sh" >&2
  exit 1
fi

echo "Passage du ruleset ${identifiant} « ${nom} » en mode ${mode}..."
gh api -X PUT "orgs/${ORG}/rulesets/${identifiant}" -f enforcement="${mode}" --jq '{id, name, enforcement}'

echo
if [ "$mode" = active ]; then
  echo "Le scan s'execute maintenant sur les pull requests de l'organisation."
  echo
  echo "Pour rendre un scan de conformite.yml bloquant, une fois le bruit mesure :"
  echo "  1. mode: bloquant sur l'etape voulue de .github/workflows/conformite.yml"
  echo "  2. git tag -f v2 && git push -f origin v2"
fi
