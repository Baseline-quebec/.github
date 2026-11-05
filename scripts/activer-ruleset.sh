#!/usr/bin/env bash
#
# Fait passer un ruleset de conformité du mode « evaluate » au mode « active ».
#
# C'est ce qui MET EN SERVICE le scan, pas ce qui le rend bloquant : en mode
# evaluate GitHub journalise la règle sans exécuter les workflows, donc rien ne
# tourne. Le blocage, lui, dépend de l'entrée `mode` de l'action, qui vaut
# `observation` par défaut, ou du workflow lui-même (secrets.yml est bloquant).
#
# Prérequis : scope admin:org.
#
# Usage : ./scripts/activer-ruleset.sh <conformite|secrets>

set -euo pipefail

# shellcheck source=scripts/ruleset-commun.sh
source "$(dirname "${BASH_SOURCE[0]}")/ruleset-commun.sh"

cle="${1:-}"
if [ -z "$cle" ]; then
  echo "Usage : $0 <conformite|secrets>" >&2
  exit 2
fi
nom=$(nom_ruleset "$cle")

identifiant=$(gh api "orgs/${ORG}/rulesets" --jq ".[] | select(.name == \"${nom}\") | .id")

if [ -z "$identifiant" ]; then
  echo "Ruleset « ${nom} » introuvable. Lancer d'abord ./scripts/creer-ruleset.sh ${cle}" >&2
  exit 1
fi

echo "Passage du ruleset ${identifiant} « ${nom} » en mode active..."
gh api -X PUT "orgs/${ORG}/rulesets/${identifiant}" -f enforcement=active --jq '{id, name, enforcement}'

echo
echo "Le scan s'execute maintenant sur les pull requests de l'organisation."
echo
echo "Pour rendre un scan de conformite.yml bloquant, une fois le bruit mesure :"
echo "  1. mode: bloquant sur l'etape voulue de .github/workflows/conformite.yml"
echo "  2. git tag -f v2 && git push -f origin v2"
