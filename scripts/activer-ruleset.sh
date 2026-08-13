#!/usr/bin/env bash
#
# Fait passer le ruleset de conformité du mode « evaluate » au mode « active ».
#
# C'est ce qui MET EN SERVICE le scan, pas ce qui le rend bloquant : en mode
# evaluate GitHub journalise la règle sans exécuter les workflows, donc rien ne
# tourne. Le blocage, lui, dépend de l'entrée `mode` de l'action, qui vaut
# `observation` par défaut et rend le job incapable d'échouer.
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

echo "Passage du ruleset ${identifiant} en mode active..."
gh api -X PUT "orgs/${ORG}/rulesets/${identifiant}" -f enforcement=active --jq '{id, name, enforcement}'

echo
echo "Le scan s'execute maintenant sur les pull requests de l'organisation."
echo "Il ne bloque rien tant que l'action reste en mode observation."
echo
echo "Pour rendre le scan bloquant, une fois le bruit mesure et cure :"
echo "  1. mode: bloquant dans .github/workflows/licence-scan.yml"
echo "  2. git tag -f v1 && git push -f origin v1"
