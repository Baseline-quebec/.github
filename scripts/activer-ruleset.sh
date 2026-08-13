#!/usr/bin/env bash
#
# Fait passer le ruleset de conformité du mode « evaluate » au mode « active ».
# À partir de ce moment, une licence interdite bloque réellement la fusion.
#
# À ne lancer qu'après avoir mesuré le volume réel de violations en mode
# evaluate et curé les faux positifs dans politique.yaml. Activer trop tôt
# bloque des pull requests légitimes et fait perdre confiance dans l'outil.
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
echo "Le scan est maintenant bloquant côté ruleset."
echo "Penser à passer aussi l'action en mode bloquant dans"
echo ".github/workflows/licence-scan.yml (mode: bloquant), puis à redéplacer le tag v1 :"
echo "  git tag -f v1 && git push -f origin v1"
