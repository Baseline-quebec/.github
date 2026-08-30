#!/usr/bin/env bash
#
# Met a jour la liste des workflows imposes par le ruleset de conformite, sans
# toucher a son mode d'application ni a son perimetre.
#
# A lancer apres avoir ajoute un controle dans WORKFLOWS (ruleset-commun.sh),
# fusionne la pull request et DEPLACE LE TAG v1. Dans l'autre ordre, le ruleset
# pointerait vers un fichier qui n'existe pas encore sous ce tag, et GitHub
# echouerait le check sur toutes les pull requests de l'organisation.
#
# Prérequis : un jeton avec le scope admin:org.
#   gh auth refresh -h github.com -s admin:org
#
# Usage :
#   ./scripts/maj-ruleset.sh              # applique
#   DRY_RUN=1 ./scripts/maj-ruleset.sh    # montre le diff sans rien changer

set -euo pipefail

# shellcheck source=scripts/ruleset-commun.sh
source "$(dirname "${BASH_SOURCE[0]}")/ruleset-commun.sh"

identifiant=$(gh api "orgs/${ORG}/rulesets" --jq ".[] | select(.name == \"${NOM_RULESET}\") | .id")

if [ -z "$identifiant" ]; then
  echo "Ruleset « ${NOM_RULESET} » introuvable. Lancer d'abord ./scripts/creer-ruleset.sh" >&2
  exit 1
fi

actuel=$(gh api "orgs/${ORG}/rulesets/${identifiant}" \
  --jq '[.rules[] | select(.type == "workflows") | .parameters.workflows[].path] | sort')
vise=$(regles_workflows | jq -c '[.[0].parameters.workflows[].path] | sort')

echo "Ruleset ${identifiant} « ${NOM_RULESET} »"
echo "  workflows actuels : $actuel"
echo "  workflows visés   : $vise"

if [ "$actuel" = "$vise" ]; then
  echo "Rien a changer."
  exit 0
fi

# Verifie que chaque workflow vise existe bien sous le tag reference. Sans ce
# garde-fou, une faute de frappe dans un chemin ferait echouer le check sur
# toutes les pull requests de l'organisation, avec pour seul symptome un
# workflow « introuvable ».
tag="${REF#refs/tags/}"
for chemin in "${WORKFLOWS[@]}"; do
  if ! gh api "repos/${ORG}/.github/contents/${chemin}?ref=${tag}" --silent 2>/dev/null; then
    echo "Absent du tag ${tag} : ${chemin}" >&2
    echo "Deplacer le tag avant de mettre a jour le ruleset :" >&2
    echo "  git tag -f ${tag} && git push -f origin ${tag}" >&2
    exit 1
  fi
done

if [ "${DRY_RUN:-0}" = "1" ]; then
  regles_workflows | jq '.'
  exit 0
fi

echo "Mise a jour..."
jq -nc --argjson rules "$(regles_workflows)" '{rules: $rules}' |
  gh api -X PUT "orgs/${ORG}/rulesets/${identifiant}" --input - \
    --jq '{id, name, enforcement, workflows: [.rules[] | select(.type == "workflows") | .parameters.workflows[].path]}'

echo
echo "Fait. Les nouveaux controles s'executent sur les pull requests de"
echo "l'organisation. Ils ne bloquent rien tant que leur action reste en mode"
echo "observation."
