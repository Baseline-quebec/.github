#!/usr/bin/env bash
#
# Met a jour un ruleset de conformite existant, retrouve par son NOM : la liste
# de ses workflows et, sur demande, ses branches ciblees. Il ne touche ni a son
# mode d'application ni a ses exclusions de depots.
#
# Deux rulesets (voir ruleset-commun.sh) : `conformite` et `secrets`.
#
# A lancer apres avoir ajoute un controle dans WORKFLOWS_* (ruleset-commun.sh),
# fusionne la pull request et DEPLACE LE TAG v2. Dans l'autre ordre, le ruleset
# pointerait vers un fichier qui n'existe pas encore sous ce tag, et GitHub
# echouerait le check sur toutes les pull requests de l'organisation.
#
# Par defaut seul `rules` est envoye : le perimetre ne peut pas etre ecrase au
# passage. Pour changer les BRANCHES ciblees (par exemple restreindre
# « Conformité Baseline » a la branche par defaut), demander
# `AVEC_CONDITIONS=1` : le script envoie alors aussi `conditions`, les
# conditions vivantes dont seules les branches sont remplacees par celles de
# ruleset-commun.sh (les exclusions reelles sont conservees). Sans ce drapeau, une derive de branches ou
# d'exclusions est seulement signalee.
#
# Idempotent : relance sans effet quand le ruleset est deja conforme.
#
# Prérequis : un jeton avec le scope admin:org.
#   gh auth refresh -h github.com -s admin:org
#
# Usage :
#   ./scripts/maj-ruleset.sh <cle>                        # workflows seulement
#   AVEC_CONDITIONS=1 ./scripts/maj-ruleset.sh <cle>      # workflows et branches
#   DRY_RUN=1 [AVEC_CONDITIONS=1] ./scripts/maj-ruleset.sh <cle>  # sans rien changer

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

vivant=$(gh api "orgs/${ORG}/rulesets/${identifiant}")
actuel=$(jq -c '[.rules[] | select(.type == "workflows") | .parameters.workflows[].path] | sort' <<<"$vivant")
vise=$(regles_workflows "$cle" | jq -c '[.[0].parameters.workflows[].path] | sort')

echo "Ruleset ${identifiant} « ${nom} »"
echo "  workflows actuels : $actuel"
echo "  workflows visés   : $vise"

# Si le perimetre reel a diverge de ce que ce depot declare, alors
# creer-ruleset.sh reconstruirait un ruleset FAUX apres un incident. Le dire
# ici est le seul moment ou quelqu'un regarde les deux cotes.
exclus_vivants=$(jq -c '.conditions.repository_name.exclude // [] | sort' <<<"$vivant")
exclus_declares=$(conditions_ruleset "$cle" | jq -c '.repository_name.exclude | sort')
if [ "$exclus_vivants" != "$exclus_declares" ]; then
  echo
  echo "::warning::Derive de perimetre entre le ruleset et ce depot."
  echo "  exclusions reelles   : $exclus_vivants"
  echo "  exclusions declarees : $exclus_declares"
  echo "  Aligner EXCLUS dans scripts/ruleset-commun.sh, sinon creer-ruleset.sh"
  echo "  reconstruira un perimetre different du vrai. Ce script n'ecrit jamais"
  echo "  les exclusions."
  echo
fi

# Branches ciblees : meme angle mort, donc meme avertissement, sauf si
# AVEC_CONDITIONS=1 les applique. Sans cela, le depot declarerait une branche
# couverte qui ne l'est pas, ce qui est pire qu'une branche oubliee.
branches_vivantes=$(jq -c '.conditions.ref_name.include // [] | sort' <<<"$vivant")
branches_declarees=$(conditions_ruleset "$cle" | jq -c '.ref_name.include | sort')
echo "  branches actuelles : $branches_vivantes"
echo "  branches visées    : $branches_declarees"
conditions_a_changer=false
[ "$branches_vivantes" = "$branches_declarees" ] || conditions_a_changer=true
if [ "$conditions_a_changer" = true ] && [ "${AVEC_CONDITIONS:-0}" != "1" ]; then
  echo
  echo "::warning::Derive de branches entre le ruleset et ce depot."
  echo "  Ce script n'ecrit conditions que sur demande. Pour appliquer :"
  echo "    AVEC_CONDITIONS=1 ./scripts/maj-ruleset.sh ${cle}"
  echo
  conditions_a_changer=false
fi

regles_a_changer=false
[ "$actuel" = "$vise" ] || regles_a_changer=true

if [ "$regles_a_changer" = false ] && [ "$conditions_a_changer" = false ]; then
  echo "Rien a changer."
  exit 0
fi

# Verifie que chaque workflow vise existe bien sous le tag reference. Sans ce
# garde-fou, une faute de frappe dans un chemin ferait echouer le check sur
# toutes les pull requests de l'organisation, avec pour seul symptome un
# workflow « introuvable ». Aussi pour un changement de branches seul : cibler
# plus de branches avec un workflow absent du tag casserait les memes PR.
tag="${REF#refs/tags/}"
while IFS= read -r chemin; do
  if ! gh api "repos/${ORG}/.github/contents/${chemin}?ref=${tag}" --silent 2>/dev/null; then
    echo "Absent du tag ${tag} : ${chemin}" >&2
    echo "Deplacer le tag avant de mettre a jour le ruleset :" >&2
    echo "  git tag -f ${tag} && git push -f origin ${tag}" >&2
    exit 1
  fi
done < <(workflows_ruleset "$cle")

# Corps du PUT : `rules` toujours, `conditions` seulement si demande ET different.
# Les champs omis d'un PUT de ruleset sont laisses tels quels par GitHub : le
# mode d'application n'est jamais envoye.
corps=$(jq -nc --argjson rules "$(regles_workflows "$cle")" '{rules: $rules}')
if [ "$conditions_a_changer" = true ]; then
  # Les conditions VIVANTES, dont seul `ref_name.include` est remplace : les
  # exclusions de depots reelles survivent meme si elles divergent du depot.
  conditions=$(jq -c --argjson b "$branches_declarees" \
    '.conditions | .ref_name.include = $b' <<<"$vivant")
  corps=$(jq -c --argjson c "$conditions" '. + {conditions: $c}' <<<"$corps")
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "$corps" | jq '.'
  exit 0
fi

echo "Mise a jour..."
echo "$corps" |
  gh api -X PUT "orgs/${ORG}/rulesets/${identifiant}" --input - \
    --jq '{id, name, enforcement, branches: .conditions.ref_name.include, workflows: [.rules[] | select(.type == "workflows") | .parameters.workflows[].path]}'

echo
echo "Fait. Les controles s'executent selon la nouvelle definition sur les pull"
echo "requests de l'organisation."
