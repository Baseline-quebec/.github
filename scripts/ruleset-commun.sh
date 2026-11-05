#!/usr/bin/env bash
#
# Definition partagee du ruleset de conformite : ce qu'il cible et quel workflow
# il impose. Sourcé par creer-ruleset.sh, maj-ruleset.sh et activer-ruleset.sh.
#
# Un seul ruleset, « Conformité Baseline » : il impose conformite.yml (les
# controles complets, gitleaks sur l'arbre compris) sur la branche par defaut
# SEULEMENT. Decision du DG (2026-11-05) : controles complets seulement avant la
# branche par defaut. Ajustee le meme jour par le responsable DevOps : les
# secrets sont arretes au pre-commit de chaque depot, sans check d'organisation
# vers develop (une pull request vers une autre branche n'en a aucun). La
# promotion vers la branche par defaut est le dernier filet avant la production.
# Trace : INTERNE67-2430.
#
# La definition vit ici et nulle part ailleurs. Deux copies, une pour la
# creation et une pour la mise a jour, finiraient par diverger : le ruleset
# recree apres un incident ne serait plus celui qu'on croyait.

# shellcheck disable=SC2034  # ORG et NOM_RULESET sont lus par les scripts qui sourcent ce fichier.
ORG="Baseline-quebec"
DEPOT_SOURCE_ID="1333554887" # Baseline-quebec/.github
REF="refs/tags/v2"
NOM_RULESET="Conformité Baseline"

# Depots hors perimetre.
#
# tracking-llm-discontinued : son registre contient l'identifiant de chaque
# modele deprecie connu, donc y lancer le scanner de modeles revient a lui faire
# scanner sa propre liste. Constate en production, 182 issues en une execution.
#
# Marketing et Ventes : depots de travail, majoritairement du HTML de sites et
# de presentations (17 Mo et 7 Mo respectivement), pas du code livre. Ils
# etaient deja exclus du ruleset en production alors que ce script ne les
# nommait pas : le script aurait donc reconstruit un perimetre PLUS large que
# le vrai apres un incident. C'est exactement le genre d'ecart qu'un fichier
# cense etre la source de verite ne doit pas porter.
#
# bswh-baylee et serko-northsky : depots hors maintenance Baseline depuis le
# 2026-09-01. Plus personne n'y traite les checks imposes sur les pull
# requests, donc le scan n'a pas de destinataire.
#
# Cette exclusion ne porte QUE sur le scan en pull request. Le balayage mensuel
# de tracking-llm-discontinued continue de couvrir ces deux depots et d'y
# ouvrir des issues : les en sortir demande de les nommer aussi dans le
# --exclude de son workflow org-sweep.yml. C'est delibere ici.
EXCLUS=(
  "tracking-llm-discontinued"
  "Marketing"
  "Ventes"
  "bswh-baylee"
  "serko-northsky"
)

# Workflow impose, par chemin dans ce depot-ci.
#
# Un SEUL job. conformite.yml porte les cinq controles comme etapes nommees du
# meme job, parce qu'un job est facture a la minute ENTIERE : quatre jobs pour
# 217 secondes de calcul cumule coutaient six minutes la ou quatre suffisent.
# Mesure sur aout 2026, 68 depots actifs, 340 commits : 1233 minutes facturees
# contre 843 une fois reunies, soit 32 % de moins sans retirer un controle.
WORKFLOWS=(
  ".github/workflows/conformite.yml"
)

# Branches ciblees : `~DEFAULT_BRANCH` SEULEMENT, la promotion vers la production.
# Le ruleset visait aussi `refs/heads/develop` ; ce n'est plus le cas (decision
# du 2026-11-05). Ne JAMAIS viser `~ALL` ni une branche de travail : la doc GitHub
# de la regle « Require workflows to pass before merging » dit qu'elle BLOQUE les
# pushs directs et ne doit viser que des branches dont tous les changements
# passent par pull request.
BRANCHES=(
  "~DEFAULT_BRANCH"
)

# Emet le tableau JSON `rules`. `do_not_enforce_on_create: true` (parametre de la
# regle `workflows` de l'API) : la creation d'une branche ou d'un depot n'est pas
# bloquee par un check qui ne peut pas encore exister.
regles_workflows() {
  local entrees=()
  local chemin
  for chemin in "${WORKFLOWS[@]}"; do
    entrees+=("$(jq -nc \
      --argjson id "$DEPOT_SOURCE_ID" \
      --arg path "$chemin" \
      --arg ref "$REF" \
      '{repository_id: $id, path: $path, ref: $ref}')")
  done
  jq -nc --argjson w "$(printf '%s\n' "${entrees[@]}" | jq -sc '.')" \
    '[{type: "workflows", parameters: {do_not_enforce_on_create: true, workflows: $w}}]'
}

# Emet l'objet `conditions` : le perimetre, exclusions comprises.
conditions_ruleset() {
  jq -nc \
    --argjson exclus "$(printf '%s\n' "${EXCLUS[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')" \
    --argjson branches "$(printf '%s\n' "${BRANCHES[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')" \
    '{
      ref_name: { include: $branches, exclude: [] },
      repository_name: { include: ["~ALL"], exclude: $exclus }
    }'
}

# Emet la charge utile complete de creation : charge_ruleset [enforcement].
charge_ruleset() {
  local enforcement="${1:-evaluate}"
  jq -nc \
    --arg name "$NOM_RULESET" \
    --arg enforcement "$enforcement" \
    --argjson conditions "$(conditions_ruleset)" \
    --argjson rules "$(regles_workflows)" \
    '{
      name: $name,
      target: "branch",
      enforcement: $enforcement,
      conditions: $conditions,
      rules: $rules
    }'
}
