#!/usr/bin/env bash
#
# Definition partagee du ruleset de conformite : ce qu'il cible et quels
# workflows il impose. Sourcé par creer-ruleset.sh et maj-ruleset.sh.
#
# La liste des workflows vit ici et nulle part ailleurs. Deux copies, une pour
# la creation et une pour la mise a jour, finiraient par diverger : le jour ou
# quelqu'un ajoute un controle a une seule des deux, le ruleset recree apres un
# incident perdrait silencieusement un controle.

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

# Workflows imposes a tous les depots cibles, par chemin dans ce depot-ci.
#
# Un SEUL workflow depuis v2. Les quatre scans y sont des etapes nommees du
# meme job, parce qu'un job est facture a la minute ENTIERE : quatre jobs pour
# 217 secondes de calcul cumule coutaient six minutes la ou quatre suffisent.
# Mesure sur aout 2026, 68 depots actifs, 340 commits : 1233 minutes facturees
# contre 843 une fois reunies, soit 32 % de moins sans retirer un controle.
WORKFLOWS=(
  ".github/workflows/conformite.yml"
)

# Emet le tableau JSON `rules` du ruleset.
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
    '[{type: "workflows", parameters: {workflows: $w}}]'
}

# Branches ciblees.
#
# `~DEFAULT_BRANCH` ne suffit pas. Le 2026-09-01, cogniflo n'etait couvert par
# AUCUN scan : sa branche par defaut est `main`, mais tout son travail passe par
# `develop` et ses huit dernieres pull requests y allaient toutes. `main` ne
# bouge que par une fusion periodique de `develop`, donc les seules pull
# requests scannees etaient celles que personne ne relit ligne par ligne.
#
# Nommer `refs/heads/develop` couvre le modele « une branche d'integration
# devant la branche par defaut » sans obliger chaque depot a se conformer a un
# seul flux de travail. Un depot sans `develop` n'est pas affecte : GitHub
# n'evalue la regle que sur les refs qui existent.
#
# baseline-automation porte une branche `dev` et non `develop`, mais ses pull
# requests visent `main` : elle est deja couverte, et ajouter `dev` ici
# imposerait des checks sur une branche que plus rien n'alimente.
BRANCHES=(
  "~DEFAULT_BRANCH"
  "refs/heads/develop"
)

# Emet l'objet `conditions` du ruleset : le perimetre, exclusions comprises.
conditions_ruleset() {
  jq -nc \
    --argjson exclus "$(printf '%s\n' "${EXCLUS[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')" \
    --argjson branches "$(printf '%s\n' "${BRANCHES[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')" \
    '{
      ref_name: { include: $branches, exclude: [] },
      repository_name: { include: ["~ALL"], exclude: $exclus }
    }'
}

# Emet la charge utile complete de creation du ruleset.
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
