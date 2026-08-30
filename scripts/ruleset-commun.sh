#!/usr/bin/env bash
#
# Definition partagee du ruleset de conformite : ce qu'il cible et quels
# workflows il impose. Sourcé par creer-ruleset.sh et maj-ruleset.sh.
#
# La liste des workflows vit ici et nulle part ailleurs. Deux copies, une pour
# la creation et une pour la mise a jour, finiraient par diverger : le jour ou
# quelqu'un ajoute un controle a une seule des deux, le ruleset recree apres un
# incident perdrait silencieusement un controle.

ORG="Baseline-quebec"
DEPOT_SOURCE_ID="1333554887" # Baseline-quebec/.github
REF="refs/tags/v1"
NOM_RULESET="Conformité Baseline"

# Workflows imposes a tous les depots cibles, par chemin dans ce depot-ci.
WORKFLOWS=(
  ".github/workflows/licence-scan.yml"
  ".github/workflows/llm-scan.yml"
  ".github/workflows/secaudit-code.yml"
  ".github/workflows/cve-scan.yml"
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

# Emet la charge utile complete de creation du ruleset.
#
# tracking-llm-discontinued est exclu, et l'exclusion n'est pas cosmetique :
# son registre contient l'identifiant de chaque modele deprecie connu, donc y
# lancer le scanner produit une issue par modele. Constate en production, 182
# issues en une execution.
charge_ruleset() {
  local enforcement="${1:-evaluate}"
  jq -nc \
    --arg name "$NOM_RULESET" \
    --arg enforcement "$enforcement" \
    --argjson rules "$(regles_workflows)" \
    '{
      name: $name,
      target: "branch",
      enforcement: $enforcement,
      conditions: {
        ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] },
        repository_name: { include: ["~ALL"], exclude: ["tracking-llm-discontinued"] }
      },
      rules: $rules
    }'
}
