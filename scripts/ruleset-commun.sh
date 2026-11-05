#!/usr/bin/env bash
#
# Definition partagee des DEUX rulesets de conformite : ce qu'ils ciblent et
# quels workflows ils imposent. Sourcé par creer-ruleset.sh, maj-ruleset.sh et
# activer-ruleset.sh.
#
# Deux rulesets, choisis par une cle (`conformite` ou `secrets`) :
# - « Conformité Baseline » impose conformite.yml (les controles complets) sur la
#   branche par defaut seulement ;
# - « Secrets Baseline » impose secrets.yml (gitleaks seul, sur le diff) sur
#   TOUTES les branches.
# Decision du Directeur general du 2026-11-05. Le partage est fait par les
# rulesets et non par une condition dans le workflow : un workflow qui choisit
# son mode d'apres `base_ref` se contourne en reciblant la pull request.
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
NOM_RULESET_SECRETS="Secrets Baseline"

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

# Workflows imposes par chaque ruleset, par chemin dans ce depot-ci.
#
# Un SEUL job par workflow. conformite.yml porte les cinq controles comme etapes
# nommees du meme job, parce qu'un job est facture a la minute ENTIERE : quatre
# jobs pour 217 secondes de calcul cumule coutaient six minutes la ou quatre
# suffisent. Mesure sur aout 2026, 68 depots actifs, 340 commits : 1233 minutes
# facturees contre 843 une fois reunies, soit 32 % de moins sans retirer un
# controle. secrets.yml ne porte que le scan des secrets.
WORKFLOWS_CONFORMITE=(
  ".github/workflows/conformite.yml"
)
WORKFLOWS_SECRETS=(
  ".github/workflows/secrets.yml"
)

# Emet le tableau JSON `rules` d'un ruleset : regles_workflows <cle>.
regles_workflows() {
  local entrees=()
  local chemin
  while IFS= read -r chemin; do
    entrees+=("$(jq -nc \
      --argjson id "$DEPOT_SOURCE_ID" \
      --arg path "$chemin" \
      --arg ref "$REF" \
      '{repository_id: $id, path: $path, ref: $ref}')")
  done < <(workflows_ruleset "${1:?cle de ruleset attendue}")
  jq -nc --argjson w "$(printf '%s\n' "${entrees[@]}" | jq -sc '.')" \
    '[{type: "workflows", parameters: {workflows: $w}}]'
}

# Branches ciblees, par ruleset.
#
# « Conformité Baseline » : `~DEFAULT_BRANCH` SEULEMENT, la promotion vers la
# production. Il visait aussi `refs/heads/develop` (le 2026-09-01, cogniflo
# n'etait couvert par AUCUN scan : tout son travail passait par `develop`).
# Cette couverture est desormais assuree par « Secrets Baseline », qui vise
# toutes les branches : les controles complets ne sont plus rejoues a chaque
# pull request vers `develop`, seulement a la promotion.
#
# « Secrets Baseline » : `~ALL`, donc toute branche existante, `develop`
# comprise. GitHub n'evalue la regle que sur les refs qui existent.
BRANCHES_CONFORMITE=(
  "~DEFAULT_BRANCH"
)
BRANCHES_SECRETS=(
  "~ALL"
)

# Les trois fonctions suivantes traduisent une cle de ruleset (`conformite` ou
# `secrets`) vers sa definition. Une cle inconnue est une erreur, jamais un
# defaut silencieux : appliquer la definition d'un ruleset a l'autre
# remplacerait son perimetre sans prevenir.
nom_ruleset() {
  case "$1" in
    conformite) echo "$NOM_RULESET" ;;
    secrets) echo "$NOM_RULESET_SECRETS" ;;
    *) echo "Ruleset inconnu : « $1 » (attendu : conformite ou secrets)" >&2; return 1 ;;
  esac
}

workflows_ruleset() {
  case "$1" in
    conformite) printf '%s\n' "${WORKFLOWS_CONFORMITE[@]}" ;;
    secrets) printf '%s\n' "${WORKFLOWS_SECRETS[@]}" ;;
    *) echo "Ruleset inconnu : « $1 » (attendu : conformite ou secrets)" >&2; return 1 ;;
  esac
}

branches_ruleset() {
  case "$1" in
    conformite) printf '%s\n' "${BRANCHES_CONFORMITE[@]}" ;;
    secrets) printf '%s\n' "${BRANCHES_SECRETS[@]}" ;;
    *) echo "Ruleset inconnu : « $1 » (attendu : conformite ou secrets)" >&2; return 1 ;;
  esac
}

# Emet l'objet `conditions` d'un ruleset : le perimetre, exclusions comprises.
# conditions_ruleset <cle>. Les deux rulesets ont les memes exclusions de depots.
conditions_ruleset() {
  jq -nc \
    --argjson exclus "$(printf '%s\n' "${EXCLUS[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')" \
    --argjson branches "$(branches_ruleset "${1:?cle de ruleset attendue}" | jq -Rsc 'split("\n") | map(select(. != ""))')" \
    '{
      ref_name: { include: $branches, exclude: [] },
      repository_name: { include: ["~ALL"], exclude: $exclus }
    }'
}

# Emet la charge utile complete de creation d'un ruleset :
# charge_ruleset <cle> [enforcement].
charge_ruleset() {
  local cle="${1:?cle de ruleset attendue}"
  local enforcement="${2:-evaluate}"
  jq -nc \
    --arg name "$(nom_ruleset "$cle")" \
    --arg enforcement "$enforcement" \
    --argjson conditions "$(conditions_ruleset "$cle")" \
    --argjson rules "$(regles_workflows "$cle")" \
    '{
      name: $name,
      target: "branch",
      enforcement: $enforcement,
      conditions: $conditions,
      rules: $rules
    }'
}
