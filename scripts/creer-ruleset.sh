#!/usr/bin/env bash
#
# Crée le ruleset organisationnel « Conformité Baseline » : il impose
# conformite.yml à tous les dépôts de Baseline-quebec, sur la branche par défaut
# seulement (voir ruleset-commun.sh).
#
# Prérequis : un jeton avec le scope admin:org.
#   gh auth refresh -h github.com -s admin:org
#
# Le mode d'application par défaut est « evaluate » : contre-intuitif mais
# vérifié, GitHub y journalise la règle SANS jamais exécuter les workflows, donc
# le scan ne tourne pas du tout. Pour qu'un ruleset NEUF s'applique tout de
# suite, demander `ENFORCEMENT=active`, ou lancer ./scripts/activer-ruleset.sh.
#
# Idempotent : si un ruleset de ce nom existe déjà, rien n'est créé et le
# script s'arrête sans erreur. Pour modifier un ruleset existant (workflows ou
# cibles), utiliser ./scripts/maj-ruleset.sh.
#
# Le workflow visé doit exister sous le tag de REF avant la création : sinon le
# check échouerait sur toutes les pull requests de l'organisation.
#
# Usage :
#   ./scripts/creer-ruleset.sh                     # crée en mode evaluate
#   ENFORCEMENT=active ./scripts/creer-ruleset.sh  # crée actif
#   DRY_RUN=1 ./scripts/creer-ruleset.sh           # affiche sans créer

set -euo pipefail

# shellcheck source=scripts/ruleset-commun.sh
source "$(dirname "${BASH_SOURCE[0]}")/ruleset-commun.sh"

# Aucun argument : il n'existe plus qu'un ruleset. Un argument (par exemple
# l'ancienne clé « secrets ») est une erreur, avant tout appel gh.
if [ "$#" -ne 0 ]; then
  echo "Usage : $0 (aucun argument, un seul ruleset : « ${NOM_RULESET} »)" >&2
  exit 2
fi
nom="$NOM_RULESET"
charge_utile=$(charge_ruleset "${ENFORCEMENT:-evaluate}")

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "$charge_utile" | jq '.'
  exit 0
fi

existant=$(gh api "orgs/${ORG}/rulesets" --paginate --jq ".[] | select(.name == \"${nom}\") | .id")
if [ -n "$existant" ]; then
  echo "Le ruleset « ${nom} » existe déjà (id ${existant}) : rien créé."
  echo "Pour le modifier : ./scripts/maj-ruleset.sh"
  exit 0
fi

tag="${REF#refs/tags/}"
while IFS= read -r chemin; do
  if ! gh api "repos/${ORG}/.github/contents/${chemin}?ref=${tag}" --silent 2>/dev/null; then
    echo "Absent du tag ${tag} : ${chemin}" >&2
    echo "Fusionner la pull request puis déplacer le tag avant de créer le ruleset :" >&2
    echo "  git tag -f ${tag} && git push -f origin ${tag}" >&2
    exit 1
  fi
done < <(printf '%s\n' "${WORKFLOWS[@]}")

echo "Création du ruleset « ${nom} » sur ${ORG} (${ENFORCEMENT:-evaluate})..."
echo "$charge_utile" | gh api -X POST "orgs/${ORG}/rulesets" --input - --jq '{id, name, enforcement}'

echo
if [ "${ENFORCEMENT:-evaluate}" = "evaluate" ]; then
  echo "Fait. Attention : en mode evaluate le scan ne s'execute PAS du tout."
  echo "Lancer ./scripts/activer-ruleset.sh pour qu'il tourne."
else
  echo "Fait. Le ruleset est actif."
fi
echo "Vérifier les exécutions dans quelques jours :"
echo "  gh api orgs/${ORG}/rulesets --jq '.[] | {id, name, enforcement}'"
echo
echo "Rappel : la règle « workflows » BLOQUE les pushs directs sur les branches"
echo "qu'elle cible (doc GitHub, « Require workflows to pass before merging »)."
echo "Ne la viser que sur des branches alimentées par pull request seulement,"
echo "jamais sur toutes les branches. Elle écoute pull_request et merge_group."
