#!/usr/bin/env bash
#
# Lance semgrep, trivy et checkov, en parallele quand c'est plus court.
#
# Pourquoi : profil de « Auditer le code » sur cogniflo, 2026-10-22, quatre
# executions : semgrep 144 s, checkov 52 s, trivy 12 s, l'un apres l'autre.
# Aucun ne depend d'un autre, chacun ecrit son propre rapport : trivy et checkov
# tournent toujours ensemble, et semgrep les rejoint quand il est incremental.
# L'analyse complete de semgrep, elle, passe seule d'abord (mesure plus bas).
#
# semgrep est INCREMENTAL quand BASE_SEMGREP est fourni (pull request) : il ne
# rapporte que les constats introduits depuis cette base (`--baseline-commit`).
# Mesure locale sur cogniflo : 119 s complet, 5 s incremental. Sans base
# (merge_group, push, appel manuel), l'analyse reste complete. Toute
# impossibilite de l'incremental retombe sur l'analyse complete, jamais sur
# « rien » : un raccourci qui echoue ne doit pas devenir un scan saute.
#
# Chaque outil se termine comme avant par un statut ignore : un scanner qui
# plante n'emporte pas les autres, et c'est rapport.py qui signale son rapport
# manquant comme muet.
#
# Entrees (environnement) :
#   RAPPORTS      dossier des rapports JSON et de _outils.log (obligatoire)
#   SOURCE        sous-repertoire a analyser, relatif a la racine (defaut .)
#   IAC           oui pour lancer checkov
#   BASE_SEMGREP  `fusion` (premier parent du commit de fusion de test d'une
#                 pull request) ou SHA d'un ancetre de HEAD ; vide pour
#                 l'analyse complete
#
# Le script s'execute depuis la racine du depot (le checkout).

# Les fonctions sont lancees indirectement, par `chronometrer` : SC2329 ne le voit pas.
# shellcheck disable=SC2329

set -uo pipefail

: "${RAPPORTS:?RAPPORTS est obligatoire}"
SOURCE="${SOURCE:-.}"
IAC="${IAC:-non}"
BASE_SEMGREP="${BASE_SEMGREP:-}"

racine="$PWD"
journaux="$(mktemp -d)"

semgrep_lancer() {
  uv run --no-project --with semgrep==1.175.0 semgrep scan \
    --config auto --json --output "$RAPPORTS/semgrep.json" --quiet "$@" .
}

semgrep_complet() {
  (cd "$racine/$SOURCE" && semgrep_lancer)
}

# Rend les parents de HEAD disponibles : le checkout est superficiel (une seule
# revision), et semgrep calcule une base de fusion, ce qui exige l'historique
# entre la base et HEAD. Deux revisions suffisent quand la base est un parent.
approfondir() {
  git -C "$racine" fetch --no-tags --quiet --depth=2 origin "$(git -C "$racine" rev-parse HEAD)"
}

# Ecrit sur la sortie le SHA de la base a utiliser, ou echoue.
#
# `fusion` designe le premier parent du commit de fusion de test qu'une pull
# request extrait : exactement la branche cible au moment de l'analyse. C'est la
# valeur a preferer. `pull_request.base.sha` est fige a l'ouverture ou a la
# derniere synchronisation, et la branche cible a souvent avance depuis : mesure
# sur cogniflo le 2026-10-22, la base de l'evenement n'etait plus dans les deux
# revisions extraites, et l'analyse retombait sur le scan complet. Un HEAD qui
# n'est pas un commit de fusion est refuse : son premier parent ne serait que
# le commit precedent, et l'incremental ignorerait tout le reste de la branche.
#
# Un SHA explicite est accepte s'il est un ancetre de HEAD.
resoudre_base() {
  local demande="$1"
  if [ "$demande" = fusion ]; then
    git -C "$racine" rev-parse --verify --quiet "HEAD^2^{commit}" >/dev/null 2>&1 \
      || approfondir || return 1
    git -C "$racine" rev-parse --verify --quiet "HEAD^2^{commit}" >/dev/null || return 1
    git -C "$racine" rev-parse --verify --quiet "HEAD^1^{commit}"
    return
  fi
  if ! git -C "$racine" merge-base --is-ancestor "$demande" HEAD 2>/dev/null; then
    approfondir || return 1
  fi
  git -C "$racine" merge-base --is-ancestor "$demande" HEAD 2>/dev/null || return 1
  echo "$demande"
}

# semgrep fait un `git reset --hard` vers la base quand l'arbre de travail est
# propre. Dans le checkout partage, trivy et checkov liraient alors, pendant ce
# temps, les fichiers de la BASE au lieu de ceux de la pull request : des
# constats perdus en silence. L'incremental tourne donc dans un arbre de travail
# a part, jete ensuite.
semgrep_incremental() {
  local base="$1" arbre statut
  arbre="$(mktemp -d)"
  rmdir "$arbre"
  git -C "$racine" worktree add --detach --quiet "$arbre" HEAD || return 1
  (cd "$arbre/$SOURCE" && semgrep_lancer --baseline-commit "$base")
  statut=$?
  git -C "$racine" worktree remove --force "$arbre" || true
  return "$statut"
}

# INCREMENTAL est decide avant le lancement (voir plus bas) : oui seulement si
# une base est fournie ET disponible.
semgrep_analyser() {
  if [ "$INCREMENTAL" = oui ]; then
    if semgrep_incremental "$BASE_RESOLUE"; then
      echo "semgrep : analyse incrementale depuis $BASE_RESOLUE ($BASE_SEMGREP)"
      return 0
    fi
    rm -f "$RAPPORTS/semgrep.json"
  fi
  if [ -n "$BASE_SEMGREP" ]; then
    echo "::notice title=semgrep::Analyse incrementale impossible depuis $BASE_SEMGREP, analyse complete."
  fi
  echo "semgrep : analyse complete"
  semgrep_complet
}

# --scanners misconfig,secret : les vulnerabilites de dependances sont la charge
# de cve-scan, qui lit les fichiers de verrouillage. Les compter aux deux
# endroits ferait apparaitre la meme CVE dans deux rapports, avec deux verdicts
# possibles selon l'outil qui l'a vue.
trivy_analyser() {
  docker run --rm \
    -v "$racine/$SOURCE":/src:ro -v "$RAPPORTS":/out \
    aquasec/trivy:0.74.0 filesystem \
    --scanners misconfig,secret --format json --output /out/trivy.json \
    --exit-code 0 --no-progress /src
}

checkov_analyser() {
  (cd "$racine/$SOURCE" && uv run --no-project --with checkov==3.3.16 checkov \
    --directory . --output json --quiet --compact > "$RAPPORTS/checkov.json")
}

# Chaque outil note sa propre duree dans son journal : c'est ce qui permettra
# de refaire le profil sans relancer les outils un par un.
chronometrer() {
  local outil="$1" debut="$SECONDS" statut
  shift
  "$@"
  statut=$?
  echo "$outil : $((SECONDS - debut)) s, statut $statut" >&2
  return "$statut"
}

INCREMENTAL=non
BASE_RESOLUE=""
if [ -n "$BASE_SEMGREP" ] && BASE_RESOLUE="$(resoudre_base "$BASE_SEMGREP")"; then
  INCREMENTAL=oui
fi

# L'analyse COMPLETE de semgrep tourne seule, avant les deux autres. Mesure sur
# cogniflo le 2026-10-22, runner a 2 vCPU : seule, 116 s ; en parallele avec
# checkov et trivy, 226 s et 236 s sur deux executions, soit une etape plus
# longue qu'en sequence (238 s contre 203 s). semgrep occupe deja tous les
# coeurs, et le partage le ralentit plus qu'il ne fait gagner aux autres.
# L'incremental, lui, est court (23 s) : il tourne avec les deux autres.
declare -A pids=()
if [ "$INCREMENTAL" = oui ]; then
  chronometrer semgrep semgrep_analyser >"$journaux/semgrep.log" 2>&1 &
  pids[semgrep]=$!
else
  chronometrer semgrep semgrep_analyser >"$journaux/semgrep.log" 2>&1
fi
chronometrer trivy trivy_analyser >"$journaux/trivy.log" 2>&1 &
pids[trivy]=$!
if [ "$IAC" = oui ]; then
  # La sortie standard de checkov EST son rapport, redirigee dans checkov_analyser :
  # seul stderr va au journal.
  chronometrer checkov checkov_analyser 2>"$journaux/checkov.log" &
  pids[checkov]=$!
fi

# Les journaux sont recopies dans un ordre fixe, un outil apres l'autre : ecrits
# en parallele dans le meme fichier, ils s'entrelaceraient ligne a ligne.
for outil in semgrep trivy checkov; do
  [ -f "$journaux/$outil.log" ] || continue
  [ -z "${pids[$outil]:-}" ] || wait "${pids[$outil]}"
  {
    echo "===== $outil ====="
    cat "$journaux/$outil.log"
  } >>"$RAPPORTS/_outils.log"
done
# Le mode de semgrep, son eventuel repli et la duree de chaque outil sont remis
# dans la sortie de l'etape : une annotation ecrite dans un fichier n'apparait
# nulle part, et le repli vers l'analyse complete doit se voir.
for outil in semgrep trivy checkov; do
  [ -f "$journaux/$outil.log" ] || continue
  grep -hE '^(::notice|semgrep : analyse|[a-z]+ : [0-9]+ s, statut)' "$journaux/$outil.log" || true
done
rm -rf "$journaux"
exit 0
