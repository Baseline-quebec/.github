#!/usr/bin/env bash
#
# Lance semgrep, trivy et checkov EN PARALLELE, puis attend les trois.
#
# Pourquoi : profil de « Auditer le code » sur cogniflo, 2026-10-22, quatre
# executions : semgrep 144 s, checkov 52 s, trivy 12 s, l'un apres l'autre.
# Aucun ne depend d'un autre, chacun ecrit son propre rapport : les faire
# tourner ensemble ramene l'etape a la duree du plus long.
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
#   BASE_SEMGREP  commit de base de la pull request, vide pour l'analyse complete
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

# Rend la base disponible localement et verifie qu'elle est un ancetre de HEAD.
# Le checkout est superficiel (une seule revision) : semgrep calcule une base de
# fusion, ce qui exige l'historique entre la base et HEAD. Sur une pull request,
# HEAD est le commit de fusion de test, dont la base est le premier parent :
# deux revisions suffisent.
base_disponible() {
  local base="$1"
  if ! git -C "$racine" merge-base --is-ancestor "$base" HEAD 2>/dev/null; then
    git -C "$racine" fetch --no-tags --quiet --depth=2 origin "$(git -C "$racine" rev-parse HEAD)" \
      || return 1
  fi
  git -C "$racine" merge-base --is-ancestor "$base" HEAD 2>/dev/null
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

semgrep_analyser() {
  if [ -n "$BASE_SEMGREP" ]; then
    if base_disponible "$BASE_SEMGREP" && semgrep_incremental "$BASE_SEMGREP"; then
      echo "semgrep : analyse incrementale depuis $BASE_SEMGREP"
      return 0
    fi
    echo "::notice title=semgrep::Analyse incrementale impossible depuis $BASE_SEMGREP, analyse complete."
    rm -f "$RAPPORTS/semgrep.json"
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

declare -A pids=()
chronometrer semgrep semgrep_analyser >"$journaux/semgrep.log" 2>&1 &
pids[semgrep]=$!
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
  [ -n "${pids[$outil]:-}" ] || continue
  wait "${pids[$outil]}"
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
