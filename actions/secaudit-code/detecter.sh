#!/usr/bin/env bash
#
# Dit ce qu'il y a a analyser dans un depot : du Python, un Dockerfile, de
# l'infrastructure decrite en fichiers.
#
# Cette logique vivait dans le `run:` de l'action, ou rien ne pouvait la tester.
# Elle decide pourtant quels outils tournent, donc une erreur ici ne casse rien
# de visible : elle fait juste silencieusement sauter un scanner.
#
# Usage : detecter.sh [racine]
# Sortie : trois lignes `cle=valeur`, valeurs `oui` ou `non`.

set -uo pipefail

racine="${1:-.}"

# Une racine absente veut dire `chemin` mal renseigne. Rendre « rien a
# analyser » serait le pire des comportements : l'audit passerait au vert sans
# avoir rien scanne, ce qui est exactement le mode de panne que cette action
# existe pour rendre visible.
if [ ! -d "$racine" ]; then
  echo "::error title=Chemin introuvable::« $racine » n'existe pas, rien n'a ete analyse." >&2
  exit 1
fi

# -prune sur les dossiers de dependances : le code d'un tiers n'est pas le
# notre, et un node_modules fait exploser le temps de scan sans produire un seul
# constat sur lequel on puisse agir.
chercher() {
  find "$racine" \
    \( -name .git -o -name node_modules -o -name .venv -o -name venv \
       -o -name vendor -o -name dist -o -name build \) -prune -o \
    -type f -name "$1" -print 2>/dev/null | head -1
}

python=non
[ -n "$(chercher '*.py')" ] && python=oui

docker=non
[ -n "$(chercher 'Dockerfile*')" ] && docker=oui

# checkov ne tourne que s'il y a de l'infrastructure decrite en fichiers. Le
# lancer sur un depot qui n'a qu'un workflow GitHub produit surtout du bruit, et
# un gate bruyant finit ignore.
iac=non
for motif in '*.tf' '*.tf.json' '*.bicep' 'docker-compose*.y*ml' 'Chart.yaml'; do
  if [ -n "$(chercher "$motif")" ]; then
    iac=oui
    break
  fi
done

# Un Dockerfile est de l'infrastructure : checkov y applique ses propres
# controles, complementaires de ceux de hadolint.
[ "$docker" = oui ] && iac=oui

echo "python=$python"
echo "docker=$docker"
echo "iac=$iac"
