#!/bin/sh
# Links the pi packages and Node types that ship with your pi install into node_modules/, so the
# editor and `tsc` can resolve imports without installing anything from npm. Development only.
set -eu

pi_bin=$(command -v pi) || { echo "pi is not on PATH" >&2; exit 1; }
root=""
for candidate in \
  "$(dirname "$(readlink -f "$pi_bin")")/../lib/node_modules/@earendil-works/pi-coding-agent/.." \
  "$HOME/.pi/agent/install/current/node_modules" \
  $(ls -d "$HOME"/.pi/agent/install/releases/*/node_modules 2>/dev/null | sort -V | tail -n 1); do
  if [ -d "$candidate/@earendil-works/pi-coding-agent" ]; then root=$(cd "$candidate" && pwd); break; fi
done
[ -n "$root" ] || { echo "Could not find pi's node_modules" >&2; exit 1; }

cd "$(dirname "$0")/.."
mkdir -p node_modules/@earendil-works node_modules/@types
for pkg in pi-coding-agent pi-tui pi-ai pi-agent-core; do
  ln -sfn "$root/@earendil-works/$pkg" "node_modules/@earendil-works/$pkg"
done
ln -sfn "$root/typebox" node_modules/typebox
ln -sfn "$root/@types/node" node_modules/@types/node
echo "Linked pi types from $root"
