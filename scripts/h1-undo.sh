#!/usr/bin/env bash
# Undo scripts/h1-apply.sh: stop/disable the service, restore every backed-up
# file, delete files it created. Usage: sudo scripts/h1-undo.sh [backup-dir]
# (default: /var/backups/freedomdesk-h1/latest). GDM/X changes take effect after
# the next GDM restart / reboot, like the apply.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
bk=$(readlink -f "${1:-/var/backups/freedomdesk-h1/latest}")
[[ -f $bk/MANIFEST ]] || { echo "no MANIFEST in $bk" >&2; exit 1; }
if grep -q '^service ' "$bk/MANIFEST"; then
  systemctl disable --now freedomdesk.service 2>/dev/null || true
fi
# Reverse order so a file both created and later backed up ends right.
tac "$bk/MANIFEST" | while read -r kind path; do
  case $kind in
    backup)  cp -a "$bk$path" "$path"; echo "restored $path";;
    created) if [[ -d $path ]]; then rmdir "$path" 2>/dev/null || echo "kept non-empty $path"; else rm -f "$path"; echo "removed $path"; fi;;
  esac
done
systemctl daemon-reload
echo "undo done from $bk. Restart GDM or reboot for display changes to revert."
