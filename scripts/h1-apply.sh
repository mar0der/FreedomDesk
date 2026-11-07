#!/usr/bin/env bash
# H1: login/lock screen + no-monitor display + root FreedomDesk service (Ubuntu 24.04, GDM, NVIDIA).
# Every file touched is backed up under /var/backups/freedomdesk-h1/<stamp>/ and
# scripts/h1-undo.sh restores them. Nothing restarts GDM or reboots: that is a
# separate, scheduled step.
#
#   sudo scripts/h1-apply.sh --binary target/release/freedomdesk \
#        [--edid-connector DP-6] [--identity ~petar/.config/freedomdesk/identity.key] \
#        [--authorized ~petar/.config/freedomdesk/authorized_viewers] [--no-gdm] [--no-start]
#
# --edid-connector: pin the CURRENT monitor's own EDID on that connector
#   (NVIDIA ConnectedMonitor + CustomEDID), so the same mode exists with the
#   TV off or unplugged. Same EDID = no change while the TV is connected.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

binary="" connector="" identity="" authorized="" do_gdm=1 do_start=1
while [[ $# -gt 0 ]]; do
  case $1 in
    --binary) binary=$2; shift 2;;
    --edid-connector) connector=$2; shift 2;;
    --identity) identity=$2; shift 2;;
    --authorized) authorized=$2; shift 2;;
    --no-gdm) do_gdm=0; shift;;
    --no-start) do_start=0; shift;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
[[ -x $binary ]] || { echo "--binary <path to freedomdesk> required" >&2; exit 2; }

stamp=$(date +%Y%m%d-%H%M%S)
bk=/var/backups/freedomdesk-h1/$stamp
mkdir -p "$bk"
manifest=$bk/MANIFEST   # lines: "backup <path>" (existed, copied) or "created <path>"
: > "$manifest"
track() {  # back up (or note creation of) a path before we change it
  local p=$1
  if [[ -e $p ]]; then
    mkdir -p "$bk$(dirname "$p")"; cp -a "$p" "$bk$p"; echo "backup $p" >> "$manifest"
  else
    echo "created $p" >> "$manifest"
  fi
}
say() { echo "h1: $*"; }

# 1. GDM greeter on Xorg (so the login screen is an X display we can capture).
if [[ $do_gdm == 1 ]]; then
  f=/etc/gdm3/custom.conf
  if grep -Eq '^\s*WaylandEnable\s*=\s*false' "$f"; then
    say "GDM already Xorg-only"
  else
    track "$f"
    if grep -Eq '^\s*#?\s*WaylandEnable\s*=' "$f"; then
      sed -i -E 's/^\s*#?\s*WaylandEnable\s*=.*/WaylandEnable=false/' "$f"
    else
      sed -i -E '0,/^\[daemon\]/s//[daemon]\nWaylandEnable=false/' "$f"
    fi
    grep -q '^WaylandEnable=false' "$f" || { echo "failed to set WaylandEnable=false" >&2; exit 1; }
    say "GDM: WaylandEnable=false (takes effect after GDM restart / reboot)"
  fi
fi

# 2. NVIDIA: keep the connector "connected" with the current monitor's EDID.
if [[ -n $connector ]]; then
  disp=$(loginctl show-session "$(loginctl show-seat seat0 -p ActiveSession --value)" -p Name --value)
  xauth=$(ls /run/user/*/gdm/Xauthority 2>/dev/null | head -1)
  hex=$(sudo -u "$disp" env DISPLAY=:0 XAUTHORITY="$xauth" xrandr --props | awk -v c="$connector" '
      $1==c {inside=1; next} inside && /^[A-Za-z]/ && $2 ~ /connected/ {inside=0}
      inside && /EDID:/ {e=1; next} e && /^\t\t[0-9a-f]+$/ {gsub(/[ \t]/,""); printf "%s",$0; next} e {e=0}')
  [[ ${#hex} -ge 256 && $(( ${#hex} % 256 )) -eq 0 ]] || { echo "could not read EDID for $connector (got ${#hex} hex chars)" >&2; exit 1; }
  busid=$(nvidia-smi --query-gpu=pci.bus_id --format=csv,noheader | head -1)   # 00000000:21:00.0
  b=${busid#*:}; bus=$((16#${b%%:*})); rest=${b#*:}; dev=$((16#${rest%%.*})); fn=${rest##*.}
  edid=/etc/X11/freedomdesk-edid-$connector.bin
  conf=/etc/X11/xorg.conf.d/20-freedomdesk-nvidia.conf
  track "$edid"; track "$conf"
  mkdir -p /etc/X11/xorg.conf.d
  echo "$hex" | xxd -r -p > "$edid"
  cat > "$conf" <<CONF
# FreedomDesk H1 ($stamp): keep $connector "connected" with its monitor's own EDID,
# so the login screen and desktop keep the same mode when the TV is off/unplugged.
# Undo: scripts/h1-undo.sh (backup in $bk)
Section "Device"
    Identifier "FreedomDesk-NVIDIA"
    Driver     "nvidia"
    BusID      "PCI:$bus:$dev:$fn"
    Option     "ConnectedMonitor" "$connector"
    Option     "CustomEDID" "$connector:$edid"
EndSection
CONF
  say "NVIDIA: $conf + $edid ($(( ${#hex} / 2 )) bytes) — takes effect after X restarts"
fi

# 3. Binary, config, service.
track /usr/local/bin/freedomdesk
install -m 0755 "$binary" /usr/local/bin/freedomdesk
if [[ ! -d /etc/freedomdesk ]]; then echo "created /etc/freedomdesk" >> "$manifest"; fi
install -d -m 0755 /etc/freedomdesk
if [[ -n $identity && ! -e /etc/freedomdesk/identity.key ]]; then
  echo "created /etc/freedomdesk/identity.key" >> "$manifest"
  install -m 0600 -o root -g root "$identity" /etc/freedomdesk/identity.key
fi
[[ -e /etc/freedomdesk/identity.key ]] || { echo "created /etc/freedomdesk/identity.key" >> "$manifest"; /usr/local/bin/freedomdesk --config-dir /etc/freedomdesk id >/dev/null; }
if [[ -n $authorized ]]; then
  track /etc/freedomdesk/authorized_viewers
  install -m 0644 -o root -g root "$authorized" /etc/freedomdesk/authorized_viewers
fi
track /etc/systemd/system/freedomdesk.service
install -m 0644 "$(dirname "$0")/../packaging/linux/freedomdesk.service" /etc/systemd/system/freedomdesk.service
systemctl daemon-reload
systemctl enable freedomdesk.service >/dev/null
echo "service freedomdesk.service" >> "$manifest"
[[ $do_start == 1 ]] && systemctl restart freedomdesk.service
say "service installed$([[ $do_start == 1 ]] && echo ' and started'); host fingerprint: $(/usr/local/bin/freedomdesk --config-dir /etc/freedomdesk id | sed -n 's/Device fingerprint: *//p')"
ln -sfn "$bk" /var/backups/freedomdesk-h1/latest
say "backup + manifest: $bk  (undo: sudo scripts/h1-undo.sh)"
