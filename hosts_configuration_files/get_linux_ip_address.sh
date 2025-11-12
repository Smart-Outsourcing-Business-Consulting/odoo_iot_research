#!/usr/bin/env bash
# select_primary_ipv4.sh
# Purpose: deterministically select the "business-critical" IPv4 bound to the NIC
# that would carry default egress, with sane fallbacks for offline/LAN-only scenarios.

set -euo pipefail

# ---------- Policy toggles (override via env) ----------
: "${PREFER_RFC1918:=1}"    # Prefer 10/172.16-31/192.168 when multiple candidates exist
: "${DENY_IF_REGEX:=^(lo|docker[0-9]*|br-|veth|virbr|tap|tun|wg|tailscale|cni|podman|kube|qvb|qvo|qbr|zt|nord|ppp)}"
: "${ALLOW_IF_REGEX:=.*}"   # Optional allowlist; keep default to allow all (post deny)

# ---------- Helpers ----------
is_rfc1918() {
  local ip="$1"
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  # 172.16.0.0/12 → 172.16. to 172.31.
  if [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then return 0; fi
  return 1
}

# Return first non-link-local, non-deprecated, global IPv4 on a device (prefer “primary”)
ipv4_on_dev() {
  local dev="$1"
  # -o (oneline) gives: <idx>: <dev>    <fam> <ip>/<mask> ... flags
  ip -4 -o addr show dev "$dev" scope global 2>/dev/null \
    | awk '
      $0 !~ / 169\.254\./ && $0 !~ / deprecated / { 
        # inet 192.168.1.10/24
        for (i=1;i<=NF;i++) if ($i=="inet") { split($(i+1),a,"/"); print a[1]; exit }
      }'
}

# Pick the default route with lowest metric, return its dev
best_default_dev() {
  # Typical lines:
  # default via 192.168.1.1 dev eth0 proto dhcp metric 100
  # default via 10.0.0.1 dev ens160 metric 5
  ip -4 route show default 2>/dev/null \
    | awk '
      {
        dev=""; metric=0; 
        for(i=1;i<=NF;i++){
          if($i=="dev"){dev=$(i+1)}
          if($i=="metric"){metric=$(i+1)}
        }
        if(dev=="") next
        if(metric=="") metric=0
        print metric, dev
      }' \
    | sort -n -k1,1 \
    | awk 'NR==1{print $2}'
}

# Fallback: choose a connected interface by on-link route metric (lowest wins)
best_connected_dev() {
  # Lines of interest (kernel on-link routes):
  # 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10 metric 100
  ip -4 route show table main scope link proto kernel 2>/dev/null \
    | awk '
      {
        dev=""; metric=0;
        for(i=1;i<=NF;i++){
          if($i=="dev"){dev=$(i+1)}
          if($i=="metric"){metric=$(i+1)}
        }
        if(dev=="") next
        if(metric=="") metric=0
        print metric, dev
      }' \
    | sort -n -k1,1 \
    | awk 'NR==1{print $2}'
}

# Normalize device selection with allow/deny policy and liveness
first_suitable_dev() {
  while read -r dev; do
    [[ -z "${dev:-}" ]] && continue
    [[ "$dev" =~ $DENY_IF_REGEX ]] && continue
    [[ "$dev" =~ $ALLOW_IF_REGEX ]] || continue
    # Require RUNNING|LOWER_UP to avoid stale/bound-but-down
    if ip -o link show dev "$dev" | grep -Eq 'state UP|LOWER_UP'; then
      echo "$dev"
      return 0
    fi
  done
  return 1
}

# ---------- Selection pipeline ----------
# 1) Try default route winner
default_dev="$(best_default_dev || true)"
candidate_dev=""

if [[ -n "${default_dev:-}" ]]; then
  candidate_dev="$(printf '%s\n' "$default_dev" | first_suitable_dev || true)"
fi

# 2) If none (offline, no default), use best on-link route dev
if [[ -z "${candidate_dev:-}" ]]; then
  connected_dev="$(best_connected_dev || true)"
  if [[ -n "${connected_dev:-}" ]]; then
    candidate_dev="$(printf '%s\n' "$connected_dev" | first_suitable_dev || true)"
  fi
fi

# 3) As a last resort, pick any UP device with a global IPv4 (policy-filtered)
if [[ -z "${candidate_dev:-}" ]]; then
  candidate_dev="$(
    ip -o link show | awk -F': ' '{print $2}' \
      | grep -Ev "$DENY_IF_REGEX" \
      | grep -E "$ALLOW_IF_REGEX" \
      | while read -r d; do
          ip -o link show dev "$d" | grep -Eq "state UP|LOWER_UP" || continue
          ip -4 -o addr show dev "$d" scope global | grep -vq '169\.254\.' || continue
          echo "$d"
        done | head -n1
  )"
fi

[[ -z "${candidate_dev:-}" ]] && { echo "ERROR: No suitable network interface found." >&2; exit 2; }

# 4) Get IPv4 on that device; if multiple, prefer RFC1918 if configured
mapfile -t ips < <(ip -4 -o addr show dev "$candidate_dev" scope global \
  | awk '$0 !~ / 169\.254\./ && $0 !~ / deprecated / { for (i=1;i<=NF;i++) if ($i=="inet") { split($(i+1),a,"/"); print a[1] } }')

if [[ "${#ips[@]}" -eq 0 ]]; then
  echo "ERROR: No global IPv4 found on $candidate_dev." >&2
  exit 3
fi

selected=""
if [[ "$PREFER_RFC1918" -eq 1 ]]; then
  for ip in "${ips[@]}"; do
    if is_rfc1918 "$ip"; then selected="$ip"; break; fi
  done
fi
[[ -z "$selected" ]] && selected="${ips[0]}"

printf '%s\n' "$selected"

