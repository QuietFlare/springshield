#!/usr/bin/env bash
# springshield: run every check on an image, assert each one did its work, give one verdict.
#
#   gate <image-ref | image.tar> [--policy gate.yaml] [--reports dir] [--dockerfile path]
#
# Exit codes: 0 the image may ship, 1 a check blocked it, 2 a check could not run.
# A check that scans nothing is exit 2, never 0: green means scanned, not merely finished.
set -euo pipefail

TARGET=""
POLICY="${SPRINGSHIELD_POLICY:-/etc/springshield/gate.yaml}"
REPORTS="${SPRINGSHIELD_REPORTS:-/reports}"
DOCKERFILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --policy)     POLICY="$2"; shift 2 ;;
    --reports)    REPORTS="$2"; shift 2 ;;
    --dockerfile) DOCKERFILE="$2"; shift 2 ;;
    -h|--help)    sed -n '2,8p' "$0"; exit 0 ;;
    *)            TARGET="$1"; shift ;;
  esac
done
[ -n "$TARGET" ] || { echo "gate: an image reference or a tar file is required" >&2; exit 2; }
[ -f "$POLICY" ] || { echo "gate: policy not found at $POLICY" >&2; exit 2; }
mkdir -p "$REPORTS"

# How Trivy reaches the target: a tar file is read directly; a reference is pulled from its
# registry, with TRIVY_USERNAME and TRIVY_PASSWORD when the registry needs them.
if [ -f "$TARGET" ]; then INPUT=(--input "$TARGET"); else INPUT=("$TARGET"); fi

# The policy, read once.
SEVERITY=$(yq -r '.block.severity | join(",")' "$POLICY")
IGNORE_UNFIXED=$(yq -r '.block.ignore_unfixed // true' "$POLICY")
ACCEPTED_FILE="$REPORTS/.accepted"
yq -r '.accepted[]? | .id' "$POLICY" > "$ACCEPTED_FILE"
today=$(date -u +%F)
# An accepted finding past its date is accepted no longer.
while IFS=$'\t' read -r id until; do
  if [ -n "$until" ] && [[ "$until" < "$today" ]]; then
    echo "gate: acceptance of $id expired on $until, it blocks again" >&2
    sed -i "/^$id\$/d" "$ACCEPTED_FILE"
  fi
done < <(yq -r '.accepted[]? | [.id, (.until // "")] | @tsv' "$POLICY")

blocked=0; broken=0
pass()  { printf '  %-18s pass   %s\n' "$1" "$2"; }
block() { printf '  %-18s BLOCK  %s\n' "$1" "$2"; blocked=1; }
broke() { printf '  %-18s BROKEN %s\n' "$1" "$2"; broken=1; }

echo "springshield on $TARGET"
echo "  policy $POLICY, reports in $REPORTS"

# vulnerabilities: fixable findings at the blocking severities, minus the accepted ones.
check_vulnerabilities() {
  local json="$REPORTS/vulnerabilities.json" txt="$REPORTS/vulnerabilities.txt" args=()
  [ "$IGNORE_UNFIXED" = "true" ] && args+=(--ignore-unfixed)
  trivy image --quiet --scanners vuln --severity "$SEVERITY" "${args[@]}" \
    --ignorefile "$ACCEPTED_FILE" --format json --output "$json" "${INPUT[@]}" || true
  # Did it do the work: an operating system or at least one package target was seen.
  local targets; targets=$(jq '[.Results[]? ] | length' "$json" 2>/dev/null || echo 0)
  if [ "${targets:-0}" -eq 0 ]; then broke vulnerabilities "no targets found; image unreadable or scan did not run"; return; fi
  trivy image --quiet --scanners vuln --severity "$SEVERITY" "${args[@]}" \
    --ignorefile "$ACCEPTED_FILE" --format table --output "$txt" "${INPUT[@]}" || true
  local n; n=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$json")
  if [ "$n" -gt 0 ]; then block vulnerabilities "$n finding(s) at $SEVERITY with a fix, see vulnerabilities.txt"
  else pass vulnerabilities "$targets target(s) scanned, none at $SEVERITY with a fix"; fi
}

# secrets: anything that looks like a credential in any layer blocks.
check_secrets() {
  local json="$REPORTS/secrets.json"
  trivy image --quiet --scanners secret --format json --output "$json" "${INPUT[@]}" || true
  local targets; targets=$(jq '[.Results[]?] | length' "$json" 2>/dev/null || echo 0)
  local n; n=$(jq '[.Results[]?.Secrets[]?] | length' "$json" 2>/dev/null || echo 0)
  # A clean image reports no targets for secrets, so the proof of work is the scan metadata.
  local seen; seen=$(jq -r '.Metadata.ImageID // .ArtifactName // ""' "$json" 2>/dev/null)
  if [ -z "$seen" ]; then broke secrets "scan produced no metadata; did not run"; return; fi
  if [ "$n" -gt 0 ]; then block secrets "$n secret(s) found in the layers, see secrets.json"
  else pass secrets "no secrets in any layer"; fi
}

# misconfiguration: the Dockerfile that built the image, when given; the image itself has no
# Dockerfile inside it to read, so without the path this check reports and does not judge.
check_misconfig() {
  local json="$REPORTS/misconfiguration.json"
  if [ -z "$DOCKERFILE" ]; then pass misconfiguration "no --dockerfile given; nothing to judge"; return; fi
  [ -f "$DOCKERFILE" ] || { broke misconfiguration "Dockerfile not found at $DOCKERFILE"; return; }
  trivy config --quiet --severity "$SEVERITY" --format json --output "$json" "$(dirname "$DOCKERFILE")" || true
  local targets; targets=$(jq '[.Results[]?] | length' "$json" 2>/dev/null || echo 0)
  if [ "${targets:-0}" -eq 0 ]; then broke misconfiguration "Dockerfile not parsed; scan did not run"; return; fi
  local n; n=$(jq '[.Results[]?.Misconfigurations[]?] | length' "$json")
  if [ "$n" -gt 0 ]; then block misconfiguration "$n finding(s) at $SEVERITY, see misconfiguration.json"
  else pass misconfiguration "Dockerfile checked, nothing at $SEVERITY"; fi
}

check_vulnerabilities
check_secrets
check_misconfig

echo
if [ "$broken" -eq 1 ]; then echo "verdict: BROKEN, a check could not run; nothing may ship on a check that did not happen"; exit 2; fi
if [ "$blocked" -eq 1 ]; then echo "verdict: BLOCKED, fix or accept in the policy with a reason and a date"; exit 1; fi
echo "verdict: SHIP"
