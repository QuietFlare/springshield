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
WORK="$(mktemp -d)"

# How Trivy reaches the target: a tar file is read directly; a reference is pulled from its
# registry, with TRIVY_USERNAME and TRIVY_PASSWORD when the registry needs them.
if [ -f "$TARGET" ]; then INPUT=(--input "$TARGET"); else INPUT=("$TARGET"); fi

# The policy, read once.
SEVERITY=$(yq -r '.block.severity | join(",")' "$POLICY")
IGNORE_UNFIXED=$(yq -r '.block.ignore_unfixed // true' "$POLICY")
FORBIDDEN_LICENCES=$(yq -r '(.licences.forbid // ["forbidden"]) | join(" ")' "$POLICY")
ACCEPTED_FILE="$WORK/accepted"
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
RESULTS="$WORK/results.tsv"; : > "$RESULTS"
record() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS"; }
pass()  { printf '  %-18s pass   %s\n' "$1" "$2"; record "$1" pass "$2"; }
block() { printf '  %-18s BLOCK  %s\n' "$1" "$2"; record "$1" block "$2"; blocked=1; }
broke() { printf '  %-18s BROKEN %s\n' "$1" "$2"; record "$1" broken "$2"; broken=1; }
count() { jq "$2" "$1" 2>/dev/null || echo 0; }

echo "springshield on $TARGET"
echo "  policy $POLICY, reports in $REPORTS"

# vulnerabilities: fixable findings at the blocking severities, minus the accepted ones.
check_vulnerabilities() {
  local json="$REPORTS/vulnerabilities.json" txt="$REPORTS/vulnerabilities.txt" args=()
  [ "$IGNORE_UNFIXED" = "true" ] && args+=(--ignore-unfixed)
  trivy image --quiet --scanners vuln --severity "$SEVERITY" "${args[@]}" \
    --ignorefile "$ACCEPTED_FILE" --format json --output "$json" "${INPUT[@]}" || true
  local targets; targets=$(count "$json" '[.Results[]?] | length')
  if [ "${targets:-0}" -eq 0 ]; then broke vulnerabilities "no targets found; image unreadable or scan did not run"; return; fi
  trivy image --quiet --scanners vuln --severity "$SEVERITY" "${args[@]}" \
    --ignorefile "$ACCEPTED_FILE" --format table --output "$txt" "${INPUT[@]}" || true
  local n; n=$(count "$json" '[.Results[]?.Vulnerabilities[]?] | length')
  if [ "$n" -gt 0 ]; then block vulnerabilities "$n finding(s) at $SEVERITY with a fix, see vulnerabilities.txt"
  else pass vulnerabilities "$targets target(s) scanned, none at $SEVERITY with a fix"; fi
}

# secrets: anything that looks like a credential in any layer blocks.
check_secrets() {
  local json="$REPORTS/secrets.json"
  trivy image --quiet --scanners secret --format json --output "$json" "${INPUT[@]}" || true
  local seen; seen=$(jq -r '.Metadata.ImageID // .ArtifactName // ""' "$json" 2>/dev/null)
  if [ -z "$seen" ]; then broke secrets "scan produced no metadata; did not run"; return; fi
  local n; n=$(count "$json" '[.Results[]?.Secrets[]?] | length')
  if [ "$n" -gt 0 ]; then block secrets "$n secret(s) found in the layers, see secrets.json"
  else pass secrets "no secrets in any layer"; fi
}

# misconfiguration: the Dockerfile that built the image, when given; the image carries no
# Dockerfile inside it, so without the path this check has nothing to judge.
check_misconfig() {
  local json="$REPORTS/misconfiguration.json"
  if [ -z "$DOCKERFILE" ]; then pass misconfiguration "no --dockerfile given; nothing to judge"; return; fi
  [ -f "$DOCKERFILE" ] || { broke misconfiguration "Dockerfile not found at $DOCKERFILE"; return; }
  local dir="$WORK/dockerfile"; mkdir -p "$dir"; cp "$DOCKERFILE" "$dir/Dockerfile"
  trivy config --quiet --severity "$SEVERITY" --format json --output "$json" "$dir" || true
  local targets; targets=$(count "$json" '[.Results[]?] | length')
  if [ "${targets:-0}" -eq 0 ]; then broke misconfiguration "Dockerfile not parsed; scan did not run"; return; fi
  local n; n=$(count "$json" '[.Results[]?.Misconfigurations[]?] | length')
  if [ "$n" -gt 0 ]; then block misconfiguration "$n finding(s) at $SEVERITY, see misconfiguration.json"
  else pass misconfiguration "Dockerfile checked, nothing at $SEVERITY"; fi
}

# sbom: the inventory, CycloneDX. The file is the result; an empty one means the scan did not run.
check_sbom() {
  local out="$REPORTS/sbom.cdx.json"
  trivy image --quiet --format cyclonedx --output "$out" "${INPUT[@]}" || true
  local n; n=$(count "$out" '.components | length')
  if [ "${n:-0}" -eq 0 ]; then broke sbom "no components listed; SBOM not produced"; return; fi
  pass sbom "$n components listed in sbom.cdx.json"
}

# licences: report every licence; block only on the categories the policy forbids.
check_licences() {
  local json="$REPORTS/licences.json" txt="$REPORTS/licences.txt"
  trivy image --quiet --scanners license --format json --output "$json" "${INPUT[@]}" || true
  trivy image --quiet --scanners license --format table --output "$txt" "${INPUT[@]}" || true
  local seen; seen=$(jq -r '.Metadata.ImageID // .ArtifactName // ""' "$json" 2>/dev/null)
  if [ -z "$seen" ]; then broke licences "scan produced no metadata; did not run"; return; fi
  local total; total=$(count "$json" '[.Results[]?.Licenses[]?] | length')
  local bad=0 cat
  for cat in $FORBIDDEN_LICENCES; do
    bad=$((bad + $(jq --arg c "$cat" '[.Results[]?.Licenses[]? | select(.Category == $c)] | length' "$json" 2>/dev/null || echo 0)))
  done
  if [ "$bad" -gt 0 ]; then block licences "$bad licence(s) in forbidden categories ($FORBIDDEN_LICENCES), see licences.txt"
  else pass licences "$total licence(s) seen, none in $FORBIDDEN_LICENCES"; fi
}

# malware: ClamAV over the image's files. The files come from the tar's layers, or from the
# registry through crane for a reference. The database was baked into this image at build time.
check_malware() {
  local fs="$WORK/fs" txt="$REPORTS/malware.txt"; mkdir -p "$fs"
  if [ -f "$TARGET" ]; then
    local layers="$WORK/layers"; mkdir -p "$layers"
    tar -xf "$TARGET" -C "$layers" 2>/dev/null || { broke malware "could not read the tar"; return; }
    local layer
    while read -r layer; do
      tar -xf "$layers/$layer" -C "$fs" 2>/dev/null || true
    done < <(jq -r '.[0].Layers[]?' "$layers/manifest.json" 2>/dev/null)
  else
    if [ -n "${TRIVY_USERNAME:-}" ]; then crane auth login "${TARGET%%/*}" -u "$TRIVY_USERNAME" -p "${TRIVY_PASSWORD:-}" >/dev/null 2>&1 || true; fi
    crane export "$TARGET" - 2>/dev/null | tar -x -C "$fs" 2>/dev/null || true
  fi
  local files; files=$(find "$fs" -type f | wc -l)
  if [ "$files" -eq 0 ]; then broke malware "no files extracted from the image; nothing was scanned"; return; fi
  clamscan --database=/var/lib/clamav --recursive --infected "$fs" > "$txt" 2>&1 || true
  local scanned infected
  scanned=$(grep -E '^Scanned files:' "$txt" | grep -oE '[0-9]+' || echo 0)
  infected=$(grep -E '^Infected files:' "$txt" | grep -oE '[0-9]+' || echo 0)
  if [ "${scanned:-0}" -eq 0 ]; then broke malware "ClamAV scanned 0 files; database missing or scan did not run"; return; fi
  if [ "${infected:-0}" -gt 0 ]; then block malware "$infected infected file(s), see malware.txt"
  else pass malware "$scanned files scanned, none infected"; fi
}

check_vulnerabilities
check_secrets
check_misconfig
check_sbom
check_licences
check_malware

if [ "$broken" -eq 1 ]; then verdict=BROKEN; code=2
elif [ "$blocked" -eq 1 ]; then verdict=BLOCKED; code=1
else verdict=SHIP; code=0; fi

# The verdict as a file: what was judged, by which gate with which databases, under which policy,
# and what each check said. This is what a cluster policy or a release page reads.
digest=$(jq -r '.Metadata.RepoDigests[0]? // .Metadata.ImageID // ""' "$REPORTS/vulnerabilities.json" 2>/dev/null || echo "")
trivy_db=$(trivy version --format json 2>/dev/null | jq -r '.VulnerabilityDB.UpdatedAt // ""' || echo "")
clamav_db=$(clamscan --version 2>/dev/null || echo "")
policy_sha=$(sha256sum "$POLICY" | cut -c1-64)
jq -n \
  --arg target "$TARGET" --arg digest "$digest" --arg verdict "$verdict" \
  --arg gate "${SPRINGSHIELD_VERSION:-dev}" --arg trivy_db "$trivy_db" --arg clamav_db "$clamav_db" \
  --arg policy "$POLICY" --arg policy_sha "$policy_sha" --arg at "$(date -u +%FT%TZ)" \
  --rawfile results "$RESULTS" \
  '{target: $target, digest: $digest, verdict: $verdict, judged_at: $at,
    gate: {version: $gate, vulnerability_db: $trivy_db, clamav: $clamav_db},
    policy: {path: $policy, sha256: $policy_sha},
    checks: ($results | split("\n") | map(select(length > 0) | split("\t") | {name: .[0], result: .[1], detail: .[2]}))}' \
  > "$REPORTS/verdict.json"

rm -rf "$WORK"
echo
case "$verdict" in
  BROKEN)  echo "verdict: BROKEN, a check could not run; nothing may ship on a check that did not happen" ;;
  BLOCKED) echo "verdict: BLOCKED, fix or accept in the policy with a reason and a date" ;;
  SHIP)    echo "verdict: SHIP" ;;
esac
exit "$code"
