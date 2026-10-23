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
BOOT_BLOCK=$(yq -r '(.boot.block // ["actuator", "dev-profile"]) | join(" ")' "$POLICY")
DEV_PROFILES=$(yq -r '(.boot.dev_profiles // ["dev", "development", "local", "test", "debug"]) | join(" ")' "$POLICY")
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

# The image's files and its config, read once: from the tar's layers, or from the registry
# through crane for a reference. The malware check and the Spring Boot checks read these.
FS="$WORK/fs"; CONFIG="$WORK/config.json"; FS_FILES=0
extract_image() {
  mkdir -p "$FS"
  if [ -f "$TARGET" ]; then
    local layers="$WORK/layers" layer config; mkdir -p "$layers"
    tar -xf "$TARGET" -C "$layers" 2>/dev/null || { echo '{}' > "$CONFIG"; return; }
    while read -r layer; do
      tar -xf "$layers/$layer" -C "$FS" 2>/dev/null || true
    done < <(jq -r '.[0].Layers[]?' "$layers/manifest.json" 2>/dev/null)
    config=$(jq -r '.[0].Config // ""' "$layers/manifest.json" 2>/dev/null)
    cp "$layers/$config" "$CONFIG" 2>/dev/null || echo '{}' > "$CONFIG"
  else
    if [ -n "${TRIVY_USERNAME:-}" ]; then crane auth login "${TARGET%%/*}" -u "$TRIVY_USERNAME" -p "${TRIVY_PASSWORD:-}" >/dev/null 2>&1 || true; fi
    crane export "$TARGET" - 2>/dev/null | tar -x -C "$FS" 2>/dev/null || true
    crane config "$TARGET" > "$CONFIG" 2>/dev/null || echo '{}' > "$CONFIG"
  fi
  FS_FILES=$(find "$FS" -type f | wc -l | tr -d ' ')
}

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

# malware: ClamAV over the image's files. The database was baked into this image at build time.
check_malware() {
  local txt="$REPORTS/malware.txt"
  if [ "$FS_FILES" -eq 0 ]; then broke malware "no files extracted from the image; nothing was scanned"; return; fi
  clamscan --database=/var/lib/clamav --recursive --infected "$FS" > "$txt" 2>&1 || true
  local scanned infected
  scanned=$(grep -E '^Scanned files:' "$txt" | grep -oE '[0-9]+' || echo 0)
  infected=$(grep -E '^Infected files:' "$txt" | grep -oE '[0-9]+' || echo 0)
  if [ "${scanned:-0}" -eq 0 ]; then broke malware "ClamAV scanned 0 files; database missing or scan did not run"; return; fi
  if [ "${infected:-0}" -gt 0 ]; then block malware "$infected infected file(s), see malware.txt"
  else pass malware "$scanned files scanned, none infected"; fi
}

# Spring Boot. The application is a fat jar (BOOT-INF inside the jar) or an exploded one
# (BOOT-INF on disk, as layertools extract and buildpacks leave it). Its application files and
# the names of its dependencies are what the three Boot checks read, together with the image's
# ENV and command line, where a profile or an exposure can also be set.
BOOT_KIND=""; BOOT_HOME=""; BOOT_LIBS=""; BOOT_CONF="$WORK/boot"; ACTIVE_PROFILES=""
boot_locate() {
  mkdir -p "$BOOT_CONF"
  local dir jar
  dir=$(find "$FS" -type d -name BOOT-INF 2>/dev/null | head -1)
  if [ -n "$dir" ]; then
    BOOT_KIND=exploded; BOOT_HOME="${dir%/BOOT-INF}"
    BOOT_LIBS=$(ls "$dir/lib" 2>/dev/null || true)
    find "$dir/classes" -maxdepth 2 -name 'application*' -type f -exec cp {} "$BOOT_CONF/" \; 2>/dev/null || true
    return
  fi
  # The entry list goes through a file: grep -q on a pipe closes it early, and with pipefail a
  # large jar then looks like a miss.
  local entries="$WORK/entries"
  while read -r jar; do
    unzip -Z1 "$jar" > "$entries" 2>/dev/null || continue
    if grep -q '^BOOT-INF/classes/' "$entries"; then
      BOOT_KIND=jar; BOOT_HOME="$jar"
      BOOT_LIBS=$(grep -E '^BOOT-INF/lib/[^/]+\.jar$' "$entries" | sed 's#^BOOT-INF/lib/##')
      unzip -o -j -q "$jar" 'BOOT-INF/classes/application*' 'BOOT-INF/classes/config/application*' -d "$BOOT_CONF" 2>/dev/null || true
      return
    fi
  done < <(find "$FS" -type f -name '*.jar' 2>/dev/null)
}

# One property as the image sets it, lowest precedence first: application files, then the
# files of the active profiles, then ENV, then the command line. Prints "value<TAB>where".
boot_prop() {
  local key="$1" f p
  prop_file() {  # $1 file, $2 "default" reads only documents without an on-profile
    local f="$1" name; name=$(basename "$f")
    case "$f" in
      *.properties) grep -E "^[[:space:]]*${key//./\\.}[[:space:]]*[=:]" "$f" 2>/dev/null | sed -E 's/^[^=:]*[=:][[:space:]]*//' | sed "s|\$|\t$name|" ;;
      *.yml|*.yaml)
        local sel='.'
        [ "$2" = default ] && sel='select((.spring.config.activate."on-profile" // .["spring.config.activate.on-profile"] // .spring.profiles) == null)'
        yq -o json -I0 "$sel | (.[\"$key\"] // .$key) | select(. != null)" "$f" 2>/dev/null \
          | jq -r 'if type == "array" then join(",") else tostring end' 2>/dev/null | sed "s|\$|\t$name|" ;;
    esac
  }
  for f in "$BOOT_CONF"/application.properties "$BOOT_CONF"/application.yml "$BOOT_CONF"/application.yaml; do
    [ -f "$f" ] && prop_file "$f" default
  done
  for p in $ACTIVE_PROFILES; do
    for f in "$BOOT_CONF/application-$p.properties" "$BOOT_CONF/application-$p.yml" "$BOOT_CONF/application-$p.yaml"; do
      [ -f "$f" ] && prop_file "$f" profile
    done
  done
  local env_key; env_key=$(printf '%s' "$key" | tr 'a-z.-' 'A-Z__')
  jq -r '.config.Env[]?' "$CONFIG" 2>/dev/null | grep -E "^($env_key|$key)=" | sed -E 's/^[^=]*=//' | sed 's|$|\tENV|'
  { jq -r '(.config.Entrypoint // [])[]?, (.config.Cmd // [])[]?, .config.Env[]?' "$CONFIG" 2>/dev/null; } \
    | grep -oE "(^|[[:space:]])(-D|--)${key//./\\.}=[^[:space:]\"']*" | sed -E 's/^.*=//' | sed 's|$|\tcommand line|'
  return 0
}

# A Boot finding blocks, is reported, or was accepted in the policy by its id.
boot_finding() {  # $1 policy name, $2 check, $3 finding id, $4 detail
  if grep -qx "$3" "$ACCEPTED_FILE"; then pass "$2" "$4; accepted in the policy as $3"
  elif grep -qw "$1" <<<"$BOOT_BLOCK"; then block "$2" "$4 ($3)"
  else pass "$2" "$4 ($3), reported only; add $1 to boot.block to block on it"; fi
}
boot_skip() {  # true when the check has nothing to judge, having said so
  if [ "$FS_FILES" -eq 0 ]; then broke "$1" "no files extracted from the image; nothing was scanned"; return 0; fi
  if [ -z "$BOOT_KIND" ]; then pass "$1" "not a Spring Boot image; nothing to judge"; return 0; fi
  return 1
}

# boot-profile: a development profile active in the image. It would start as a dev build.
check_boot_profile() {
  boot_skip boot-profile && return
  local hits active bad="" p src
  hits=$( { boot_prop spring.profiles.active; boot_prop spring.profiles.include; } )
  active=$(cut -f1 <<<"$hits" | tr ',' '\n' | tr -d ' "' | grep -v '^$' | sort -u || true)
  ACTIVE_PROFILES=$(paste -sd' ' <<<"$active")
  for p in $active; do grep -qw "$p" <<<"$DEV_PROFILES" && bad="$bad $p"; done
  if [ -z "$bad" ]; then pass boot-profile "active profiles: ${ACTIVE_PROFILES:-none set}; none is a development profile"; return; fi
  src=$(grep -E "^[^	]*($(tr ' ' '|' <<<"${bad# }"))" <<<"$hits" | cut -f2 | sort -u | paste -sd, - )
  boot_finding dev-profile boot-profile BOOT-DEV-PROFILE "profile${bad} active, set in $src"
}

# boot-actuator: Actuator endpoints beyond health and info exposed over HTTP with no Spring
# Security in the image. With Security present the gate cannot read the filter chain and says so.
check_boot_actuator() {
  boot_skip boot-actuator && return
  if ! grep -qE '^spring-boot-actuator-' <<<"$BOOT_LIBS"; then pass boot-actuator "Actuator not in the image"; return; fi
  local hit exposed src
  hit=$(boot_prop management.endpoints.web.exposure.include | tail -1)
  exposed=$(cut -f1 <<<"$hit" | tr ',' '\n' | tr -d ' "' | grep -v '^$' | sort -u | grep -vxE 'health|info' | paste -sd, - || true)
  if [ -z "$exposed" ]; then pass boot-actuator "Actuator exposes health and info only"; return; fi
  src=$(cut -f2 <<<"$hit")
  if grep -qE '^spring-security-(web|config)-' <<<"$BOOT_LIBS"; then
    pass boot-actuator "Actuator exposes $exposed (set in $src); Spring Security is present, check that its filter chain covers /actuator"; return
  fi
  boot_finding actuator boot-actuator BOOT-ACTUATOR "Actuator exposes $exposed over HTTP, set in $src, and Spring Security is not in the image"
}

# boot-layers: one fat jar means dependencies and classes travel in one layer, re-shipped on
# every build. An exploded application keeps them apart.
check_boot_layers() {
  boot_skip boot-layers && return
  if [ "$BOOT_KIND" = exploded ]; then pass boot-layers "application exploded at ${BOOT_HOME#$FS}, dependencies and classes in separate paths"; return; fi
  local mb libs; mb=$(du -m "$BOOT_HOME" | cut -f1); libs=$(grep -c . <<<"$BOOT_LIBS" || true)
  boot_finding unlayered boot-layers BOOT-UNLAYERED "one fat jar at ${BOOT_HOME#$FS}, $mb MB with $libs dependencies inside"
}

extract_image
check_vulnerabilities
check_secrets
check_misconfig
check_sbom
check_licences
check_malware
boot_locate
check_boot_profile
check_boot_actuator
check_boot_layers

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
