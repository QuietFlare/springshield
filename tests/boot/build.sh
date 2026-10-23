#!/usr/bin/env bash
# Two small Spring Boot images for the gate's own tests, written as tars into the given folder.
# No Java is involved: a Boot application is recognised by its layout, so a zip with the right
# entries and jars with the right names is enough to exercise the three Boot checks.
#
#   boot-bad.tar   one fat jar, Actuator exposing everything, no Spring Security, profile dev
#                  set in ENV. Expected: BLOCKED by boot-profile and boot-actuator.
#   boot-good.tar  exploded application, Actuator exposing health and info by default and
#                  everything only under the dev profile, Spring Security present, profile prod.
#                  Expected: SHIP.
set -euo pipefail
out="${1:?folder for the tars}"; mkdir -p "$out"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

mkdir -p "$work/bad/src/META-INF" "$work/bad/src/BOOT-INF/classes" "$work/bad/src/BOOT-INF/lib"
printf 'Manifest-Version: 1.0\nMain-Class: org.springframework.boot.loader.launch.JarLauncher\nSpring-Boot-Version: 3.4.5\n' > "$work/bad/src/META-INF/MANIFEST.MF"
printf 'management:\n  endpoints:\n    web:\n      exposure:\n        include: "*"\n' > "$work/bad/src/BOOT-INF/classes/application.yml"
: > "$work/bad/src/BOOT-INF/lib/spring-boot-3.4.5.jar"
: > "$work/bad/src/BOOT-INF/lib/spring-boot-actuator-3.4.5.jar"
(cd "$work/bad/src" && zip -qr ../app.jar .)
cat > "$work/bad/Dockerfile" <<'DF'
FROM alpine:3.21
ENV SPRING_PROFILES_ACTIVE=dev
COPY app.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
DF
docker build -q -t springshield-test/boot-bad "$work/bad" >/dev/null
docker save springshield-test/boot-bad -o "$out/boot-bad.tar"

mkdir -p "$work/good/app/BOOT-INF/classes" "$work/good/app/BOOT-INF/lib" "$work/good/app/META-INF"
printf 'Manifest-Version: 1.0\nSpring-Boot-Version: 3.4.5\n' > "$work/good/app/META-INF/MANIFEST.MF"
cat > "$work/good/app/BOOT-INF/classes/application.yml" <<'YML'
management:
  endpoints:
    web:
      exposure:
        include: [health, info]
---
spring:
  config:
    activate:
      on-profile: dev
management.endpoints.web.exposure.include: "*"
YML
: > "$work/good/app/BOOT-INF/lib/spring-boot-3.4.5.jar"
: > "$work/good/app/BOOT-INF/lib/spring-boot-actuator-3.4.5.jar"
: > "$work/good/app/BOOT-INF/lib/spring-security-web-6.4.5.jar"
cat > "$work/good/Dockerfile" <<'DF'
FROM alpine:3.21
COPY app /app
ENTRYPOINT ["java", "-Dspring.profiles.active=prod", "org.springframework.boot.loader.launch.JarLauncher"]
DF
docker build -q -t springshield-test/boot-good "$work/good" >/dev/null
docker save springshield-test/boot-good -o "$out/boot-good.tar"
echo "wrote $out/boot-bad.tar and $out/boot-good.tar"
