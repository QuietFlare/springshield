# springshield: the release gate as one image. Trivy for vulnerabilities, secrets,
# misconfiguration, SBOM and licences; ClamAV for malware with its database baked in at build
# time; crane to read an image's files from a registry. The databases are fetched once, here,
# as root, before the switch to the gate user; nothing updates anything at runtime, so a run on a
# laptop without network still works. The image is rebuilt weekly so the databases stay current.
#
#   docker build -t springshield .
#   docker save app:1.4.0 -o image.tar
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/image.tar:/image.tar:ro" \
#     -v "$PWD/reports:/reports" springshield /image.tar

FROM aquasec/trivy:0.70.0 AS trivy

FROM alpine:3.21 AS crane
ARG CRANE_VERSION=0.20.3
RUN apk add --no-cache curl \
 && curl -sSL "https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/go-containerregistry_Linux_x86_64.tar.gz" \
    | tar -xz -C /usr/local/bin crane

FROM alpine:3.21
RUN apk add --no-cache bash jq yq ca-certificates clamav \
 && adduser -S -u 10001 -h /home/gate gate \
 && mkdir -p /reports /cache && chmod 1777 /reports /cache /tmp
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=crane /usr/local/bin/crane /usr/local/bin/crane
COPY gate.sh /usr/local/bin/gate
COPY gate.yaml /etc/springshield/gate.yaml
RUN chmod +x /usr/local/bin/gate
ENV TRIVY_CACHE_DIR=/cache HOME=/tmp
# The databases, fetched once at build time by root. The vulnerability database refreshes itself
# on a run with network; the ClamAV database is refreshed by the weekly rebuild.
RUN trivy image --download-db-only --cache-dir /cache >/dev/null 2>&1 && chmod -R a+rwX /cache
RUN freshclam --datadir=/var/lib/clamav --quiet && chmod -R a+rX /var/lib/clamav \
 && ls /var/lib/clamav/main.c?d /var/lib/clamav/daily.c?d >/dev/null
# Non-root by default. Run with --user "$(id -u):$(id -g)" when /reports is a mounted host folder,
# so the reports belong to you; every folder the gate writes to accepts any user.
USER gate
VOLUME ["/reports"]
ENTRYPOINT ["gate"]
