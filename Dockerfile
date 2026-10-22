# springshield: the release gate as one image. Trivy for vulnerabilities, secrets and
# misconfiguration today; Syft, ClamAV and Cosign join over the week. The vulnerability database
# is baked in at build time so a run on a laptop without network still works; the image is
# rebuilt weekly so the database stays current.
#
#   docker build -t springshield .
#   docker run --rm -v "$PWD/reports:/reports" springshield ghcr.io/you/app:1.4.0

FROM aquasec/trivy:0.70.0 AS trivy

FROM alpine:3.21
RUN apk add --no-cache bash jq yq ca-certificates \
 && adduser -S -u 10001 -h /home/gate gate \
 && mkdir -p /reports /cache && chown -R gate /reports /cache
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY gate.sh /usr/local/bin/gate
COPY gate.yaml /etc/springshield/gate.yaml
RUN chmod +x /usr/local/bin/gate
USER gate
ENV TRIVY_CACHE_DIR=/cache
# The database at build time; a run with network refreshes it, a run without still has this one.
RUN trivy image --download-db-only --cache-dir /cache >/dev/null 2>&1 || true
VOLUME ["/reports"]
ENTRYPOINT ["gate"]
