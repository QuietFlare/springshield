# Changelog

Each release is also a container image, `ghcr.io/quietflare/springshield:<version>-<date>`, rebuilt every Monday with fresh databases under a new date. The floating tags `:<version>`, `:<major.minor>` and `:<major>` move to the newest rebuild.

## 1.0.0

The first release, after the first real image went through it and shipped.

- Six checks on an image: vulnerabilities, secrets, misconfiguration, SBOM, licences, malware.
- Every check asserts it did its work and reports BROKEN when it did not; a check that scans nothing never passes.
- One verdict, SHIP, BLOCKED or BROKEN, as the exit code and in `reports/verdict.json`, with the image digest, the gate version, the database dates, each check's result and the policy's hash.
- A policy file, `gate.yaml`: what blocks, which licence categories are forbidden, and accepted findings that need a reason and a date and expire on their own.
- Input as a tar for the image you just built, or a registry reference for an image already out there.
- Runs as the caller's user so the reports belong to whoever ran it.
- Databases baked in at build time: works without network, refreshed weekly.
- A worked example: a Spring Boot image released through the gate in GitHub Actions.
