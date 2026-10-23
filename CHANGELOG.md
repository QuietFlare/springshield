# Changelog

Each release is also a container image, `ghcr.io/quietflare/springshield:<version>-<date>`, rebuilt every Monday with fresh databases under a new date. The floating tags `:<version>`, `:<major.minor>` and `:<major>` move to the newest rebuild.

## 1.1.0

The Spring Boot checks.

- Three checks on a Boot application, fat jar or exploded: `boot-profile` blocks on a development profile active in the jar, the ENV or the command line; `boot-actuator` blocks on Actuator endpoints beyond health and info exposed with no Spring Security in the image; `boot-layers` reports one fat jar, and blocks only when the policy says so.
- Policy: `boot.block` names which Boot findings block, `boot.dev_profiles` which profile names count as development. Findings are accepted by id, `BOOT-DEV-PROFILE`, `BOOT-ACTUATOR`, `BOOT-UNLAYERED`, with a reason and a date, like a CVE.
- An image that is not a Spring Boot application passes the three checks with "nothing to judge".
- The image's files and config are extracted once and shared by the malware and Boot checks.
- Two Boot fixture images in `tests/boot`, built without Java, prove the checks in CI.

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
