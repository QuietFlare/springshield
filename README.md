# springshield

[![release](https://img.shields.io/github/v/release/QuietFlare/springshield?label=release)](https://github.com/QuietFlare/springshield/releases/latest)
[![image](https://img.shields.io/badge/ghcr.io-quietflare%2Fspringshield-blue)](https://github.com/QuietFlare/springshield/pkgs/container/springshield)
[![ci](https://github.com/QuietFlare/springshield/actions/workflows/ci.yml/badge.svg)](https://github.com/QuietFlare/springshield/actions/workflows/ci.yml)
[![licence](https://img.shields.io/github/license/QuietFlare/springshield)](LICENSE)

The release gate for Spring Boot images. It runs on any container image; Boot is where it knows the most.


One command, the same on a laptop and in CI, on the image you just built and have not pushed:

```bash
docker save app:1.4.0 -o image.tar
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/image.tar:/image.tar:ro" \
  -v "$PWD/Dockerfile:/Dockerfile:ro" \
  -v "$PWD/gate.yaml:/gate.yaml:ro" \
  -v "$PWD/reports:/reports" \
  ghcr.io/quietflare/springshield:1 /image.tar --dockerfile /Dockerfile --policy /gate.yaml
```

The app hands over three things: the image as a tar, its Dockerfile for the misconfiguration check, and its `gate.yaml`, the policy that says what blocks and which findings are accepted and why. Without `--policy` the built-in default applies: HIGH and CRITICAL block, nothing is accepted.

The gate runs every check, writes one report per check into `reports/`, and prints one verdict line. The exit code is zero only when the image may ship; the push comes after, never before.

The same command with a registry reference instead of a tar audits an image that is already out there, yours from last month or a vendor's:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/reports:/reports" ghcr.io/quietflare/springshield:1 ghcr.io/you/app:1.4.0
```

## The rule

A check that scans nothing must fail, not pass.

Every check in springshield asserts that it did the work before it reports a result: the scanner found an operating system and packages, the database was present, files were counted. A green that means "finished" is worse than a red, because nobody looks at a green. This rule exists because, in one afternoon of setting up seven checks by hand, three of them passed without doing anything.

## The checks

| Check | What it answers | Blocks when |
|---|---|---|
| vulnerabilities | which packages carry known, fixable CVEs | HIGH or CRITICAL with a fix, unless accepted in the policy |
| secrets | did a key, token or password end up in a layer | any |
| misconfiguration | does the image run as root, use a floating tag, lack a user | HIGH or CRITICAL |
| SBOM | what exactly is in the image, as CycloneDX | never, the file is the result |
| licences | which licences the contents carry | only those the policy forbids |
| malware | known malicious files, ClamAV | any |
| boot-profile | is a development profile active, in the jar, the ENV or the command line | any profile named in the policy's `dev_profiles` |
| boot-actuator | are Actuator endpoints beyond health and info exposed with no Spring Security in the image | yes |
| boot-layers | is the application one fat jar, re-shipped whole on every build | only if the policy says so; reported otherwise |
| signature and provenance | sign the image by digest, attach the SBOM and a provenance statement | on request, after the other checks pass |

The first nine run in the gate. Signing stays in the pipeline for now, because keyless signing uses the pipeline's own identity; see the example.

## The verdict

Besides the exit code, every run writes `reports/verdict.json`: the image digest, the verdict, the gate's version and the dates of its databases, the policy's hash, and each check's result with its detail. That file is what a release page shows and what a cluster admission policy reads.

## Versions

A release is a tag, `v1.0.0`, and an image, `ghcr.io/quietflare/springshield:1.0.0-20261022`. The dated tag never moves. Every Monday the newest release is rebuilt with fresh databases under a new date, and the floating tags `:1.0.0`, `:1.0` and `:1` move to it. Pin the dated tag when a verdict must be reproducible; use `:1` when you want the newest databases.

## The policy

`gate.yaml`, committed beside the Dockerfile of the application. It says what blocks, what only reports, and which findings are accepted and why. An accepted CVE needs a reason and a date; it is the written form of "not affected, and here is why".

```yaml
version: 1
block:
  severity: [HIGH, CRITICAL]
  ignore_unfixed: true
boot:
  block: [actuator, dev-profile]
  dev_profiles: [dev, development, local, test, debug]
accepted:
  - id: CVE-2026-111943
    reason: helper binary runs once at start, opens no socket
    until: 2026-12-31
  - id: BOOT-UNLAYERED
    reason: image is built once a month, the layer saving is not worth the Dockerfile
    until: 2027-03-31
```

## Spring Boot

The gate finds the application whether it is one fat jar or exploded on disk, as `layertools extract` and buildpacks leave it, and reads its `application` files, the names of its dependencies, and the image's ENV and command line. Three checks follow, and each says "not a Spring Boot image" when there is nothing to judge.

A development profile active anywhere, `spring.profiles.active` in the jar, `SPRING_PROFILES_ACTIVE` in the ENV, `-Dspring.profiles.active` on the command line, blocks: the image would start as a dev build. Actuator endpoints beyond `health` and `info` exposed over HTTP block when Spring Security is not in the image; when it is, the gate reports the exposure and says it cannot read the filter chain. One fat jar is reported, not blocked, unless the policy lists `unlayered`; it means every build re-ships every dependency. Each finding has an id, `BOOT-DEV-PROFILE`, `BOOT-ACTUATOR`, `BOOT-UNLAYERED`, and is accepted like a CVE, with a reason and a date.

The first worked example is a Spring Boot image built from a layered jar on a Temurin base, in `examples/aurae`.

## Why not a buildpack or a scanner action

Buildpacks build; this gates. Scanner actions run one tool each and leave the assertions, the policy and the verdict to the pipeline author. springshield is the part between the scanners and the push, packaged once so a laptop and a pipeline get the same answer.

## Licence

MIT. Contributions welcome; the checks are shell and the policy is YAML on purpose, so anyone can read what the gate does.
