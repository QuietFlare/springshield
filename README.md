# springshield

The release gate for Spring Boot images. It runs on any container image; Boot is where it knows the most.

One command, the same on a laptop and in CI:

```bash
docker run --rm -v "$PWD/reports:/reports" ghcr.io/quietflare/springshield:1 ghcr.io/you/app:1.4.0
```

It runs every check, writes one report per check into `reports/`, and prints one verdict line. The exit code is zero only when the image may ship.

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
| signature and provenance | sign the image by digest, attach the SBOM and a provenance statement | on request, after the other checks pass |

The first three are in today. The rest arrive in order over the week.

## The policy

`gate.yaml`, committed beside the Dockerfile of the application. It says what blocks, what only reports, and which findings are accepted and why. An accepted CVE needs a reason and a date; it is the written form of "not affected, and here is why".

```yaml
version: 1
block:
  severity: [HIGH, CRITICAL]
  ignore_unfixed: true
accepted:
  - id: CVE-2026-111943
    reason: helper binary runs once at start, opens no socket
    until: 2026-12-31
```

## Spring Boot

The first worked example is a Spring Boot image built from a layered jar on a Temurin base, in `examples/aurae`. The Boot-specific checks, an Actuator exposed without authentication, a dev profile baked into the jar, a jar not split into layers, come after the generic ones.

## Why not a buildpack or a scanner action

Buildpacks build; this gates. Scanner actions run one tool each and leave the assertions, the policy and the verdict to the pipeline author. springshield is the part between the scanners and the push, packaged once so a laptop and a pipeline get the same answer.

## Licence

MIT. Contributions welcome; the checks are shell and the policy is YAML on purpose, so anyone can read what the gate does.
