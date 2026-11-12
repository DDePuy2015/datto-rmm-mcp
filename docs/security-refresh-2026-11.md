# November 2026 Datto security refresh

This refresh continues draft PR #20 without changing the Datto SDK identity or
provider tool behavior. The November 12 production audit found four newly
reported vulnerable packages in the previously clean October lockfile.

## Dependency remediation

The compatible locked updates are @hono/node-server 2.1.7, body-parser 2.4.0,
qs 6.17.1 and Zod 4.6.7. body-parser also requires content-type 2.1.0 and
iconv-lite 0.7.3. No other lock entries or root dependencies are changed.

Relevant advisories:

- https://github.com/advisories/GHSA-rmxm-3fg6-px4f
- https://github.com/advisories/GHSA-27r3-jxmh-p828
- https://github.com/advisories/GHSA-6pq8-jhm2-2vcw
- https://github.com/advisories/GHSA-mrhx-c7xc-m3w5

A clean version audit is not proof that every advisory path was reachable.
The complete production graph is patched even where a dependency feature is
not used by the service.

## HTTP input bound

Both Node and Worker HTTP transports set maxRequestBodySize to 256 KiB,
reducing the SDK default of 4 MiB. The SDK rejects declared or streamed bodies
over this byte limit with HTTP 413 before JSON parsing and request validation.
Authentication still runs first. Responses are not limited by this option.
Datto tools use small scalar arguments and an optional quickjob string-variable
map, not file uploads. Existing valid smaller requests are unchanged; callers
sending larger variable maps must reduce their request size.

For https://github.com/advisories/GHSA-46jr-4wx8-v453, this repository uses the
lower-level Server, not McpServer. The advisory's maxToolInputElements option
therefore does not apply here, and recursive McpServer tool-schema validation
is not used. The shared byte ceiling bounds the HTTP input before the SDK's
shallow argument-record validation, with patched Zod retained. This is not a
claim of universal DoS resistance or a new stdio framing limit.

The Node and Worker regressions use real transports and a mocked Datto client:
exact byte limit, limit plus one, streamed input without Content-Length,
multibyte UTF-8, auth ordering, and service recovery. The container fixture
checks the patched versions and an actual HTTP 413 inside the non-root image.
No real Datto credentials or provider write calls are needed.

## Verification boundaries

A fresh November 12 rerun of the October head installed canonical dependencies
and passed source checks, then correctly failed the new production audit gate.
It did not build or scan an image after that failure. The later patched-head
validation must pass before this refresh is considered verified.

Local Windows tests use locked public packages and the existing local Datto
SDK 1.1.0 artifact because canonical local installation returned a GitHub
Packages authentication error. They are explicitly offline compatibility
checks, not proof of canonical private-package integrity. The independent
GitHub validation workflow must supply the canonical install and real Linux
image evidence.

## Publisher preparation

The inherited CI Docker job and reusable Release job now require the exact
upstream WYRE-AI repository, a push event, and main. Neither can publish from
the Summit fork on PR or main pushes. Source checks remain in CI and Fork
Container Validation; the inherited Release job is intentionally skipped.
This removes accidental publication to the fork GHCR path or the upstream
WYRE-AI GHCR destination. It does not create a Summit ACR publisher.

A separate publisher change must adapt the established Summit manual,
exact-main-source, validated-OCI-artifact workflow to one Datto image, preserving
signature, SBOM, provenance and immutable-digest verification. Existing Azure
identity and repository-scope permissions must be checked before claiming a
credential or permission blocker. No new grant is authorized by this patch.

## Release hold

Source preparation and a successful validation image do not authorize merge,
publication, signing, Azure staging, or production traffic. Any release needs
reviewed publication destinations, an exact-source signed immutable ACR image,
fresh artifact evidence, and the Summit Ops deployment and rollback gates.
The validation-only image is local to CI and is not a release artifact.
