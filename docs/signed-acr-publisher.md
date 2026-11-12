# Datto signed ACR publisher

The publisher is manual and remains dormant while DATTO_ACR_PUBLICATION_ENABLED
is unset. Merging this workflow does not authorize signing, image publication,
Container Apps staging or production traffic changes.

## Consistent release-record handling

Datto follows the established FortiManager approach: an operator verifies the
private Ops release record before dispatch, and the publisher carries its
immutable URL into signed provenance. GitHub Actions does not read the private
Ops repository and needs no dedicated Ops token.

Record-content verification is an operator responsibility, not an automated workflow gate.
The workflow checks the immutable URL format and requires explicit publication
confirmation, but it cannot itself prove that the operator read the record or
that the record contains the approved scope. Do not describe the URL in signed
provenance as proof of an in-workflow record-content check.

Reference: FortiManager publisher run
[43107173849](https://github.com/DDePuy2015/summit-fortimanager-mcp/actions/runs/43107173849)
at source 4dc7d2ecebaa86c9b520f5d4f8b4161dc7102e91. This consistency change moves
only the location of the record check. It retains Datto's zero-finding policy,
source/image binding, main-only manual request and disabled-by-default controls.

## Before any publication

1. Review and merge the intended Datto source. Require successful exact-main CI,
   MCP assertions, full source/image validation and trusted Semgrep evidence.
2. Prepare the separately approved Ops publication record for that final source,
   merge it into summit-mcp-ops main, and use its full immutable commit URL.
3. From an operator session that already has authorized GitHub CLI access to Ops,
   run the strict read-only verifier below. It verifies the pinned commit is
   merged, checks the file identity and hash, and matches the exact Datto source,
   destination and publish-only scope. Missing access or any mismatch is a stop.
   Do not extract the operator's credential or copy it to an Actions secret.
4. Retain the sanitized verification result with the operator's release evidence.
   Obtain explicit approval for the exact source and publication action, then
   supply that same source and record URL to the manual publisher. If main or the
   approved scope changes, stop and verify the new request instead.

Example in a shell with existing authenticated gh access:

```sh
export GITHUB_SHA="$(gh api repos/DDePuy2015/datto-rmm-mcp/git/ref/heads/main --jq .object.sha)"
export RELEASE_RECORD_URL="https://github.com/DDePuy2015/summit-mcp-ops/blob/FULL_OPS_COMMIT/deployments/RECORD.md"
python3 scripts/verify-publication-record.py > ../datto-ops-record-check.json
```

The example requires an actual approved record; placeholders are rejected. The
verifier never grants approval or dispatches a workflow. Its sanitized output
contains identity and hash metadata, not the private document body. That local
receipt is not automatically consumed or attested by the publishing workflow.

## Artifact flow

1. Every PR and main push runs canonical source checks and builds one OCI archive
   from the exact checkout and pinned official Node base. Private-package
   credentials enter only as a BuildKit secret, never a build argument.
2. The archive includes BuildKit maximum provenance and SPDX SBOM. Its selected
   runtime is loaded locally; tests and scans use its exact config ID. The package
   verifier checks every reachable OCI blob, tracked-source hashes, source labels,
   runtime identity, run/attempt, audit results and scan coverage.
3. Production npm audit, runtime vulnerabilities at every severity and secret
   scans must all be zero. No Datto residual-risk exception exists. Failure keeps
   sanitized diagnostic evidence, never a validated release package.
4. The manual publisher requires exact current main, explicit publication
   confirmation, first attempt, configured enablement, successful latest main CI,
   trusted Semgrep evidence and the immutable Ops record URL checked separately.
5. Reusable validation creates a fresh package in that same run. Before Azure
   login, the publisher verifies the exact source/run/attempt artifact against the
   checkout and rechecks Semgrep. It never rebuilds after obtaining credentials.
6. Digest-preserving copy targets only summititmcpacr.azurecr.io/datto-rmm-mcp.
   Registry root bytes and the complete round-tripped OCI graph must match before
   keyless Cosign signing. The signature, CycloneDX SBOM and source/run provenance
   are verified against the exact digest and main-branch workflow identity.
   Provenance includes the operator-supplied immutable release-record URL.

Full-SHA/run/attempt tags are locators, not deployment identities. Different
existing tags are never overwritten. Partial publication is recorded separately.
Reruns are refused: reconcile the evidence and obtain a fresh explicit decision
before another dispatch. Publication approval does not authorize deployment.

## Publisher configuration

On November 12, the owner approved the dedicated Datto managed identity and its
registry-scoped AcrPush grant, matching the FortiManager pattern. The main-only
GitHub OIDC trust uses immutable owner/repository IDs. The three existing-pattern
Azure identifier settings are configured:

- AZURE_CLIENT_ID
- AZURE_TENANT_ID
- AZURE_SUBSCRIPTION_ID

There is no Ops-token requirement. GitHub's built-in token handles this Datto
repository's reads; it is not assumed to read the private Ops repository.
DATTO_ACR_PUBLICATION_ENABLED remains unset until publication is separately
approved. Never enable it merely to test a login or a release-record check.

The registry uses LegacyRegistryPermissions, so AcrPush grants pull/push across
all repositories in that registry. The workflow's Datto destination restriction
does not reduce that underlying Azure permission. Moving the registry to ABAC is
a separate platform change affecting existing identities and is not part of this
workflow change. The workflow never uses registry admin passwords, provisions
identities, alters role assignments or federation, or enables itself.

## Immutable Ops record format

The separate verifier requires deployments/<record>.md at a full commit in
DDePuy2015/summit-mcp-ops, already reachable from main, with exactly one fenced
JSON block tagged datto-publication:

```datto-publication
{
  "schemaVersion": 1,
  "service": "datto",
  "sourceCommit": "FULL_REVIEWED_DATTO_MAIN_SHA",
  "destination": "summititmcpacr.azurecr.io/datto-rmm-mcp",
  "decision": "publish-only"
}
```

The record describes the approved scope and source. It does not substitute for
the owner's explicit approval of the manual publication action.

## Verification limits

Offline fixtures exercise malformed/tampered archives, wrong source/config/run,
missing or failing evidence, lower-severity findings, source substitutions,
Semgrep provenance, record scope, signature payloads and workflow guards. Linux
CI additionally validates real OCI export/load/parser and scanner compatibility.
Registry copying, keyless signing and live Azure federation login are not proven
by a non-publishing CI artifact. No Datto ACR publication or deployment has been
performed by this preparation.

The first all-severity Linux validation identified medium Alpine zlib finding
CVE-2026-4738. The runtime now requires the official fixed zlib >=1.4-r0; subsequent
full scans passed with no suppression. Strict BuildKit 0.34.2 OCI referrer support
and runner-local artifact paths have real Linux validation and regression tests.
