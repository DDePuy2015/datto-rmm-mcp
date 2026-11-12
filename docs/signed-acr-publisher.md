# Datto signed ACR publisher preparation

This prepares publication only. It does not merge source, configure credentials,
create identities, grant permissions, publish images or change Container Apps.
The workflow remains dormant while DATTO_ACR_PUBLICATION_ENABLED is unset.

## Artifact flow

1. Every PR and main push runs the canonical source checks and builds one OCI
   archive from the exact checkout and pinned official Node base. Private-package
   credentials enter only as a BuildKit secret, never as a build argument.
2. That archive, including BuildKit maximum provenance and SPDX SBOM, is loaded
   into the local Docker daemon. Tests and scans run against its exact config ID.
   A package verifier checks the full reachable OCI graph, source labels and
   tracked-file hashes, runtime identity, run/attempt, audits and scan coverage.
3. Production npm audit, every runtime vulnerability severity and all secret
   scans must be zero. There is no Datto residual-risk exception. Failure retains
   sanitized diagnostic evidence, never a validated release package.
4. A separate manual workflow requires exact current main, an explicit publication
   confirmation, first attempt, configured enablement, successful latest main CI,
   trusted Semgrep evidence, and an immutable merged Ops scope record.
5. Its reusable validation job creates a fresh package in the same workflow run.
   The publisher downloads only that exact source/run/attempt artifact, verifies
   it again against the checked-out source, and rechecks Semgrep/Ops before Azure
   login. It never rebuilds an image after credentials are obtained.
6. A digest-preserving copy targets only the existing
   summititmcpacr.azurecr.io/datto-rmm-mcp repository. The publisher checks the
   registry root bytes and round-trips the whole OCI graph before keyless Cosign
   signing. Signature, CycloneDX and source/run/approval-scope provenance are
   verified against the exact digest and this workflow's main-branch identity.

Tags include the full source SHA and run/attempt and are locators, not deployment
identities. A different existing tag is never overwritten. Partial publication
is recorded separately. Reruns are refused: reconcile the retained evidence and
obtain a fresh explicit decision before any new dispatch.

## Required configuration decision

Read-only inspection on November 12 found the Datto ACR repository exists, but
this GitHub repository has no Azure publisher secrets, variables or environments.
Existing registered ACR publisher identities federate to Proxy, IT Glue or
FortiManager, not Datto. Their identities must not be repurposed silently.

The registry currently uses LegacyRegistryPermissions. Standard AcrPush is
registry-wide, not restricted to this one repository. Provisioning a dedicated
Datto workload identity with that grant therefore needs explicit approval of
that scope. Moving the whole registry to ABAC is a separate platform change
that can affect existing pull/push identities and is not part of this patch.
A repository-scoped credential design would need its own reviewed lifecycle.

Datto currently has GitHub's name-based default OIDC subject. Any choice to
adopt immutable owner/repository IDs must be coordinated with the exact Azure
federation subject; no subject setting was changed. A future setup must supply
these existing-pattern configuration names without placing values in source:

- AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID repository secrets.
- OPS_READ_TOKEN: read-only access to the private summit-mcp-ops repository.
  The Datto repository's GITHUB_TOKEN is not assumed to have cross-repo access.
- DATTO_ACR_PUBLICATION_ENABLED repository variable, explicitly true only after
  the identity, scope, record-reader and reviewed publisher are approved.

The workflow never uses registry admin passwords, creates credentials, alters
federation, changes role assignments, or enables itself. No such setup has been
authorized or performed by this preparation.

## Immutable Ops record format

The URL must identify deployments/<record>.md at a full commit in
DDePuy2015/summit-mcp-ops, and that commit must already be reachable from main.
The file must contain exactly one fenced JSON block tagged datto-publication:

```datto-publication
{
  "schemaVersion": 1,
  "service": "datto",
  "sourceCommit": "FULL_REVIEWED_DATTO_MAIN_SHA",
  "destination": "summititmcpacr.azurecr.io/datto-rmm-mcp",
  "decision": "publish-only"
}
```

The record binds the approved scope and source; it does not replace the owner's
explicit manual-dispatch confirmation. The workflow retains only sanitized
record metadata and a hash, not the private document's full contents.
Publication approval does not authorize Azure staging or production traffic.

## Verification limits

Offline fixtures exercise malformed/tampered archives, wrong source/config/run,
missing or failing evidence, lower-severity findings, source-file substitutions,
Semgrep provenance, record scope, signature payloads and workflow guards. Real
Linux validation must additionally establish OCI export/load/parser and scanner
compatibility. Registry copying, keyless signing, Azure federation and production
acceptance remain unexecuted until separately authorized. The non-publishing PR
validation artifact is not an already signed or deployed release.

## First Linux validation findings

The first PR validation passed source/runtime checks but exposed a fixable medium
Alpine zlib finding (CVE-2026-4738, installed 1.3.2-r1, fixed 1.4-r0). The runtime
now requires zlib >=1.4-r0 from the official Alpine 3.24 repository. This is a
package fix, not a scan suppression. The same run also exercised BuildKit 0.34.2
OCI referrer-format attestations and revealed an artifact path compatibility
issue; regression checks cover both before repeating Linux validation.
