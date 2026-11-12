"""Offline contracts for deliberately dormant, same-run publication wiring."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.validation = (ROOT / ".github/workflows/fork-container-validation.yml").read_text(encoding="utf-8-sig")
        self.publisher = (ROOT / ".github/workflows/publish-image.yml").read_text(encoding="utf-8-sig")

    def test_python_sources_parse(self):
        for path in (ROOT / "scripts").glob("*release*.py"):
            with self.subTest(path=path.name):
                ast.parse(path.read_text(encoding="utf-8-sig"))

    def test_publication_is_manual_main_first_attempt_and_dormant(self):
        self.assertIn("'on':\n  workflow_dispatch:", self.publisher)
        for trigger in ("pull_request:", "  push:", "schedule:", "workflow_run:"):
            self.assertNotIn(trigger, self.publisher)
        for gate in ("github.repository == 'DDePuy2015/datto-rmm-mcp'", "github.event_name == 'workflow_dispatch'",
                     "github.ref == 'refs/heads/main'", "github.run_attempt == 1", "inputs.publication_confirmed",
                     "vars.DATTO_ACR_PUBLICATION_ENABLED == 'true'"):
            self.assertIn(gate, self.publisher)
        self.assertIn("cancel-in-progress: false", self.publisher)

    def test_validation_has_no_registry_or_oidc_authority(self):
        for forbidden in ("azure/login@", "docker login", "skopeo login", "cosign sign", "id-token:", "--push", "push: true"):
            self.assertNotIn(forbidden, self.validation)
        self.assertIn('"docker-daemon:$LOCAL_IMAGE"', self.validation)
        self.assertEqual(self.publisher.count("id-token: write"), 1)
        self.assertNotIn("secrets: inherit", self.publisher)

    def test_single_build_artifact_is_validated_and_exported(self):
        self.assertEqual(self.validation.count("docker buildx build "), 1)
        for requirement in ("--provenance=mode=max", "--sbom=true", "--no-cache", "--output \"type=oci,dest=$RELEASE/image.oci.tar\"",
                            "release-package.py create", "release-package.py verify", "--repository-root ."):
            self.assertIn(requirement, self.validation)
        self.assertIn("name: datto-release-${{ env.EXPECTED_SHA }}-${{ github.run_id }}-${{ github.run_attempt }}", self.validation)
        self.assertIn("name: datto-release-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}", self.publisher)

    def test_package_and_source_are_checked_before_credentials(self):
        verify = self.publisher.index("release-package.py verify --directory release")
        login = self.publisher.index("uses: azure/login@")
        self.assertLess(verify, login)
        self.assertLess(self.publisher.index("verify-semgrep-release.py > publication/semgrep.json"), login)
        self.assertLess(self.publisher.index("verify-publication-record.py > publication/ops-record.json"), login)
        self.assertIn("release-package.py request", self.publisher[:login])
        self.assertIn("Missing successful latest exact-main validation", self.publisher)
        publish_job = self.publisher[self.publisher.index("  publish:\n"):]
        self.assertNotIn("docker build", publish_job)

    def test_all_severity_scans_and_no_suppression(self):
        self.assertIn("--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", self.validation)
        self.assertIn("--ignore-unfixed=false", self.validation)
        self.assertIn("--ignorefile /dev/null", self.validation)
        self.assertIn("--list-all-pkgs", self.validation)
        self.assertNotIn("ignore-policy", self.validation)
        self.assertIn("Any severity blocks release export", self.validation)

    def test_copy_roundtrip_signatures_and_attestations_use_exact_digest(self):
        for requirement in ("--preserve-digests", "cmp publication/local-index.json publication/registry-index.json",
                            "release-package.py compare", "verify-release-attestations.py", "cosign verify --certificate-identity",
                            "--certificate-oidc-issuer", "https://slsa.dev/provenance/v1", "datto-rmm-mcp/.github/workflows/publish-image.yml@refs/heads/main"):
            self.assertIn(requirement, self.publisher)
        self.assertIn("ref=\"$ACR_SERVER/$ACR_REPOSITORY@$expected\"", self.publisher)
        self.assertNotIn("az containerapp", self.publisher)
        self.assertNotIn("az role assignment create", self.publisher)

    def test_external_actions_are_immutable(self):
        for workflow in (self.publisher, self.validation):
            for action in re.findall(r"uses:\s+(\S+)", workflow):
                if action.startswith("./"):
                    continue
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_python_checks_run_without_dirtying_build_context(self):
        self.assertIn("PYTHONDONTWRITEBYTECODE: '1'", self.validation)
        self.assertIn("python3 -m unittest discover -s tests/release", self.validation)
        self.assertIn("test -z \"$(git status --porcelain)\"", self.validation)

    def test_artifact_paths_are_absolute_outside_build_context_without_parent_segments(self):
        self.assertIn("RELEASE: ${{ runner.temp }}/datto-release", self.validation)
        self.assertIn("EVIDENCE: ${{ runner.temp }}/datto-release/reports", self.validation)
        self.assertNotIn("/../", self.validation)

    def test_runtime_base_has_fixed_zlib_without_scan_exception(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        production = dockerfile[dockerfile.index(" AS production"):]
        self.assertIn("RUN apk add --no-cache 'zlib>=1.4-r0'", production)
        self.assertNotIn("CVE-2026-4738", self.validation)
