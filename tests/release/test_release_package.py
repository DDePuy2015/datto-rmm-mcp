"""Offline synthetic request, graph, gate, tamper and source binding proofs."""
import contextlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from fixtures import SOURCE, OTHER_SOURCE, archive, evidence, release, request_env


class RequestTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(release.request(request_env()), SOURCE)

    def test_every_field_required(self):
        for field in request_env():
            value = request_env()
            del value[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                release.request(value)

    def test_bad_values(self):
        changes = {"GITHUB_REPOSITORY": "other/repo", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/dev",
                   "GITHUB_RUN_ATTEMPT": "2", "GITHUB_RUN_ID": "0", "GITHUB_SHA": "short",
                   "MAIN_SHA": OTHER_SOURCE, "REQUESTED_SOURCE_SHA": OTHER_SOURCE, "PUBLICATION_CONFIRMED": "false",
                   "RELEASE_RECORD_URL": request_env()["RELEASE_RECORD_URL"].replace(SOURCE, "main"),
                   "AZURE_CLIENT_ID": "missing"}
        for key, val in changes.items():
            with self.subTest(field=key), self.assertRaises(ValueError):
                release.request({**request_env(), key: val})


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "image.oci.tar"

    def inspect(self, **kwargs):
        config = archive(self.path, **kwargs)
        return release.inspect_archive(self.path, SOURCE, config)

    def test_valid_graph(self):
        self.assertEqual(len(self.inspect()["graphDigests"]), 8)

    def test_paths_links_duplicates(self):
        for name, kind in [("../outside", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("blobs/link", tarfile.SYMTYPE), ("index.json", tarfile.REGTYPE)]:
            with self.subTest(path=name), self.assertRaises(ValueError):
                self.inspect(extra_members=[(name, b"x", kind)])

    def test_corrupt_blob(self):
        with self.assertRaises(ValueError):
            self.inspect(corrupt_blob=True)

    def test_negative_graph_semantics(self):
        edits = [
            ("config", lambda v: v["config"].update(User="root")),
            ("config", lambda v: v["config"].update(Cmd=["sh"])),
            ("config", lambda v: v["config"]["Labels"].update({"org.opencontainers.image.source": "https://example.org"})),
            ("config", lambda v: v["config"]["Labels"].update({"org.opencontainers.image.revision": OTHER_SOURCE})),
            ("index", lambda v: v["manifests"][0]["platform"].update(architecture="arm64")),
            ("index", lambda v: v["manifests"][0].update(size=1)),
            ("statements", lambda v: v[0]["predicate"].update(materials=[])),
            ("statements", lambda v: v[0]["predicate"]["materials"][0].update(uri="pkg:docker/attacker/node@26")),
            ("statements", lambda v: v[0]["predicate"].pop("buildConfig")),
            ("statements", lambda v: v[0]["subject"][0].update(digest={"sha256": "0" * 64})),
            ("statements", lambda v: v.pop()),
            ("statements", lambda v: v.append(v[0]))]
        for stage, edit in edits:
            with self.subTest(stage=stage, edit=edit), self.assertRaises(ValueError):
                self.inspect(mutate=lambda s, v: edit(v) if s == stage else None)

    def test_wrong_tested_config(self):
        archive(self.path)
        with self.assertRaises(ValueError):
            release.inspect_archive(self.path, SOURCE, "sha256:" + "0" * 64)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.reports = evidence(self.root)

    def metadata(self, **kwargs):
        return release.package_metadata(self.root, SOURCE, kwargs.get("run_id", "123"), kwargs.get("attempt", "1"))

    def test_valid_package_and_pr_attempt(self):
        self.assertEqual(self.metadata()["sourceCommit"], SOURCE)
        value = json.loads((self.reports / "validation.json").read_text())
        value["runAttempt"] = "2"
        (self.reports / "validation.json").write_text(json.dumps(value))
        self.assertEqual(self.metadata(attempt="2")["runAttempt"], "2")

    def test_all_required_reports(self):
        for path in self.reports.iterdir():
            original = path.read_text()
            path.write_text("{}")
            with self.subTest(path=path.name), self.assertRaises((ValueError, KeyError)):
                self.metadata()
            path.write_text(original)

    def test_negative_gates(self):
        edits = [
            ("validation.json", lambda v: v.update(runtimeChecks="failed")),
            ("validation.json", lambda v: v.update(sourceCommit=OTHER_SOURCE)),
            ("validation.json", lambda v: v.update(runId="124")),
            ("validation.json", lambda v: v.update(imageId="sha256:" + "0" * 64)),
            ("production-audit.json", lambda v: v["metadata"]["vulnerabilities"].update(low=1)),
            ("image-scan-summary.json", lambda v: v["results"].pop()),
            ("image-scan-summary.json", lambda v: v.update(imageId="sha256:" + "0" * 64)),
            ("image-scan-summary.json", lambda v: v["results"][0].update(secrets=[{"id": "fixture"}])),
            ("source-files.json", lambda v: v.update({"../outside": "a" * 64}))]
        for severity in ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            edits.append(("image-scan-summary.json", lambda v, s=severity:
                          v["results"][0].update(vulnerabilities=[{"severity": s}])))
        for name, edit in edits:
            path = self.reports / name
            original = path.read_text()
            value = json.loads(original)
            edit(value)
            path.write_text(json.dumps(value))
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.metadata()
            path.write_text(original)

    def cli(self, mode, *extra):
        args = ["release-package.py", mode, "--directory", str(self.root), "--source", SOURCE, *extra]
        with patch.dict("os.environ", {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}), \
                patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
            release.main()

    def test_cli_roundtrip_and_tamper(self):
        self.cli("create")
        self.cli("verify")
        self.cli("compare", "--archive", str(self.root / "image.oci.tar"))
        (self.reports / "extra.log").write_text("tamper")
        with self.assertRaises(ValueError):
            self.cli("verify")

    def test_run_replay_rejected(self):
        with self.assertRaises(ValueError):
            self.metadata(run_id="124")


if __name__ == "__main__":
    unittest.main()

class ExtendedBindingTests(PackageTests):
    def test_checkout_hashes_and_path_set(self):
        checkout = self.root / "checkout"
        checkout.mkdir()
        (checkout / "Dockerfile").write_bytes(b"fixture")
        hashes = {"Dockerfile": release.file_digest(checkout / "Dockerfile").removeprefix("sha256:")}
        (self.reports / "source-files.json").write_text(json.dumps(hashes))
        def check_output(args, **kwargs):
            return SOURCE + "\n" if "rev-parse" in args else b"Dockerfile\x00"
        with patch("subprocess.check_output", side_effect=check_output):
            release.package_metadata(self.root, SOURCE, "123", "1", checkout)
            (checkout / "Dockerfile").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "Checkout bytes"):
                release.package_metadata(self.root, SOURCE, "123", "1", checkout)
        with patch("subprocess.check_output", side_effect=[SOURCE + "\n", b"Dockerfile\x00extra\x00"]):
            with self.assertRaisesRegex(ValueError, "Tracked source"):
                release.package_metadata(self.root, SOURCE, "123", "1", checkout)

    def test_v1_max_provenance(self):
        def convert(stage, value):
            if stage == "statements":
                legacy = value[0]["predicate"]
                value[0]["predicateType"] = "https://slsa.dev/provenance/v1"
                value[0]["predicate"] = {"buildDefinition": {
                    "buildType": "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
                    "internalParameters": {"buildConfig": {"llbDefinition": [{"id": "fixture"}]}},
                    "resolvedDependencies": legacy["materials"]}}
        path = self.root / "v1.tar"
        config = archive(path, mutate=convert)
        release.inspect_archive(path, SOURCE, config)
        def invalid(stage, value):
            convert(stage, value)
            if stage == "statements":
                value[0]["predicate"]["buildDefinition"]["internalParameters"] = {}
        config = archive(path, mutate=invalid)
        with self.assertRaisesRegex(ValueError, "Maximum BuildKit"):
            release.inspect_archive(path, SOURCE, config)

    def test_archive_roundtrip_changed_graph(self):
        self.cli("create")
        path = self.root / "roundtrip.tar"
        def change(stage, value):
            if stage == "statements":
                value[1]["predicate"]["name"] = "different SBOM"
        archive(path, mutate=change)
        with self.assertRaisesRegex(ValueError, "Round-trip graph"):
            self.cli("compare", "--archive", str(path))

    def test_unreachable_blob_rejected(self):
        path = self.root / "extra.tar"
        config = archive(path, extra_members=[("blobs/sha256/" + "0" * 64, b"extra", tarfile.REGTYPE)])
        with self.assertRaisesRegex(ValueError, "Unreachable"):
            release.inspect_archive(path, SOURCE, config)

class OCIArtifactTests(ArchiveTests):
    """Pinned BuildKit v0.34.2 OCI artifact manifest, not an extra image graph."""
    def inspect(self, **kwargs):
        kwargs["oci_artifact"] = True
        return super().inspect(**kwargs)

    def test_artifact_subject_fields_and_extra_edges_fail_closed(self):
        changes = [lambda v: v["subject"].update(digest="sha256:" + "0" * 64),
                   lambda v: v["subject"].update(size=v["subject"]["size"] + 1),
                   lambda v: v["subject"].update(mediaType=release.INDEX),
                   lambda v: v["subject"].update(urls=["https://example.invalid/blob"]),
                   lambda v: v["subject"].update(data="e30="),
                   lambda v: v["subject"].update(platform={"os": "linux", "architecture": "amd64"}),
                   lambda v: v.update(subject=None), lambda v: v.pop("subject"),
                   lambda v: v.pop("artifactType"), lambda v: v.update(artifactType="unknown")]
        for edit in changes:
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.inspect(mutate=lambda stage, value: edit(value) if stage == "attestation" else None)

    def test_artifact_empty_config_cannot_carry_other_data(self):
        changes = [{"data": "e30=\n"}, {"data": "e30"}, {"data": "eA=="}, {"size": 3},
                   {"digest": "sha256:" + "0" * 64}, {"mediaType": "application/vnd.oci.image.config.v1+json"},
                   {"urls": ["https://example.invalid/blob"]}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.inspect(mutate=lambda stage, value:
                             value["config"].update(change) if stage == "attestation" else None)

    def test_artifact_missing_or_corrupt_empty_blob_rejected(self):
        config = archive(self.path, oci_artifact=True)
        empty_name = "blobs/sha256/" + release.digest(b"{}").split(":")[1]
        with tarfile.open(self.path) as original:
            entries = [(member, original.extractfile(member).read()) for member in original]
        for replacement in (None, b"[]"):
            with tarfile.open(self.path, "w") as rewritten:
                for member, data in entries:
                    if member.name == empty_name:
                        if replacement is None:
                            continue
                        data = replacement
                    rewritten.addfile(member, io.BytesIO(data))
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                release.inspect_archive(self.path, SOURCE, config)
