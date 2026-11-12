"""Offline immutable Ops commit, document and publication-scope negative proofs."""
import base64
import hashlib
import json
import subprocess
import unittest
from unittest.mock import patch
from fixtures import SOURCE, load_module

record = load_module("publication_record", "verify-publication-record.py")
PIN, MAIN = "2" * 40, "3" * 40
PATH = "deployments/datto-publication.md"
URL = f"https://github.com/{record.OPS}/blob/{PIN}/{PATH}"
PREFIX = "repos/" + record.OPS


class PublicationRecordTests(unittest.TestCase):
    def setUp(self):
        self.scope = {"schemaVersion": 1, "service": "datto", "sourceCommit": SOURCE,
                      "destination": record.DESTINATION, "decision": "publish-only"}
        self.data = {
            f"{PREFIX}/git/commits/{PIN}": {"sha": PIN},
            f"{PREFIX}/git/ref/heads/main": {"ref": "refs/heads/main", "object": {"type": "commit", "sha": MAIN}},
            f"{PREFIX}/compare/{PIN}...{MAIN}": {"status": "ahead", "behind_by": 0,
                "base_commit": {"sha": PIN}, "merge_base_commit": {"sha": PIN}}}
        self.set_text(self.block())

    def block(self):
        return "```datto-publication\n" + json.dumps(self.scope) + "\n```\n"

    def set_text(self, text):
        raw = text.encode()
        self.data[f"{PREFIX}/contents/{PATH}?ref={PIN}"] = {
            "type": "file", "path": PATH, "size": len(raw), "encoding": "base64",
            "content": base64.b64encode(raw).decode(),
            "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\x00" + raw).hexdigest()}

    def verify(self, url=URL):
        return record.verify_record(url, SOURCE, self.data.__getitem__)

    def test_valid_scope_only_returns_sanitized_evidence(self):
        self.set_text("Private unrelated operational text\n" + self.block())
        evidence = self.verify()
        self.assertEqual(evidence["sourceCommit"], SOURCE)
        self.assertEqual(evidence["opsMain"], MAIN)
        self.assertNotIn("Private", json.dumps(evidence))
        self.assertNotIn("content", evidence)

    def test_identical_main_allowed(self):
        self.data[f"{PREFIX}/git/ref/heads/main"]["object"]["sha"] = PIN
        self.data[f"{PREFIX}/compare/{PIN}...{PIN}"] = {
            "status": "identical", "behind_by": 0, "base_commit": {"sha": PIN}, "merge_base_commit": {"sha": PIN}}
        self.assertEqual(self.verify()["opsMain"], PIN)

    def test_nonimmutable_or_wrong_urls(self):
        for url in [URL.replace(PIN, "main"), URL.replace("github.com", "evil.example"),
                    URL.replace("datto-publication.md", "../other.md"), URL + "?x=y", URL + "\n"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.verify(url)

    def test_absent_commit_or_document(self):
        for key in [f"{PREFIX}/git/commits/{PIN}", f"{PREFIX}/contents/{PATH}?ref={PIN}"]:
            with patch.dict(self.data):
                del self.data[key]
                with self.assertRaises(KeyError):
                    self.verify()

    def test_wrong_commit_and_unmerged_pin(self):
        self.data[f"{PREFIX}/git/commits/{PIN}"]["sha"] = MAIN
        with self.assertRaises(ValueError):
            self.verify()
        self.data[f"{PREFIX}/git/commits/{PIN}"]["sha"] = PIN
        for status in ["behind", "diverged", "unknown"]:
            self.data[f"{PREFIX}/compare/{PIN}...{MAIN}"]["status"] = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.verify()

    def test_wrong_source_destination_decision_schema_or_extra_fields(self):
        changes = {"sourceCommit": PIN, "destination": "other.azurecr.io/datto", "decision": "deploy",
                   "service": "fortimanager", "schemaVersion": True, "extra": "not allowed"}
        for key, value in changes.items():
            with patch.dict(self.scope, {key: value}):
                self.set_text(self.block())
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.verify()

    def test_missing_multiple_unclosed_malformed_blocks(self):
        for text in ["no block", self.block() * 2, self.block().removesuffix("```\n"),
                     "```datto-publication\nnot json\n```", "```datto-publication\n[]\n```",
                     self.block().replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1')]:
            self.set_text(text)
            with self.subTest(text=text[:30]), self.assertRaises(ValueError):
                self.verify()

    def test_blob_integrity(self):
        value = self.data[f"{PREFIX}/contents/{PATH}?ref={PIN}"]
        for key, item in {"sha": "0" * 40, "size": 1, "path": "other.md", "type": "symlink", "content": "%%%"}.items():
            with patch.dict(value, {key: item}), self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()

    def test_api_not_found_is_sanitized(self):
        response = subprocess.CompletedProcess([], 1, "", "private token details")
        with patch("subprocess.run", return_value=response):
            with self.assertRaisesRegex(ValueError, "Ops read failed") as error:
                record.github_fetch("repos/example/missing")
            self.assertNotIn("private", str(error.exception))

    def test_main_uses_existing_cli_auth_without_an_exported_token(self):
        env = {"RELEASE_RECORD_URL": URL, "GITHUB_SHA": SOURCE}
        with patch.dict("os.environ", env, clear=True), \
             patch.object(record, "github_fetch", side_effect=self.data.__getitem__) as fetch, \
             patch("builtins.print") as output:
            record.main()
            self.assertEqual(fetch.call_count, 4)
            self.assertEqual(json.loads(output.call_args.args[0])["sourceCommit"], SOURCE)

    def test_missing_request_fails_before_network(self):
        with patch.dict("os.environ", {}, clear=True), patch.object(record, "github_fetch") as fetch:
            with self.assertRaisesRegex(ValueError, "record URL"):
                record.main()
            fetch.assert_not_called()

    def test_cli_read_uses_auth_session_without_extracting_credentials(self):
        endpoint = f"{PREFIX}/git/commits/{PIN}"
        response = subprocess.CompletedProcess([], 0, json.dumps({"sha": PIN}), "")
        with patch("subprocess.run", return_value=response) as run:
            self.assertEqual(record.github_fetch(endpoint), {"sha": PIN})
            run.assert_called_once_with(["gh", "api", endpoint], capture_output=True,
                                        text=True, timeout=60)

    def test_crlf_record(self):
        self.set_text(self.block().replace("\n", "\r\n"))
        self.assertEqual(self.verify()["decision"], "publish-only")
