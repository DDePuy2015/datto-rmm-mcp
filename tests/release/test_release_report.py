"""Sanitized scanner summaries retain gates without retaining secret values."""
import json
import unittest
from fixtures import SOURCE, load_module

report = load_module("release_report", "release-report.py")


class ReportTests(unittest.TestCase):
    def test_source_secrets_redacted_not_hidden(self):
        value = report.summarize({"SchemaVersion": 2, "Results": [{"Target": "fixture", "Secrets": [{
            "RuleID": "token", "Severity": "HIGH", "Match": "not-a-real-secret", "Code": {"Lines": ["secret"]}}]}]}, SOURCE)
        self.assertEqual(value["results"][0]["secrets"], [{"rule": "token", "severity": "HIGH"}])
        self.assertNotIn("not-a-real-secret", json.dumps(value))
        self.assertNotIn("Lines", json.dumps(value))

    def test_all_severities_and_inventory_retained(self):
        findings = [{"VulnerabilityID": "fixture-" + s, "Severity": s, "PkgName": "fixture"}
                    for s in ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")]
        value = report.summarize({"SchemaVersion": 2, "Metadata": {"ImageID": "sha256:" + "a" * 64},
            "Results": [{"Target": "fixture", "Class": "os-pkgs", "Type": "alpine",
                         "Packages": [{"Name": "fixture"}], "Vulnerabilities": findings}]}, SOURCE, True)
        self.assertEqual(value["results"][0]["packageCount"], 1)
        self.assertEqual(len(value["results"][0]["vulnerabilities"]), 5)
        self.assertEqual(value["sourceCommit"], SOURCE)
        self.assertEqual(value["imageId"], "sha256:" + "a" * 64)

    def test_invalid_schema_rejected(self):
        for value in ({}, {"SchemaVersion": 1}, {"SchemaVersion": 2, "Results": {}},
                      {"SchemaVersion": 2, "Results": [None]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                report.summarize(value, SOURCE)
