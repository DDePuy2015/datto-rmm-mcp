"""Offline negative proofs for the trusted Semgrep merge-tree fallback."""
import copy
import unittest
from fixtures import load_module

semgrep = load_module("semgrep_release", "verify-semgrep-release.py")
SOURCE, HEAD, TREE = "1" * 40, "2" * 40, "3" * 40
PREFIX = "repos/" + semgrep.REPOSITORY


class SemgrepReleaseTests(unittest.TestCase):
    def setUp(self):
        self.pr = {"number": 22, "state": "closed", "merged": True, "merge_commit_sha": SOURCE,
                   "base": {"ref": "main", "repo": {"full_name": semgrep.REPOSITORY}},
                   "head": {"sha": HEAD, "repo": {"full_name": semgrep.REPOSITORY}}}
        self.check = {"id": 123, "name": semgrep.CHECK_NAME, "head_sha": HEAD,
                      "app": {"id": semgrep.APP_ID}, "status": "completed", "conclusion": "success",
                      "details_url": "https://semgrep.dev/example"}
        self.data = {f"{PREFIX}/git/commits/{SOURCE}": {"sha": SOURCE, "tree": {"sha": TREE}},
                     f"{PREFIX}/git/commits/{HEAD}": {"sha": HEAD, "tree": {"sha": TREE}},
                     f"{PREFIX}/commits/{SOURCE}/check-runs": [],
                     f"{PREFIX}/commits/{SOURCE}/pulls": [{"number": 22, "merge_commit_sha": SOURCE}],
                     f"{PREFIX}/pulls/22": self.pr,
                     f"{PREFIX}/commits/{HEAD}/check-runs": [self.check]}
        self.calls = []

    def run_proof(self):
        def fetch(endpoint):
            self.calls.append(endpoint)
            return self.data[endpoint]
        return semgrep.select_evidence(SOURCE, fetch)

    def test_identical_merged_tree_passes_and_retains_proof(self):
        result = self.run_proof()
        self.assertEqual(result["mode"], "identical-merged-pr-tree")
        self.assertEqual((result["pullRequest"], result["scannedHead"], result["mergeCommit"],
                          result["sourceTree"], result["scannedTree"], result["checkId"]),
                         (22, HEAD, SOURCE, TREE, TREE, 123))
        self.assertTrue(result["checkUrl"].endswith("/runs/123"))

    def main_check(self, **updates):
        check = {**self.check, "head_sha": SOURCE, **updates}
        self.data[f"{PREFIX}/commits/{SOURCE}/check-runs"] = [check]
        return check

    def test_exact_main_preferred_without_pr_lookup(self):
        self.main_check()
        self.assertEqual(self.run_proof()["mode"], "exact-main")
        self.assertFalse(any(p.endswith("/pulls") for p in self.calls))

    def test_present_main_pending_or_failed_never_falls_back(self):
        for updates in ({"status": "in_progress", "conclusion": None},
                        {"conclusion": "failure"}, {"conclusion": "neutral"},
                        {"conclusion": "skipped"}):
            with self.subTest(updates=updates):
                self.calls.clear()
                self.main_check(**updates)
                with self.assertRaises(ValueError):
                    self.run_proof()
                self.assertFalse(any(p.endswith("/pulls") for p in self.calls))

    def test_latest_failure_overrides_older_success(self):
        self.data[f"{PREFIX}/commits/{HEAD}/check-runs"].append(
            {**self.check, "id": 124, "conclusion": "failure"})
        with self.assertRaises(ValueError):
            self.run_proof()

    def test_latest_success_is_selected(self):
        self.data[f"{PREFIX}/commits/{HEAD}/check-runs"].append({**self.check, "id": 124})
        self.assertEqual(self.run_proof()["checkId"], 124)

    def test_wrong_app_or_head_is_not_proof(self):
        for edit in ({"app": {"id": 999}}, {"head_sha": SOURCE}, {"name": "other"}):
            self.data[f"{PREFIX}/commits/{HEAD}/check-runs"] = [{**self.check, **edit}]
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.run_proof()

    def test_main_wrong_head_fails_closed(self):
        self.main_check(head_sha=HEAD)
        with self.assertRaises(ValueError):
            self.run_proof()

    def test_wrong_repository_or_base_rejected(self):
        for side, key, value in (("base", "ref", "other"),
                                 ("base", "repo", {"full_name": "attacker/repo"}),
                                 ("head", "repo", {"full_name": "attacker/repo"})):
            pr = copy.deepcopy(self.pr)
            pr[side][key] = value
            self.data[f"{PREFIX}/pulls/22"] = pr
            with self.subTest(side=side, key=key), self.assertRaises(ValueError):
                self.run_proof()

    def test_wrong_merge_closed_state_or_number_rejected(self):
        for edit in ({"merge_commit_sha": HEAD}, {"merged": False}, {"state": "open"},
                     {"number": 23}):
            self.data[f"{PREFIX}/pulls/22"] = {**self.pr, **edit}
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.run_proof()

    def test_different_tree_rejected(self):
        self.data[f"{PREFIX}/git/commits/{HEAD}"]["tree"]["sha"] = "4" * 40
        with self.assertRaises(ValueError):
            self.run_proof()

    def test_missing_ambiguous_or_wrong_association_rejected(self):
        good = {"number": 22, "merge_commit_sha": SOURCE}
        for value in ([], [good, good], [{"number": 22, "merge_commit_sha": HEAD}], [None], {}):
            self.data[f"{PREFIX}/commits/{SOURCE}/pulls"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.run_proof()

    def test_missing_or_malformed_check_rejected(self):
        for value in ([], {}, [None], [{**self.check, "id": "123"}], [self.check, self.check]):
            self.data[f"{PREFIX}/commits/{HEAD}/check-runs"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.run_proof()

    def test_invalid_commit_proof_rejected(self):
        for value in ({}, {"sha": HEAD, "tree": {"sha": TREE}},
                      {"sha": SOURCE, "tree": {"sha": "short"}}):
            self.data[f"{PREFIX}/git/commits/{SOURCE}"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.run_proof()

    def test_wrong_app_on_main_cannot_impersonate_trusted_scan(self):
        self.main_check(app={"id": 999}, conclusion="success")
        self.data[f"{PREFIX}/commits/{HEAD}/check-runs"] = []
        with self.assertRaises(ValueError):
            self.run_proof()
