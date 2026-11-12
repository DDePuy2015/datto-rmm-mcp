#!/usr/bin/env python3
"""Retain trusted Semgrep evidence for an exact commit or identical merged PR tree."""
import json
import os
import re
import subprocess

REPOSITORY = "DDePuy2015/datto-rmm-mcp"
APP_ID = 4487249
CHECK_NAME = "semgrep-cloud-platform/scan"
SHA = re.compile(r"[0-9a-f]{40}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def latest_check(checks, sha):
    require(isinstance(checks, list) and all(isinstance(c, dict) for c in checks),
            "Malformed Semgrep check list")
    matches = [c for c in checks if c.get("name") == CHECK_NAME and
               isinstance(c.get("app"), dict) and c["app"].get("id") == APP_ID]
    if not matches:
        return None
    require(all(c.get("head_sha") == sha and type(c.get("id")) is int and c["id"] > 0
                for c in matches), "Malformed trusted Semgrep identity")
    require(len({c["id"] for c in matches}) == len(matches), "Ambiguous Semgrep check IDs")
    check = max(matches, key=lambda c: c["id"])
    require(check.get("status") == "completed" and check.get("conclusion") == "success",
            "Latest trusted Semgrep check is not successful; fallback forbidden")
    return check


def select_evidence(source, fetch):
    require(isinstance(source, str) and SHA.fullmatch(source), "Full source SHA required")
    prefix = "repos/" + REPOSITORY

    def commit_tree(sha):
        commit = fetch(f"{prefix}/git/commits/{sha}")
        tree = commit.get("tree", {}).get("sha")
        require(commit.get("sha") == sha and isinstance(tree, str) and SHA.fullmatch(tree),
                "Malformed commit/tree proof")
        return tree

    tree = commit_tree(source)
    check = latest_check(fetch(f"{prefix}/commits/{source}/check-runs"), source)
    head, number, merge = source, None, None
    mode = "exact-main"
    if check is None:
        associated = fetch(f"{prefix}/commits/{source}/pulls")
        require(isinstance(associated, list) and all(isinstance(p, dict) for p in associated),
                "Malformed associated PR proof")
        matches = [p for p in associated if p.get("merge_commit_sha") == source]
        require(len(matches) == 1, "Exactly one associated merged PR proof required")
        number = matches[0].get("number")
        require(type(number) is int and number > 0, "Invalid PR number")
        pr = fetch(f"{prefix}/pulls/{number}")
        require(pr.get("number") == number and pr.get("state") == "closed" and
                pr.get("merged") is True and pr.get("merge_commit_sha") == source,
                "PR is not the exact merged source")
        require(pr.get("base", {}).get("ref") == "main" and
                pr["base"].get("repo", {}).get("full_name") == REPOSITORY and
                pr.get("head", {}).get("repo", {}).get("full_name") == REPOSITORY,
                "PR must target main in the same repository")
        head = pr["head"].get("sha")
        require(isinstance(head, str) and SHA.fullmatch(head), "Invalid merged PR head")
        require(commit_tree(head) == tree, "Merged source differs from scanned PR tree")
        check = latest_check(fetch(f"{prefix}/commits/{head}/check-runs"), head)
        require(check is not None, "Merged PR head lacks trusted Semgrep success")
        merge, mode = source, "identical-merged-pr-tree"
    return {"schemaVersion": 1, "repository": REPOSITORY, "mode": mode,
            "sourceCommit": source, "sourceTree": tree, "scannedHead": head,
            "scannedTree": tree, "pullRequest": number, "mergeCommit": merge,
            "checkId": check["id"], "checkName": CHECK_NAME, "appId": APP_ID,
            "checkUrl": f"https://github.com/{REPOSITORY}/runs/{check['id']}",
            "scanUrl": check.get("details_url"), "conclusion": "success"}


def github_fetch(endpoint):
    # GH_TOKEN has read-only contents/checks/pull-requests permissions.
    collection = endpoint.endswith(("/check-runs", "/pulls"))
    args = ["gh", "api", endpoint + ("?per_page=100" if collection else "")]
    if collection:
        args += ["--paginate", "--slurp"]
    value = json.loads(subprocess.run(args, check=True, capture_output=True, text=True).stdout)
    if not collection:
        require(isinstance(value, dict), "Malformed GitHub object")
        return value
    require(isinstance(value, list), "Malformed GitHub pagination")
    result = []
    for page in value:
        items = page.get("check_runs") if endpoint.endswith("/check-runs") else page
        require(isinstance(items, list), "Malformed GitHub collection")
        result.extend(items)
    return result


if __name__ == "__main__":
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "Wrong repository")
    print(json.dumps(select_evidence(os.environ["GITHUB_SHA"], github_fetch), indent=2))
