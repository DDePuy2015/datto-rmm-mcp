#!/usr/bin/env python3
"""Verify merged immutable Ops scope evidence; never substitutes for dispatch approval."""
import base64
import hashlib
import json
import os
import re
import subprocess

OPS = "DDePuy2015/summit-mcp-ops"
DESTINATION = "summititmcpacr.azurecr.io/datto-rmm-mcp"
SHA = re.compile(r"[0-9a-f]{40}")
RECORD = re.compile(r"https://github\.com/DDePuy2015/summit-mcp-ops/blob/([0-9a-f]{40})/(deployments/[A-Za-z0-9._-]+\.md)(?:#[A-Za-z0-9._-]+)?")
MAX_DOCUMENT = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_keys(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate publication scope key")
        value[key] = item
    return value


def verify_record(url, source, fetch):
    require(isinstance(url, str), "Immutable Ops record URL required")
    match = RECORD.fullmatch(url)
    require(match is not None, "Immutable Ops record URL required")
    require(isinstance(source, str) and SHA.fullmatch(source), "Full source SHA required")
    pinned, path = match.groups()
    prefix = "repos/" + OPS
    commit = fetch(f"{prefix}/git/commits/{pinned}")
    require(commit.get("sha") == pinned, "Ops commit identity mismatch")
    ref = fetch(f"{prefix}/git/ref/heads/main")
    main = ref.get("object", {}).get("sha")
    require(ref.get("ref") == "refs/heads/main" and ref.get("object", {}).get("type") == "commit" and
            isinstance(main, str) and SHA.fullmatch(main), "Invalid Ops main identity")
    comparison = fetch(f"{prefix}/compare/{pinned}...{main}")
    require(comparison.get("status") in ("ahead", "identical") and
            comparison.get("base_commit", {}).get("sha") == pinned and
            comparison.get("merge_base_commit", {}).get("sha") == pinned and
            comparison.get("behind_by") == 0, "Ops record commit is not merged into main")
    content = fetch(f"{prefix}/contents/{path}?ref={pinned}")
    blob_sha = content.get("sha")
    require(content.get("type") == "file" and content.get("path") == path and
            content.get("encoding") == "base64" and isinstance(blob_sha, str) and SHA.fullmatch(blob_sha) and
            type(content.get("size")) is int and 0 < content["size"] <= MAX_DOCUMENT,
            "Invalid Ops file identity or size")
    encoded = content.get("content")
    require(isinstance(encoded, str) and len(encoded) <= 2 * MAX_DOCUMENT, "Invalid Ops content")
    try:
        raw = base64.b64decode("".join(encoded.split()), validate=True)
    except (ValueError, TypeError):
        raise ValueError("Invalid Ops base64 content") from None
    require(len(raw) == content["size"], "Ops content size mismatch")
    actual_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\x00" + raw).hexdigest()
    require(actual_blob == blob_sha, "Ops blob content hash mismatch")
    try:
        document = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Ops document must be UTF-8") from None
    openings = re.findall(r"^```datto-publication[^\r\n]*\r?$", document, re.MULTILINE)
    blocks = re.findall(r"^```datto-publication\r?\n(.*?)^```[ \t]*\r?$", document, re.MULTILINE | re.DOTALL)
    require(len(openings) == len(blocks) == 1, "Exactly one datto-publication JSON block required")
    try:
        decision = json.loads(blocks[0], object_pairs_hook=unique_keys)
    except (ValueError, TypeError):
        raise ValueError("Malformed publication scope JSON") from None
    expected = {"schemaVersion": 1, "service": "datto", "sourceCommit": source,
                "destination": DESTINATION, "decision": "publish-only"}
    require(isinstance(decision, dict) and type(decision.get("schemaVersion")) is int and
            decision == expected, "Publication record scope does not match this source and destination")
    return {"schemaVersion": 1, "recordUrl": url, "opsCommit": pinned, "opsMain": main,
            "sourceCommit": source, "destination": DESTINATION, "decision": "publish-only",
            "blobSha": blob_sha, "contentSha256": hashlib.sha256(raw).hexdigest()}


def github_fetch(endpoint):
    result = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True, timeout=60)
    # Do not include private document content or authentication diagnostics in errors.
    require(result.returncode == 0, "Ops read failed; verify read-only Ops access and immutable record existence")
    require(len(result.stdout) <= 3 * MAX_DOCUMENT, "Oversize Ops API response")
    try:
        value = json.loads(result.stdout)
    except ValueError:
        raise ValueError("Invalid Ops API response") from None
    require(isinstance(value, dict), "Invalid Ops API object")
    return value


def main():
    require(bool(os.environ.get("GH_TOKEN")), "Read-only Ops token is required")
    print(json.dumps(verify_record(os.environ.get("RELEASE_RECORD_URL"),
                                  os.environ.get("GITHUB_SHA"), github_fetch), indent=2))


if __name__ == "__main__":
    main()
