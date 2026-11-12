#!/usr/bin/env python3
"""Create sanitized validation records; never retain secret matches or credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def summarize(data, source, image=False):
    if data.get("SchemaVersion") != 2 or not isinstance(data.get("Results", []), list):
        raise ValueError("Malformed Trivy report")
    results = []
    for result in data.get("Results", []):
        if not isinstance(result, dict):
            raise ValueError("Malformed scan row")
        row = {"target": result.get("Target", ""), "secrets": [
            {"rule": secret["RuleID"], "severity": secret["Severity"]}
            for secret in result.get("Secrets", [])]}
        if image:
            row.update({"class": result.get("Class", ""), "type": result.get("Type", ""),
                        "packageCount": len(result.get("Packages", [])),
                        "vulnerabilities": [{"id": finding["VulnerabilityID"],
                            "severity": finding["Severity"], "package": finding["PkgName"],
                            "installedVersion": finding.get("InstalledVersion", ""),
                            "fixedVersion": finding.get("FixedVersion", "")}
                            for finding in result.get("Vulnerabilities", [])]})
        results.append(row)
    summary = {"schemaVersion": 1, "sourceCommit": source, "results": results}
    if image:
        summary["imageId"] = data["Metadata"]["ImageID"]
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["source-files", "source-scan", "image-scan", "validation"])
    parser.add_argument("--input")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    source = os.environ["EXPECTED_SHA"]
    if args.command == "source-files":
        paths = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
        write(args.output, {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths if p})
    elif args.command == "validation":
        metadata = json.loads(Path(args.input).read_text())
        write(args.output, {"sourceCommit": source, "runId": os.environ["GITHUB_RUN_ID"],
            "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"], "imageId": metadata[0]["Id"],
            "sourceChecks": "passed", "runtimeChecks": "passed"})
    else:
        write(args.output, summarize(json.loads(Path(args.input).read_text()), source,
                                    image=args.command == "image-scan"))


if __name__ == "__main__":
    main()
