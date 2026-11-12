#!/usr/bin/env python3
"""Fail-closed verification of the exact validated OCI release package; no network."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile

REPOSITORY = "DDePuy2015/datto-rmm-mcp"
WORKFLOW = f"https://github.com/{REPOSITORY}/.github/workflows/publish-image.yml@refs/heads/main"
INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
NODE_DIGEST = "6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def file_digest(path):
    with open(path, "rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def request(env):
    require(env.get("GITHUB_REPOSITORY") == REPOSITORY, "Wrong repository")
    require(env.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "Manual dispatch required")
    require(env.get("GITHUB_RUN_ATTEMPT") == "1",
            "Reruns are not supported: reconcile any partial publication, then obtain a fresh dispatch")
    require(re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ID", "")),
            "Positive GitHub run identity required")
    require(env.get("GITHUB_REF") == "refs/heads/main", "Main workflow ref required")
    sha = env.get("GITHUB_SHA", "")
    require(SHA.fullmatch(sha), "Full immutable source SHA required")
    require(env.get("REQUESTED_SOURCE_SHA") == sha, "Requested source differs from dispatch SHA")
    require(env.get("MAIN_SHA") == sha, "Main moved; start a newly reviewed dispatch")
    require(env.get("PUBLICATION_CONFIRMED") == "true", "Publication not approved")
    require(env.get("PUBLICATION_ENABLED") == "true", "Publication configuration is dormant")
    require(re.fullmatch(
        r"https://github\.com/DDePuy2015/summit-mcp-ops/blob/[0-9a-f]{40}/deployments/[A-Za-z0-9._-]+\.md(?:#[A-Za-z0-9._-]+)?",
        env.get("RELEASE_RECORD_URL", "")), "Immutable Ops release-decision record required")
    for key in ("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"):
        require(re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}",
                             env.get(key, "")), f"Missing or invalid publisher configuration: {key}")
    return sha


def inspect_archive(path, source, expected_config):
    """Return transport-selected root digest, not sha256(index.json) or tar hash."""
    require(SHA.fullmatch(source), "Full source SHA required")
    require(not Path(path).is_symlink(), "Archive symlink forbidden")
    require(Path(path).stat().st_size <= 2 * 1024 ** 3, "Oversize archive")
    with tarfile.open(path, "r:") as archive:
        members = {}
        total = 0
        for count, item in enumerate(archive):
            total += item.size
            require(count < 4096 and total <= 2 * 1024 ** 3, "Archive resource limit")
            name = item.name
            while name.startswith("./"):
                name = name[2:]
            require(name not in members, "Duplicate archive path")
            require((item.isdir() or item.isfile()) and not item.sparse, "Links/devices/sparse files are forbidden")
            if item.isdir():
                require(name.rstrip("/") in ("", "blobs", "blobs/sha256"), "Unexpected directory")
                continue
            require(name in ("oci-layout", "index.json") or
                    re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name), "Unexpected archive path")
            require(item.size <= 2 * 1024 ** 3, "Oversize archive member")
            members[name] = item

        def read(name):
            require(name in members, "Missing OCI member: " + name)
            require(members[name].size <= 16 * 1024 ** 2, "Oversize JSON document")
            return archive.extractfile(members[name]).read()

        visited = set()
        def blob(descriptor, opaque=False):
            require(DIGEST.fullmatch(descriptor.get("digest", "")), "Invalid descriptor digest")
            require(not any(k in descriptor for k in ("urls", "data", "artifactType")), "External or embedded descriptor forbidden")
            name = "blobs/sha256/" + descriptor["digest"].split(":")[1]
            require(name in members and type(descriptor.get("size")) is int and
                    members[name].size == descriptor["size"], "Descriptor size mismatch")
            if opaque:
                with archive.extractfile(members[name]) as stream:
                    actual = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
                require(actual == descriptor["digest"], "Blob digest mismatch")
                visited.add(descriptor["digest"])
                return None
            raw = read(name)
            visited.add(descriptor["digest"])
            require(len(raw) == descriptor.get("size"), "Descriptor size mismatch")
            require(digest(raw) == descriptor["digest"], "Blob digest mismatch")
            return raw

        require(json.loads(read("oci-layout")) == {"imageLayoutVersion": "1.0.0"}, "Invalid OCI layout")
        layout = json.loads(read("index.json"))
        require(layout.get("schemaVersion") == 2 and len(layout.get("manifests", [])) == 1,
                "Exactly one OCI transport root required")
        root = layout["manifests"][0]
        require(root.get("mediaType") == INDEX, "Attested OCI image index required")
        root_json = json.loads(blob(root))
        require(root_json.get("schemaVersion") == 2 and root_json.get("mediaType") == INDEX,
                "Invalid image index")
        descriptors = root_json.get("manifests", [])
        require(len(descriptors) == 2, "Exactly one runtime and one attestation manifest required")
        runtime = [d for d in descriptors if d.get("platform") == {"architecture": "amd64", "os": "linux"}]
        require(len(runtime) == 1, "Only linux/amd64 is approved")
        runtime = runtime[0]
        attest = [d for d in descriptors if d is not runtime]
        require(len(attest) == 1, "Attestation manifest missing")
        attest = attest[0]
        require(attest.get("platform") == {"architecture": "unknown", "os": "unknown"}, "Unexpected attestation platform")
        annotations = attest.get("annotations", {})
        require(annotations.get("vnd.docker.reference.type") == "attestation-manifest" and
                annotations.get("vnd.docker.reference.digest") == runtime["digest"], "Attestation reference mismatch")
        require(runtime.get("mediaType") == attest.get("mediaType") == MANIFEST, "Unsupported manifest type")
        manifest = json.loads(blob(runtime))
        require(manifest.get("schemaVersion") == 2 and manifest.get("mediaType") == MANIFEST, "Invalid runtime manifest")
        require("subject" not in manifest, "Unexpected runtime subject")
        config_descriptor = manifest["config"]
        require(config_descriptor.get("mediaType") == "application/vnd.oci.image.config.v1+json", "Invalid config type")
        require(config_descriptor["digest"] == expected_config, "Tested image differs from OCI runtime")
        config = json.loads(blob(config_descriptor))
        require(config.get("architecture") == "amd64" and config.get("os") == "linux", "Runtime platform mismatch")
        require(config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") == source,
                "Runtime source revision mismatch")
        runtime_config = config.get("config", {})
        require(runtime_config.get("Labels", {}).get("org.opencontainers.image.source") ==
                "https://github.com/" + REPOSITORY, "Runtime source URL mismatch")
        require(runtime_config.get("User") == "datto" and
                runtime_config.get("Cmd") == ["node", "dist/index.js"], "Runtime user/command mismatch")
        require(manifest.get("layers"), "Runtime layers missing")
        for layer in manifest["layers"]:
            require(layer.get("mediaType") in ("application/vnd.oci.image.layer.v1.tar",
                    "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd"),
                    "Unsupported runtime layer")
            blob(layer, opaque=True)
        attestation = json.loads(blob(attest))
        require(attestation.get("schemaVersion") == 2 and attestation.get("mediaType") == MANIFEST,
                "Invalid attestation manifest")
        if "subject" in attestation or "artifactType" in attestation:
            # BuildKit v0.34.2 writer.go:648-677 uses the OCI artifact format by
            # default. Its only subject is the already verified runtime manifest.
            require(attestation.get("artifactType") ==
                    "application/vnd.docker.attestation.manifest.v1+json",
                    "Unexpected attestation artifact type")
            subject = attestation.get("subject")
            require(isinstance(subject, dict) and type(subject.get("size")) is int and
                    subject == {key: runtime[key] for key in ("mediaType", "digest", "size")},
                    "Attestation artifact subject differs from runtime descriptor")
            blob(subject)
            # DescriptorEmptyJSON embeds exactly {} and BuildKit also writes its
            # blob. Do not permit arbitrary embedded data or external references.
            empty_config = {"mediaType": "application/vnd.oci.empty.v1+json",
                            "digest": digest(b"{}"), "size": 2, "data": "e30="}
            require(attestation.get("config") == empty_config and
                    type(attestation["config"].get("size")) is int,
                    "Invalid attestation empty JSON config")
            require(blob({k: v for k, v in empty_config.items() if k != "data"}) == b"{}",
                    "Attestation empty JSON blob mismatch")
        else:
            require(attestation["config"].get("mediaType") ==
                    "application/vnd.oci.image.config.v1+json", "Invalid legacy attestation config type")
            blob(attestation["config"])
        types = set()
        for layer in attestation.get("layers", []):
            require(layer.get("mediaType") == "application/vnd.in-toto+json", "Invalid attestation media type")
            statement = json.loads(blob(layer))
            require(statement.get("_type") == "https://in-toto.io/Statement/v0.1" or
                    statement.get("_type") == "https://in-toto.io/Statement/v1", "Invalid attestation statement")
            subjects = statement.get("subject", [])
            require(subjects and all(s.get("digest", {}).get("sha256") == runtime["digest"].split(":")[1]
                                     for s in subjects), "Attestation subject mismatch")
            kind = statement.get("predicateType")
            require(kind not in types, "Duplicate attestation predicate")
            types.add(kind)
            if kind in ("https://slsa.dev/provenance/v0.2", "https://slsa.dev/provenance/v1"):
                predicate = statement["predicate"]
                if kind == "https://slsa.dev/provenance/v0.2":
                    require(predicate.get("buildType") == "https://mobyproject.org/buildkit@v1",
                            "Unexpected provenance builder")
                    require(predicate.get("buildConfig"), "Maximum BuildKit provenance missing")
                    dependencies = predicate.get("materials", [])
                else:
                    # BuildKit v0.34.2: provenance/types/types.go and docs/attestations/slsa-definitions.md.
                    definition = predicate.get("buildDefinition", {})
                    require(definition.get("buildType") ==
                            "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
                            "Unexpected provenance builder")
                    config = definition.get("internalParameters", {}).get("buildConfig", {})
                    require(isinstance(config, dict) and isinstance(config.get("llbDefinition"), list)
                            and config["llbDefinition"], "Maximum BuildKit provenance missing")
                    dependencies = definition.get("resolvedDependencies", [])
                require(any(isinstance(m, dict) and m.get("digest", {}).get("sha256") == NODE_DIGEST
                            and re.fullmatch(r"pkg:docker/(?:docker.io/library/)?node@[^?]+(?:\?[^ ]+)?", m.get("uri", ""))
                            for m in dependencies), "Pinned official Node provenance material missing")
            elif kind == "https://spdx.dev/Document":
                require(statement.get("predicate", {}).get("spdxVersion") == "SPDX-2.3", "Invalid SPDX predicate")
            else:
                raise ValueError("Unsupported attestation predicate: " + repr(kind))
        require(types in ({"https://slsa.dev/provenance/v0.2", "https://spdx.dev/Document"},
                          {"https://slsa.dev/provenance/v1", "https://spdx.dev/Document"}),
                "Exactly one supported BuildKit provenance and SPDX SBOM both required")
        require(visited == {"sha256:" + name.split("/")[-1] for name in members if name.startswith("blobs/")},
                "Unreachable blob in OCI archive")
        return {"indexDigest": root["digest"], "graphDigests": sorted(visited), "runtimeManifestDigest": runtime["digest"],
                "configDigest": config_descriptor["digest"], "attestationManifestDigest": attest["digest"]}



def package_metadata(root, source, run_id, attempt, repository_root=None):
    root = Path(root)
    require(SHA.fullmatch(source), "Full source SHA required")
    require(all(re.fullmatch(r"[1-9][0-9]*", str(v)) for v in (run_id, attempt)), "Invalid run identity")
    require(not root.is_symlink(), "Package symlink forbidden")
    reports = root / "reports"
    require(not reports.is_symlink(), "Reports symlink forbidden")
    files = list(reports.rglob("*"))
    require(len(files) <= 20000, "Too many evidence files")
    for item in files:
        require(not item.is_symlink(), "Evidence symlink forbidden")
        require(item.is_file() or item.is_dir(), "Invalid evidence member")
        if item.is_file():
            require(item.stat().st_size <= 128 * 1024 ** 2, "Oversize evidence")
    def read(name):
        return json.loads((reports / name).read_text(encoding="utf-8"))
    metadata = read("image-metadata.json")
    require(isinstance(metadata, list) and len(metadata) == 1, "One tested image required")
    image = metadata[0]
    config = image.get("Id", "")
    require(DIGEST.fullmatch(config), "Invalid tested image ID")
    require(image.get("Architecture") == "amd64" and image.get("Os") == "linux", "Tested platform mismatch")
    require(image.get("Config", {}).get("User") == "datto" and
            image["Config"].get("Cmd") == ["node", "dist/index.js"], "Tested runtime configuration mismatch")
    labels = image["Config"].get("Labels", {})
    require(labels.get("org.opencontainers.image.revision") == source and
            labels.get("org.opencontainers.image.source") == "https://github.com/" + REPOSITORY,
            "Tested source mismatch")
    graph = inspect_archive(root / "image.oci.tar", source, config)
    require(read("build-metadata.json").get("containerimage.digest") == graph["indexDigest"], "Build index mismatch")
    validation = read("validation.json")
    require(all(validation.get(k) == v for k, v in {
        "sourceCommit": source, "runId": str(run_id), "runAttempt": str(attempt),
        "imageId": config, "sourceChecks": "passed", "runtimeChecks": "passed"}.items()),
        "Source/runtime validation binding failed")
    audit = read("production-audit.json").get("metadata", {}).get("vulnerabilities", {})
    require(set(audit) == {"info", "low", "moderate", "high", "critical", "total"} and
            all(type(v) is int and v == 0 for v in audit.values()), "Production audit not zero")
    for name in ("source-scan-summary.json", "image-scan-summary.json"):
        scan = read(name)
        require(scan.get("schemaVersion") == 1 and scan.get("sourceCommit") == source,
                "Scan source/schema mismatch")
        rows = scan.get("results")
        require(isinstance(rows, list) and all(isinstance(r, dict) for r in rows), "Missing scan results")
        for row in rows:
            require(row.get("secrets") == [], "Secret findings or missing secret results")
        if name.startswith("image"):
            require(scan.get("imageId") == config and rows, "Image scan binding missing")
            require(all(row.get("vulnerabilities") == [] for row in rows), "Runtime vulnerabilities remain")
            for kind in ("os-pkgs", "lang-pkgs"):
                require(any(r.get("class") == kind and type(r.get("packageCount")) is int and
                            r["packageCount"] > 0 for r in rows), "Incomplete image package coverage")
    for name in ("source-sbom.cdx.json", "image-sbom.cdx.json"):
        sbom = read(name)
        require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion") and
                isinstance(sbom.get("components"), list) and sbom["components"], "Missing SBOM inventory")
    source_files = read("source-files.json")
    require(isinstance(source_files, dict) and source_files, "Missing tracked source inventory")
    for name, value in source_files.items():
        require(isinstance(name, str) and not name.startswith(("/", ".git/")) and
                not any(p in ("", ".", "..") for p in name.split("/")) and
                not any(c in name for c in ("\\", ":", "\x00")) and
                isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "Invalid source inventory")
    if repository_root is not None:
        import subprocess
        checkout = Path(repository_root)
        actual_source = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
        require(actual_source == source, "Checkout source mismatch")
        tracked = subprocess.check_output(["git", "-C", str(checkout), "ls-files", "-z"]).decode().split("\x00")[:-1]
        require(set(tracked) == set(source_files), "Tracked source inventory differs")
        for name in tracked:
            target = checkout / name
            require(not any(p.is_symlink() for p in (target, *target.parents)), "Checkout symlink forbidden")
            require(file_digest(target) == "sha256:" + source_files[name], "Checkout bytes differ: " + name)
    hashes = {item.relative_to(root).as_posix(): file_digest(item) for item in sorted(files) if item.is_file()}
    return {"schemaVersion": 1, "repository": REPOSITORY, "sourceCommit": source,
            "runId": str(run_id), "runAttempt": str(attempt), "platform": "linux/amd64",
            "archiveSha256": file_digest(root / "image.oci.tar"), **graph, "evidenceHashes": hashes}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("request", "create", "verify", "compare"))
    parser.add_argument("--directory")
    parser.add_argument("--source")
    parser.add_argument("--repository-root")
    parser.add_argument("--archive")
    args = parser.parse_args()
    if args.mode == "request":
        request(os.environ)
        return
    root = Path(args.directory)
    result = package_metadata(root, args.source, os.environ["GITHUB_RUN_ID"],
                              os.environ["GITHUB_RUN_ATTEMPT"], args.repository_root)
    metadata = root / "package.json"
    require(not metadata.is_symlink(), "Package metadata symlink forbidden")
    if args.mode == "create":
        metadata.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    else:
        require(json.loads(metadata.read_text(encoding="utf-8")) == result, "Release package metadata mismatch")
    if args.mode == "compare":
        graph = inspect_archive(args.archive, args.source, result["configDigest"])
        require(all(result[k] == v for k, v in graph.items()), "Round-trip graph mismatch")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
