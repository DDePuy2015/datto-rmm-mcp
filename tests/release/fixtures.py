"""Synthetic OCI archives and evidence. Never touches Docker, registries or Azure."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "1" * 40
OTHER_SOURCE = "2" * 40


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load_module("release_package", "release-package.py")
attestations = load_module("verify_attestations", "verify-release-attestations.py")


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def archive(path, mutate=None, extra_members=None, corrupt_blob=False):
    blobs = {}

    def blob(value, media_type):
        data = value if isinstance(value, bytes) else raw(value)
        digest = sha(data)
        blobs["blobs/sha256/" + digest.split(":")[1]] = data
        return {"mediaType": media_type, "size": len(data), "digest": digest}

    config = {"architecture": "amd64", "os": "linux",
              "config": {"User": "datto", "Cmd": ["node", "dist/index.js"], "Labels": {"org.opencontainers.image.revision": SOURCE, "org.opencontainers.image.source": "https://github.com/" + release.REPOSITORY}},
              "rootfs": {"type": "layers", "diff_ids": []}}
    if mutate:
        mutate("config", config)
    config_desc = blob(config, "application/vnd.oci.image.config.v1+json")
    runtime = {"schemaVersion": 2, "mediaType": release.MANIFEST,
               "config": config_desc,
               "layers": [blob(b"synthetic layer, not an executable image",
                               "application/vnd.oci.image.layer.v1.tar")]}
    if mutate:
        mutate("runtime", runtime)
    runtime_desc = blob(runtime, release.MANIFEST)
    runtime_desc["platform"] = {"architecture": "amd64", "os": "linux"}

    statements = [
        {"_type": "https://in-toto.io/Statement/v0.1",
         "subject": [{"name": "_", "digest": {"sha256": runtime_desc["digest"].split(":")[1]}}],
         "predicateType": "https://slsa.dev/provenance/v0.2",
         "predicate": {"buildType": "https://mobyproject.org/buildkit@v1",
                       "buildConfig": {"steps": [{"id": "synthetic fixture"}]},
                       "materials": [{"uri": "pkg:docker/node@26-alpine?platform=linux%2Famd64", "digest": {"sha256": release.NODE_DIGEST}}]}},
        {"_type": "https://in-toto.io/Statement/v0.1",
         "subject": [{"name": "_", "digest": {"sha256": runtime_desc["digest"].split(":")[1]}}],
         "predicateType": "https://spdx.dev/Document",
         "predicate": {"spdxVersion": "SPDX-2.3"}},
    ]
    if mutate:
        mutate("statements", statements)
    attestation = {"schemaVersion": 2, "mediaType": release.MANIFEST,
                   "config": blob({}, "application/vnd.oci.image.config.v1+json"),
                   "layers": [blob(s, "application/vnd.in-toto+json") for s in statements]}
    if mutate:
        mutate("attestation", attestation)
    attest_desc = blob(attestation, release.MANIFEST)
    attest_desc["platform"] = {"architecture": "unknown", "os": "unknown"}
    attest_desc["annotations"] = {"vnd.docker.reference.type": "attestation-manifest",
                                  "vnd.docker.reference.digest": runtime_desc["digest"]}
    index = {"schemaVersion": 2, "mediaType": release.INDEX,
             "manifests": [runtime_desc, attest_desc]}
    if mutate:
        mutate("index", index)
    root_desc = blob(index, release.INDEX)
    layout = {"schemaVersion": 2, "manifests": [root_desc]}
    if mutate:
        mutate("layout", layout)
    members = {"oci-layout": raw({"imageLayoutVersion": "1.0.0"}),
               "index.json": raw(layout), **blobs}
    if corrupt_blob:
        key = next(k for k in members if k.startswith("blobs/"))
        members[key] += b"corruption"
    with tarfile.open(path, "w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, data, member_type in extra_members or []:
            info = tarfile.TarInfo(name)
            info.type = member_type
            if member_type == tarfile.REGTYPE:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                info.linkname = "outside"
                tar.addfile(info)
    return config_desc["digest"]


def evidence(directory):
    root = Path(directory)
    reports = root / "reports"
    reports.mkdir(parents=True)
    config = archive(root / "image.oci.tar")
    graph = release.inspect_archive(root / "image.oci.tar", SOURCE, config)
    values = {
        "image-metadata.json": [{"Id": config, "Architecture": "amd64", "Os": "linux", "Config": {
            "User": "datto", "Cmd": ["node", "dist/index.js"], "Labels": {
                "org.opencontainers.image.revision": SOURCE,
                "org.opencontainers.image.source": "https://github.com/" + release.REPOSITORY}}}],
        "build-metadata.json": {"containerimage.digest": graph["indexDigest"]},
        "validation.json": {"sourceCommit": SOURCE, "runId": "123", "runAttempt": "1", "imageId": config,
                            "sourceChecks": "passed", "runtimeChecks": "passed"},
        "production-audit.json": {"metadata": {"vulnerabilities": dict.fromkeys(
            ["info", "low", "moderate", "high", "critical", "total"], 0)}},
        "source-scan-summary.json": {"schemaVersion": 1, "sourceCommit": SOURCE, "results": []},
        "image-scan-summary.json": {"schemaVersion": 1, "sourceCommit": SOURCE, "imageId": config,
                                   "results": [{"class": k, "packageCount": 10, "vulnerabilities": [], "secrets": []}
                                               for k in ("os-pkgs", "lang-pkgs")]},
        "source-files.json": {"Dockerfile": "a" * 64}}
    for name in ("source-sbom.cdx.json", "image-sbom.cdx.json"):
        values[name] = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "fixture"}]}
    for name, value in values.items():
        (reports / name).write_text(json.dumps(value))
    return reports


def request_env():
    return {"GITHUB_REPOSITORY": release.REPOSITORY,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": SOURCE, "REQUESTED_SOURCE_SHA": SOURCE, "MAIN_SHA": SOURCE,
            "PUBLICATION_CONFIRMED": "true", "PUBLICATION_ENABLED": "true",
            "RELEASE_RECORD_URL": "https://github.com/DDePuy2015/summit-mcp-ops/blob/" + SOURCE +
                                  "/deployments/release-decision.md",
            "AZURE_CLIENT_ID": "11111111-1111-1111-1111-111111111111",
            "AZURE_TENANT_ID": "22222222-2222-2222-2222-222222222222",
            "AZURE_SUBSCRIPTION_ID": "33333333-3333-3333-3333-333333333333"}
