#!/usr/bin/env python3
"""Compare cryptographically verified Cosign payloads to the intended predicates."""
import base64
import json
from pathlib import Path
import sys


def statements(text):
    decoder = json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        text = text.lstrip()[end:]
        for envelope in value if isinstance(value, list) else [value]:
            yield json.loads(base64.b64decode(envelope["payload"], validate=True))


def verify(expected_digest, envelopes, expected_predicate, predicate_type):
    matching = [s for s in statements(envelopes)
                if s.get("_type") in ("https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1")
                and s.get("predicateType") == predicate_type
                and s.get("predicate") == expected_predicate
                and s.get("subject")
                and all(subject.get("digest", {}).get("sha256") == expected_digest.removeprefix("sha256:")
                        for subject in s["subject"])]
    if not matching:
        raise ValueError("No verified attestation matches the exact image and intended predicate")


if __name__ == "__main__":
    digest, sbom_envelopes, sbom, provenance_envelopes, provenance = sys.argv[1:]
    verify(digest, Path(sbom_envelopes).read_text(), json.loads(Path(sbom).read_text()),
           "https://cyclonedx.org/bom")
    verify(digest, Path(provenance_envelopes).read_text(), json.loads(Path(provenance).read_text()),
           "https://slsa.dev/provenance/v1")
